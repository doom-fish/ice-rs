//! Host candidate gathering and the gathering state (RFC 8445 §5.1.1).
//! Server-reflexive and relayed candidates are gathered by the agent over its
//! own socket.

use std::ffi::CStr;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use crate::candidate::Candidate;
use crate::component::ComponentId;

/// One usable local IP address discovered on a non-loopback, non-link-local,
/// up interface.
#[derive(Debug, Clone)]
pub struct LocalAddress {
    /// The interface name (e.g. `en0`).
    pub interface: String,
    /// The IP address.
    pub ip: IpAddr,
}

/// Enumerate usable local IP addresses for host-candidate gathering.
///
/// Interfaces are first classified with `networkframework::list_interfaces`
/// (which knows which interfaces are loopback); their addresses are then read
/// from the BSD `getifaddrs(3)` table — `networkframework` exposes interface
/// identity but not per-interface addresses, so the addresses come from `libc`.
/// Loopback, link-local, and down addresses are skipped.
#[must_use]
pub fn local_addresses() -> Vec<LocalAddress> {
    // Names of interfaces networkframework considers loopback; we exclude them.
    let loopback_names: Vec<String> = networkframework::list_interfaces()
        .into_iter()
        .filter(|i| i.interface_type == networkframework::InterfaceType::Loopback)
        .map(|i| i.name)
        .collect();

    let mut out = Vec::new();
    unsafe {
        let mut ifap: *mut libc::ifaddrs = std::ptr::null_mut();
        if libc::getifaddrs(&mut ifap) != 0 {
            return out;
        }
        let mut cur = ifap;
        while !cur.is_null() {
            let ifa = &*cur;
            cur = ifa.ifa_next;

            if ifa.ifa_addr.is_null() {
                continue;
            }
            let flags = ifa.ifa_flags;
            let up = flags & (libc::IFF_UP as u32) != 0;
            let loopback = flags & (libc::IFF_LOOPBACK as u32) != 0;
            if !up || loopback {
                continue;
            }

            let name = if ifa.ifa_name.is_null() {
                String::new()
            } else {
                CStr::from_ptr(ifa.ifa_name).to_string_lossy().into_owned()
            };
            if loopback_names.contains(&name) {
                continue;
            }

            if let Some(ip) = sockaddr_ip(ifa.ifa_addr) {
                if is_loopback_or_link_local(ip) {
                    continue;
                }
                out.push(LocalAddress { interface: name, ip });
            }
        }
        libc::freeifaddrs(ifap);
    }
    out
}

/// Read the [`IpAddr`] out of a raw `sockaddr` pointer (IPv4 or IPv6 only).
unsafe fn sockaddr_ip(sa: *const libc::sockaddr) -> Option<IpAddr> {
    match i32::from((*sa).sa_family) {
        x if x == libc::AF_INET => {
            let sin = &*sa.cast::<libc::sockaddr_in>();
            Some(IpAddr::V4(Ipv4Addr::from(sin.sin_addr.s_addr.to_ne_bytes())))
        }
        x if x == libc::AF_INET6 => {
            let sin6 = &*sa.cast::<libc::sockaddr_in6>();
            Some(IpAddr::V6(Ipv6Addr::from(sin6.sin6_addr.s6_addr)))
        }
        _ => None,
    }
}

/// Returns `true` for loopback or link-local addresses, which are never
/// gathered as host candidates.
#[must_use]
fn is_loopback_or_link_local(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_loopback() || (v4.octets()[0] == 169 && v4.octets()[1] == 254)
        }
        IpAddr::V6(v6) => v6.is_loopback() || (v6.segments()[0] & 0xffc0) == 0xfe80,
    }
}

/// Gather host candidates for `component` on the socket bound to `bound`:
/// the bound address itself when it is specific, otherwise one per usable
/// local address of the same family, all sharing the bound port.
#[must_use]
pub fn gather_host(bound: SocketAddr, component: ComponentId) -> Vec<Candidate> {
    if !bound.ip().is_unspecified() {
        return vec![Candidate::host(bound, component)];
    }
    local_addresses()
        .into_iter()
        .filter(|la| la.ip.is_ipv4() == bound.is_ipv4())
        .map(|la| Candidate::host(SocketAddr::new(la.ip, bound.port()), component))
        .collect()
}

/// The progress of the gathering process (RFC 8445 §6.1.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GatherState {
    /// Gathering has not started.
    New,
    /// Gathering is underway; candidates may still be produced.
    Gathering,
    /// Gathering is finished (end-of-candidates).
    Complete,
}
