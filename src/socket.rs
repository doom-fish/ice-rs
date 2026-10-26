//! The shared UDP socket and first-byte packet demultiplexing.
//!
//! WebRTC multiplexes ICE/STUN, DTLS, and SRTP on a single UDP 5-tuple, so the
//! ICE agent cannot hold its socket exclusively: DTLS and SRTP bytes must be
//! readable and writable through the very same socket. [`SharedSocket`] is an
//! `Arc`-shared, cloneable handle to an **unconnected** UDP socket that can send
//! to and receive from arbitrary peers — exactly what ICE needs to probe many
//! candidate pairs and what the downstream `rtc` layer needs to push DTLS/SRTP.
//!
//! It is implemented directly on the BSD sockets API via `libc`. Apple's
//! Network.framework `UdpClient` is *connected-mode* (bound to a single peer)
//! and therefore cannot serve as the multi-peer, in-process-loopback-capable
//! socket the ICE agent requires; `networkframework` is still used for
//! interface enumeration during gathering. The STUN Binding requests for
//! server-reflexive candidates and the TURN allocation for relayed candidates
//! use this same socket, so the addresses they learn belong to it.

use std::io;
use std::mem;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::os::unix::io::RawFd;
use std::sync::Arc;
use std::time::Duration;

pub use crate::packet::{classify, PacketKind};

/// A sink for non-STUN packets demultiplexed off the shared socket.
///
/// The ICE agent consumes STUN bytes itself; everything else (DTLS, SRTP, …) is
/// handed to the application through this trait so it can drive its own
/// security and media layers over the negotiated 5-tuple.
pub trait PacketSink: Send + Sync {
    /// Called for each received non-STUN datagram, classified by first byte.
    fn on_packet(&self, kind: PacketKind, bytes: &[u8], from: SocketAddr);
}

struct Inner {
    fd: RawFd,
}

impl Drop for Inner {
    fn drop(&mut self) {
        unsafe { libc::close(self.fd) };
    }
}

/// A cloneable, `Send + Sync` handle to an unconnected UDP socket.
#[derive(Clone)]
pub struct SharedSocket {
    inner: Arc<Inner>,
}

impl std::fmt::Debug for SharedSocket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SharedSocket")
            .field("fd", &self.inner.fd)
            .field("local_addr", &self.local_addr().ok())
            .finish()
    }
}

impl SharedSocket {
    /// Bind an unconnected UDP socket to `addr`.
    ///
    /// The socket family (IPv4 / IPv6) is chosen to match `addr`. Pass a port
    /// of `0` to let the OS pick an ephemeral port; read it back with
    /// [`SharedSocket::local_addr`].
    ///
    /// # Errors
    ///
    /// Returns the underlying [`io::Error`] if the socket cannot be created or
    /// bound.
    pub fn bind(addr: SocketAddr) -> io::Result<Self> {
        let family = match addr {
            SocketAddr::V4(_) => libc::AF_INET,
            SocketAddr::V6(_) => libc::AF_INET6,
        };
        let fd = unsafe { libc::socket(family, libc::SOCK_DGRAM, libc::IPPROTO_UDP) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let inner = Arc::new(Inner { fd });

        // Allow quick rebinding in tests.
        let one: libc::c_int = 1;
        unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_REUSEADDR,
                std::ptr::addr_of!(one).cast(),
                mem::size_of::<libc::c_int>() as libc::socklen_t,
            );
        }

        let (level, option) = match addr {
            SocketAddr::V4(_) => (libc::IPPROTO_IP, libc::IP_PKTINFO),
            SocketAddr::V6(_) => (libc::IPPROTO_IPV6, libc::IPV6_RECVPKTINFO),
        };
        let rc = unsafe {
            libc::setsockopt(
                fd,
                level,
                option,
                std::ptr::addr_of!(one).cast(),
                mem::size_of::<libc::c_int>() as libc::socklen_t,
            )
        };
        if rc < 0 {
            return Err(io::Error::last_os_error());
        }

        let (storage, len) = to_sockaddr(addr);
        let rc = unsafe { libc::bind(fd, std::ptr::addr_of!(storage).cast(), len) };
        if rc < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self { inner })
    }

    /// The local address the socket is bound to (resolving an ephemeral port).
    ///
    /// # Errors
    ///
    /// Returns the underlying [`io::Error`] if `getsockname` fails.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        let mut storage: libc::sockaddr_storage = unsafe { mem::zeroed() };
        let mut len = mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
        let rc = unsafe {
            libc::getsockname(
                self.inner.fd,
                std::ptr::addr_of_mut!(storage).cast(),
                &mut len,
            )
        };
        if rc < 0 {
            return Err(io::Error::last_os_error());
        }
        from_sockaddr(&storage).ok_or_else(|| io::Error::other("bad sockaddr"))
    }

    /// Set the receive timeout, so [`SharedSocket::recv_from`] returns
    /// [`io::ErrorKind::WouldBlock`] when no datagram arrives in time. This lets
    /// the agent's single-threaded event loop wake up to run the Ta scheduler.
    ///
    /// # Errors
    ///
    /// Returns the underlying [`io::Error`] if `setsockopt` fails.
    pub fn set_read_timeout(&self, timeout: Duration) -> io::Result<()> {
        let tv = libc::timeval {
            tv_sec: timeout.as_secs() as libc::time_t,
            tv_usec: libc::suseconds_t::try_from(timeout.subsec_micros()).unwrap_or(0),
        };
        let rc = unsafe {
            libc::setsockopt(
                self.inner.fd,
                libc::SOL_SOCKET,
                libc::SO_RCVTIMEO,
                std::ptr::addr_of!(tv).cast(),
                mem::size_of::<libc::timeval>() as libc::socklen_t,
            )
        };
        if rc < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// Send `buf` as a single datagram to `dest`.
    ///
    /// # Errors
    ///
    /// Returns the underlying [`io::Error`] on send failure.
    pub fn send_to(&self, buf: &[u8], dest: SocketAddr) -> io::Result<usize> {
        let (storage, len) = to_sockaddr(dest);
        let n = unsafe {
            libc::sendto(
                self.inner.fd,
                buf.as_ptr().cast(),
                buf.len(),
                0,
                std::ptr::addr_of!(storage).cast(),
                len,
            )
        };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(n as usize)
    }

    /// Receive a single datagram into `buf`, returning the byte count and the
    /// source address.
    ///
    /// Honors the timeout set by [`SharedSocket::set_read_timeout`]: a timeout
    /// surfaces as [`io::ErrorKind::WouldBlock`].
    ///
    /// # Errors
    ///
    /// Returns the underlying [`io::Error`] on receive failure or timeout.
    pub fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        let mut storage: libc::sockaddr_storage = unsafe { mem::zeroed() };
        let mut len = mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
        let n = unsafe {
            libc::recvfrom(
                self.inner.fd,
                buf.as_mut_ptr().cast(),
                buf.len(),
                0,
                std::ptr::addr_of_mut!(storage).cast(),
                &mut len,
            )
        };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        let addr = from_sockaddr(&storage)
            .ok_or_else(|| io::Error::other("bad source sockaddr"))?;
        Ok((n as usize, addr))
    }

    #[allow(missing_docs)]
    pub fn recv_with_destination(&self, buf: &mut [u8]) -> io::Result<Received> {
        let mut storage: libc::sockaddr_storage = unsafe { mem::zeroed() };
        let mut iov = libc::iovec {
            iov_base: buf.as_mut_ptr().cast(),
            iov_len: buf.len(),
        };
        let mut control = [0u64; 16];
        let mut msg: libc::msghdr = unsafe { mem::zeroed() };
        msg.msg_name = std::ptr::addr_of_mut!(storage).cast();
        msg.msg_namelen = mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
        msg.msg_iov = std::ptr::addr_of_mut!(iov);
        msg.msg_iovlen = 1;
        msg.msg_control = control.as_mut_ptr().cast();
        msg.msg_controllen = mem::size_of_val(&control) as libc::socklen_t;
        let n = unsafe { libc::recvmsg(self.inner.fd, std::ptr::addr_of_mut!(msg), 0) };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        if msg.msg_flags & libc::MSG_TRUNC != 0 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "datagram truncated"));
        }
        let from = from_sockaddr(&storage).ok_or_else(|| io::Error::other("bad source sockaddr"))?;
        let mut to = None;
        let mut cmsg = unsafe { libc::CMSG_FIRSTHDR(std::ptr::addr_of!(msg)) };
        while !cmsg.is_null() {
            let header = unsafe { std::ptr::read_unaligned(cmsg) };
            let data = unsafe { libc::CMSG_DATA(cmsg) };
            if header.cmsg_level == libc::IPPROTO_IP && header.cmsg_type == libc::IP_PKTINFO {
                let info = unsafe { std::ptr::read_unaligned(data.cast::<libc::in_pktinfo>()) };
                to = Some(IpAddr::V4(Ipv4Addr::from(info.ipi_addr.s_addr.to_ne_bytes())));
            } else if header.cmsg_level == libc::IPPROTO_IPV6
                && header.cmsg_type == libc::IPV6_PKTINFO
            {
                let info = unsafe { std::ptr::read_unaligned(data.cast::<libc::in6_pktinfo>()) };
                to = Some(IpAddr::V6(Ipv6Addr::from(info.ipi6_addr.s6_addr)));
            }
            cmsg = unsafe { libc::CMSG_NXTHDR(std::ptr::addr_of!(msg), cmsg) };
        }
        Ok(Received {
            len: n as usize,
            from,
            to,
        })
    }

    #[allow(missing_docs)]
    pub fn send_from(&self, buf: &[u8], source: IpAddr, dest: SocketAddr) -> io::Result<usize> {
        let (storage, len) = to_sockaddr(dest);
        let mut iov = libc::iovec {
            iov_base: buf.as_ptr().cast_mut().cast(),
            iov_len: buf.len(),
        };
        let mut control = [0u64; 8];
        let mut msg: libc::msghdr = unsafe { mem::zeroed() };
        msg.msg_name = std::ptr::addr_of!(storage).cast_mut().cast();
        msg.msg_namelen = len;
        msg.msg_iov = std::ptr::addr_of_mut!(iov);
        msg.msg_iovlen = 1;
        msg.msg_control = control.as_mut_ptr().cast();
        let (level, kind, payload) = match source {
            IpAddr::V4(_) => (
                libc::IPPROTO_IP,
                libc::IP_PKTINFO,
                mem::size_of::<libc::in_pktinfo>(),
            ),
            IpAddr::V6(_) => (
                libc::IPPROTO_IPV6,
                libc::IPV6_PKTINFO,
                mem::size_of::<libc::in6_pktinfo>(),
            ),
        };
        let payload = payload as libc::c_uint;
        msg.msg_controllen = unsafe { libc::CMSG_SPACE(payload) } as libc::socklen_t;
        unsafe {
            let cmsg = libc::CMSG_FIRSTHDR(std::ptr::addr_of!(msg));
            if cmsg.is_null() {
                return Err(io::Error::other("control buffer too small"));
            }
            (*cmsg).cmsg_level = level;
            (*cmsg).cmsg_type = kind;
            (*cmsg).cmsg_len = libc::CMSG_LEN(payload) as libc::socklen_t;
            let data = libc::CMSG_DATA(cmsg);
            match source {
                IpAddr::V4(ip) => std::ptr::write_unaligned(
                    data.cast::<libc::in_pktinfo>(),
                    libc::in_pktinfo {
                        ipi_ifindex: 0,
                        ipi_spec_dst: libc::in_addr {
                            s_addr: u32::from_ne_bytes(ip.octets()),
                        },
                        ipi_addr: libc::in_addr { s_addr: 0 },
                    },
                ),
                IpAddr::V6(ip) => std::ptr::write_unaligned(
                    data.cast::<libc::in6_pktinfo>(),
                    libc::in6_pktinfo {
                        ipi6_addr: libc::in6_addr {
                            s6_addr: ip.octets(),
                        },
                        ipi6_ifindex: 0,
                    },
                ),
            }
        }
        let n = unsafe { libc::sendmsg(self.inner.fd, std::ptr::addr_of!(msg), 0) };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(n as usize)
    }
}

#[allow(missing_docs)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Received {
    pub len: usize,
    pub from: SocketAddr,
    pub to: Option<IpAddr>,
}

/// Convert a [`SocketAddr`] into a `sockaddr_storage` and its valid length.
fn to_sockaddr(addr: SocketAddr) -> (libc::sockaddr_storage, libc::socklen_t) {
    let mut storage: libc::sockaddr_storage = unsafe { mem::zeroed() };
    match addr {
        SocketAddr::V4(v4) => {
            let sa = unsafe { &mut *std::ptr::addr_of_mut!(storage).cast::<libc::sockaddr_in>() };
            sa.sin_family = libc::AF_INET as libc::sa_family_t;
            sa.sin_port = v4.port().to_be();
            sa.sin_addr.s_addr = u32::from_ne_bytes(v4.ip().octets());
            (storage, mem::size_of::<libc::sockaddr_in>() as libc::socklen_t)
        }
        SocketAddr::V6(v6) => {
            let sa = unsafe { &mut *std::ptr::addr_of_mut!(storage).cast::<libc::sockaddr_in6>() };
            sa.sin6_family = libc::AF_INET6 as libc::sa_family_t;
            sa.sin6_port = v6.port().to_be();
            sa.sin6_addr.s6_addr = v6.ip().octets();
            sa.sin6_scope_id = v6.scope_id();
            (storage, mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t)
        }
    }
}

/// Convert a `sockaddr_storage` back into a [`SocketAddr`].
fn from_sockaddr(storage: &libc::sockaddr_storage) -> Option<SocketAddr> {
    match i32::from(storage.ss_family) {
        x if x == libc::AF_INET => {
            let sa = unsafe { &*std::ptr::from_ref(storage).cast::<libc::sockaddr_in>() };
            let ip = Ipv4Addr::from(sa.sin_addr.s_addr.to_ne_bytes());
            let port = u16::from_be(sa.sin_port);
            Some(SocketAddr::V4(SocketAddrV4::new(ip, port)))
        }
        x if x == libc::AF_INET6 => {
            let sa = unsafe { &*std::ptr::from_ref(storage).cast::<libc::sockaddr_in6>() };
            let ip = Ipv6Addr::from(sa.sin6_addr.s6_addr);
            let port = u16::from_be(sa.sin6_port);
            Some(SocketAddr::V6(SocketAddrV6::new(
                ip,
                port,
                sa.sin6_flowinfo,
                sa.sin6_scope_id,
            )))
        }
        _ => None,
    }
}

/// The unspecified bind address for `family`-matching an example address.
#[must_use]
pub fn unspecified_like(addr: IpAddr) -> SocketAddr {
    match addr {
        IpAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        IpAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
    }
}
