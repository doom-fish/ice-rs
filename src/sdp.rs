//! Minimal `a=candidate:` line serialization and parsing (RFC 8839 §5.1).
//!
//! The grammar implemented here is:
//!
//! ```text
//! candidate:<foundation> <component-id> <transport> <priority>
//!           <connection-address> <port> typ <cand-type>
//!           [raddr <rel-addr> rport <rel-port>]
//! ```
//!
//! Both the bare attribute value (`candidate:...`) and the full SDP attribute
//! line (`a=candidate:...`) are accepted on parse; serialization emits the bare
//! attribute value, which is what a signaling layer places after `a=`.

use std::net::{IpAddr, SocketAddr, ToSocketAddrs};

use crate::candidate::{Candidate, CandidateType};
use crate::component::{ComponentId, Transport};
use crate::config::MdnsPolicy;
use crate::error::{Error, Result};

/// Serialize a candidate as an `a=candidate:` attribute value (RFC 8839).
///
/// The returned string does **not** include the leading `a=`; it begins with
/// `candidate:`. The foundation and priority are taken verbatim from the
/// candidate so a round-trip is loss-free for the fields ICE exchanges.
#[must_use]
pub fn to_sdp(candidate: &Candidate) -> String {
    let mut line = format!(
        "candidate:{found} {comp} {transport} {prio} {ip} {port} typ {typ}",
        found = candidate.foundation,
        comp = candidate.component.as_u16(),
        transport = candidate.transport.as_str().to_uppercase(),
        prio = candidate.priority,
        ip = candidate.addr.ip(),
        port = candidate.addr.port(),
        typ = candidate.typ.as_str(),
    );
    if let Some(related) = candidate.related {
        if candidate.typ != CandidateType::Host {
            line.push_str(&format!(" raddr {} rport {}", related.ip(), related.port()));
        }
    }
    line
}

/// Parse an `a=candidate:` line (with or without the `a=` prefix) into a
/// [`Candidate`]. A connection address that is an mDNS name (`*.local`) is
/// resolved as `mdns` allows; no lookup happens under [`MdnsPolicy::Reject`].
///
/// # Errors
///
/// Returns [`Error::ParseCandidate`] if the line is malformed, uses an
/// unknown candidate type or transport, or names an mDNS host that `mdns`
/// rejects or cannot resolve.
pub fn parse(line: &str, mdns: &MdnsPolicy) -> Result<Candidate> {
    let body = line
        .trim()
        .strip_prefix("a=")
        .unwrap_or_else(|| line.trim())
        .strip_prefix("candidate:")
        .ok_or_else(|| Error::ParseCandidate(format!("missing 'candidate:' prefix: {line}")))?;

    let tokens: Vec<&str> = body.split_whitespace().collect();
    if tokens.len() < 8 {
        return Err(Error::ParseCandidate(format!("too few fields: {line}")));
    }

    let foundation = tokens[0].to_owned();
    let component = tokens[1]
        .parse::<u16>()
        .map_err(|_| Error::ParseCandidate(format!("bad component-id: {}", tokens[1])))?;
    let transport = Transport::parse(tokens[2])
        .ok_or_else(|| Error::ParseCandidate(format!("bad transport: {}", tokens[2])))?;
    let priority = tokens[3]
        .parse::<u32>()
        .map_err(|_| Error::ParseCandidate(format!("bad priority: {}", tokens[3])))?;
    let port = tokens[5]
        .parse::<u16>()
        .map_err(|_| Error::ParseCandidate(format!("bad port: {}", tokens[5])))?;
    let ip = connection_address(tokens[4], port, mdns)?;
    if tokens[6] != "typ" {
        return Err(Error::ParseCandidate(format!("expected 'typ', got: {}", tokens[6])));
    }
    let typ = CandidateType::parse(tokens[7])
        .ok_or_else(|| Error::ParseCandidate(format!("bad candidate type: {}", tokens[7])))?;

    let addr = SocketAddr::new(ip, port);

    // Optional raddr/rport, plus tolerated trailing key/value extensions.
    let mut related = None;
    let mut idx = 8;
    while idx + 1 < tokens.len() {
        match tokens[idx] {
            "raddr" => {
                let rip = tokens[idx + 1]
                    .parse::<IpAddr>()
                    .map_err(|_| Error::ParseCandidate(format!("bad raddr: {}", tokens[idx + 1])))?;
                let rport = related.map_or(0, |s: SocketAddr| s.port());
                related = Some(SocketAddr::new(rip, rport));
            }
            "rport" => {
                let rport = tokens[idx + 1]
                    .parse::<u16>()
                    .map_err(|_| Error::ParseCandidate(format!("bad rport: {}", tokens[idx + 1])))?;
                let rip = related.map_or(IpAddr::from([0, 0, 0, 0]), |s| s.ip());
                related = Some(SocketAddr::new(rip, rport));
            }
            _ => {}
        }
        idx += 2;
    }

    let base = match typ {
        CandidateType::Host => addr,
        _ => related.unwrap_or(addr),
    };

    Ok(Candidate {
        typ,
        component: ComponentId(component),
        transport,
        addr,
        base,
        related,
        server: None,
        foundation,
        priority,
    })
}

fn connection_address(token: &str, port: u16, mdns: &MdnsPolicy) -> Result<IpAddr> {
    if let Ok(ip) = token.parse::<IpAddr>() {
        return Ok(ip);
    }
    let name = token.trim_end_matches('.');
    let is_mdns = name.len() > ".local".len()
        && name
            .get(name.len() - ".local".len()..)
            .is_some_and(|suffix| suffix.eq_ignore_ascii_case(".local"));
    if !is_mdns {
        return Err(Error::ParseCandidate(format!("bad connection-address: {token}")));
    }
    let resolved = match mdns {
        MdnsPolicy::Reject => {
            return Err(Error::ParseCandidate(format!(
                "mDNS candidate {token} rejected by MdnsPolicy::Reject"
            )))
        }
        MdnsPolicy::Resolve => (name, port)
            .to_socket_addrs()
            .ok()
            .and_then(|mut addrs| addrs.next())
            .map(|addr| addr.ip()),
        MdnsPolicy::ResolveWith(resolve) => resolve(name),
    };
    resolved.ok_or_else(|| Error::ParseCandidate(format!("mDNS candidate {token} did not resolve")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_round_trip() {
        let c = Candidate::host("192.0.2.1:50000".parse().unwrap(), ComponentId::RTP);
        let line = to_sdp(&c);
        let back = parse(&line, &MdnsPolicy::Reject).unwrap();
        assert_eq!(back.addr, c.addr);
        assert_eq!(back.typ, CandidateType::Host);
        assert_eq!(back.priority, c.priority);
    }
}
