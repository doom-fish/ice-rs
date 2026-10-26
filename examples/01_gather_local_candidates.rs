//! Gather and print this host's local ICE candidates.
//!
//! Run with: `cargo run --example 01_gather_local_candidates`

use std::net::SocketAddr;

use ice::gather::gather_host;
use ice::{sdp, ComponentId};

fn main() {
    let unbound = SocketAddr::from(([0, 0, 0, 0], 50_000));
    let candidates = gather_host(unbound, ComponentId::RTP);

    println!("Host candidates for an agent bound to {unbound} (as SDP a=candidate lines):\n");
    for candidate in &candidates {
        println!("  {}", sdp::to_sdp(candidate));
    }

    if candidates.is_empty() {
        println!("  (no non-loopback host candidates found on this machine)");
    } else {
        println!("\n{} candidate(s) gathered.", candidates.len());
    }
}
