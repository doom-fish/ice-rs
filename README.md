# ice

[![crates.io](https://img.shields.io/badge/crates.io-unpublished-lightgrey.svg)](https://github.com/doom-fish/ice-rs)
[![license](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)

A pure-Rust **full ICE** agent implementing
[RFC 8445] with the WebRTC ICE-bis profile, **trickle ICE** ([RFC 8838]),
**consent freshness** ([RFC 7675]), and the SDP `a=candidate:` grammar
([RFC 8839]), layered on the sibling `stun-rs`, `turn-rs`, and
`networkframework` crates.

ICE (Interactive Connectivity Establishment) is the NAT-traversal machinery
that lets two endpoints discover a working bidirectional path between them. This
crate gathers host, server-reflexive, and relayed candidates, forms candidate
pairs, runs prioritized connectivity checks with `MESSAGE-INTEGRITY`, resolves
role conflicts, nominates a pair, and keeps it alive with periodic consent
checks.

It is built for WebRTC peers and other ICE-compliant endpoints. STUN message
framing, integrity, and fingerprinting come from `stun-rs`; relayed transports
come from `turn-rs`; interface enumeration comes from `networkframework`. The
UDP socket is a BSD socket opened with `libc`.

The third-party runtime dependencies are `libc` and `zeroize` (which clears the
ICE passwords); everything else comes from the sibling crates. Cryptography
comes from Apple system libraries by way of those crates.

## Features

- **Candidate gathering** — host candidates from every usable interface,
  server-reflexive candidates via STUN, and relayed candidates via TURN
  (RFC 8445 §5.1.1). The STUN Binding requests and the TURN allocation use the
  agent's own socket, so the learned addresses are that socket's mappings, and
  the `TurnClient` lives (and refreshes the allocation) as long as the agent.
  Checks and media on relayed pairs travel in TURN `Send`/`Data` indications.
  Candidate priority and foundation follow RFC 8445 §5.1.2 and §5.1.1.3.
- **Check lists** — frozen-candidate pruning, foundation freezing/unfreezing,
  the `Frozen → Waiting → In-Progress → Succeeded/Failed` pair state machine,
  and a triggered-check queue (RFC 8445 §6).
- **Connectivity checks** — `USERNAME`, `PRIORITY`, `ICE-CONTROLLING` /
  `ICE-CONTROLLED`, `USE-CANDIDATE`, `MESSAGE-INTEGRITY`, and `FINGERPRINT`
  (`MESSAGE-INTEGRITY-SHA256` only when `IceConfig::integrity` asks for it).
  A response counts only after its `FINGERPRINT` and message integrity verify
  and its source and destination addresses match the request (RFC 8445
  §7.2.5.2.1); its `XOR-MAPPED-ADDRESS` drives peer-reflexive discovery and
  valid-pair construction.
- **Role conflict resolution** — the `487 Role Conflict` tiebreaker handling
  for both-controlling and both-controlled collisions (RFC 8445 §7.3.1.1). The
  `487` carries the integrity attribute the request used, and an incoming `487`
  switches the role only when it is authenticated.
- **Regular nomination** — the controlling agent nominates a valid pair by
  repeating its check with `USE-CANDIDATE`; the controlled agent selects on
  validation and the controlling agent ignores `USE-CANDIDATE` (RFC 8445 §8).
  Aggressive nomination is intentionally not used.
- **Trickle ICE** — incremental `add_remote_candidate` / `end_of_candidates`
  signaling so checks start before gathering completes (RFC 8838).
- **Consent freshness** — a STUN check on the selected pair every 4–6 s; if no
  authenticated response arrives for 30 s, consent expires, the failure
  callback fires, and `send_on_selected` returns `Error::ConsentExpired`
  (RFC 7675).
- **Source filtering** — non-STUN datagrams reach the `PacketSink` only from
  the selected pair's remote (or, before selection, a validated remote); the
  rest are dropped and counted in `IceAgent::stats`.
- **Limits** — `IceConfig::limits` caps remote candidates (100), peer-reflexive
  candidates (16), and candidate pairs (100, RFC 8445 §6.1.2.5); unusable
  remote addresses are rejected.
- **mDNS candidates** — `.local` connection addresses are rejected unless an
  `MdnsPolicy` resolves them.
- **SDP grammar** — `to_sdp` / `parse` for `a=candidate:` lines including
  `raddr` / `rport` for reflexive and relayed candidates (RFC 8839).
- **First-byte demultiplexing** — incoming datagrams are classified as STUN,
  DTLS, SRTP, or TURN ChannelData (RFC 5764 §5.1.2) so application media can be
  routed past the agent.

## Design: synchronous API, one background thread

The public [`IceAgent`] API is **synchronous and runtime-free**. There is no
`async`, no executor, and no third-party scheduler. A single background thread
owns the socket, drives the `Ta`-paced check scheduler, retransmits with an
RTO back-off, runs the timeout / nomination / consent ticks, and dispatches
inbound datagrams. State is shared through an `Arc<Mutex<…>>`, so your calls
into the agent are ordinary blocking method calls. Each TURN server gets a
worker thread that owns its `TurnClient`. Callbacks and the packet sink run
after the agent's state lock is released.

You receive locally gathered candidates and connection-failure notifications
through callbacks; you feed remote candidates in as your signaling channel
delivers them; and you block on [`IceAgent::wait_for_selected_pair`] (with a
timeout) for the negotiated path.

## Quick start

Negotiate a path between two endpoints. In a real application the two agents
live in different processes and exchange candidates over your signaling
channel; here they share one process over the loopback interface:

```rust,no_run
use std::sync::mpsc;
use std::time::Duration;
use ice::{IceAgent, IceConfig, IceRole};

# fn main() -> Result<(), Box<dyn std::error::Error>> {
let mut cfg = IceConfig::new(
    IceRole::Controlling,
    "localUfrag", "localPasswordAtLeast22ch",
    "peerUfrag",  "peerPasswordAtLeast22chr",
);
cfg.bind_addr = Some("127.0.0.1:0".parse().unwrap());

let agent = IceAgent::new(cfg)?;

// Trickle locally gathered candidates out over your signaling channel.
let (tx, rx) = mpsc::channel();
agent.on_local_candidate(move |c| { let _ = tx.send(c); });

agent.start_gathering()?;
for candidate in rx.try_iter() {
    // signaling.send(candidate.to_sdp());
    let _ = candidate;
}

// As remote candidates arrive over signaling, feed them in:
// agent.add_remote_candidate(ice::sdp::parse(&line, &ice::MdnsPolicy::Reject)?)?;
agent.end_of_candidates();
agent.remote_end_of_candidates();

let (local, remote) = agent.wait_for_selected_pair(Duration::from_secs(5))?;
println!("selected {} -> {}", local.addr, remote.addr);

agent.send_on_selected(b"application data over the nominated pair")?;
# Ok(())
# }
```

## Examples

```sh
# Enumerate local host candidates and print their SDP lines (offline):
cargo run --example 01_gather_local_candidates

# Host + server-reflexive gathering against an in-process STUN server (offline):
cargo run --example 02_full_gather

# Two in-process agents negotiate over loopback, no network (offline):
cargo run --example 03_loopback_pair
```

## Platform

This crate targets **macOS** (and other Apple platforms): interface
enumeration comes from Network.framework via the sibling `networkframework`
crate, the socket is a BSD UDP socket, and all cryptography comes from Apple
system libraries via `stun-rs`.

## Scope

This is a **full-ICE** implementation (it always forms a complete check list and
runs checks in both directions); ICE-lite is not provided. UDP candidates are
gathered; TCP candidate gathering (RFC 6544) is out of scope, and relayed
candidates need a `turn:` server reachable over UDP (`?transport=tcp` and
`turns:` servers are skipped). See
[`COVERAGE.md`](COVERAGE.md) for the precise RFC-clause coverage and the small
set of documented simplifications.

## Minimum Supported Rust Version

Rust **1.82**.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.

[RFC 8445]: https://www.rfc-editor.org/rfc/rfc8445
[RFC 8838]: https://www.rfc-editor.org/rfc/rfc8838
[RFC 7675]: https://www.rfc-editor.org/rfc/rfc7675
[RFC 8839]: https://www.rfc-editor.org/rfc/rfc8839
[`IceAgent`]: https://docs.rs/ice
[`IceAgent::wait_for_selected_pair`]: https://docs.rs/ice
