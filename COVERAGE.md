# Coverage

This document records, clause by clause, what `ice` implements from the ICE
family of RFCs, and the small set of deliberate simplifications. It is an honest
specification-vs-implementation diff, not a marketing summary.

## RFC 8445 — Interactive Connectivity Establishment

| Clause | Topic | Status |
| --- | --- | --- |
| §5.1.1 | Host / server-reflexive / relayed gathering | **Implemented** (UDP). Binding requests and the TURN allocation run over the agent's socket; the `TurnClient` lives as long as the agent |
| §5.1.1.3 | Foundation computation | **Implemented** (`candidate::compute_foundation`) |
| §5.1.2 | Candidate priority | **Implemented** (`candidate::compute_priority`) |
| §5.1.3 | Eliminating redundant candidates | **Implemented** (same transport address and base) |
| §6.1.1 | Forming the check list | **Implemented** (`checklist`; host and relayed locals only, same family and component) |
| §6.1.2 | Computing pair priority | **Implemented** (`pair::pair_priority`) |
| §6.1.2.5 | Pair limit | **Implemented** (`Limits::max_pairs`, default 100); pairs beyond the limit are refused rather than displacing lower-priority ones |
| §6.1.2.6 | Frozen pairs | **Implemented** |
| §6.1.4.1 | Ta-paced scheduling | **Implemented** (`Ta = 50 ms` for Binding requests, triggered and ordinary checks, and nomination) |
| §7.2.2 | Retransmission | **Implemented** (RFC 5389 schedule: 7 transmissions over 39.5 s) |
| §7.2.2 | `PRIORITY` of a check | **Implemented** (the peer-reflexive priority of the local candidate) |
| §7.2.5.1 | Role conflict response | **Implemented** (only an authenticated `487` switches the role, and only if it answers the role still held; the tiebreaker is redrawn) |
| §7.2.5.2.1 | Non-symmetric addresses | **Implemented** (source address and arrival route, including the destination IP from `IP_PKTINFO` / `IPV6_PKTINFO`) |
| §7.2.5.3.1 | Peer-reflexive local candidates | **Implemented** (from `XOR-MAPPED-ADDRESS`, capped by `Limits::max_peer_reflexive`) |
| §7.2.5.3.2 | Valid pairs | **Implemented** |
| §7.3 | Receiving / responding to checks | **Implemented** (`check::validate_request`; unauthenticated requests get no answer, unknown comprehension-required attributes get `420`) |
| §7.3.1.1 | Role-conflict resolution (`487`) | **Implemented** (`role::resolve_conflict`; the `487` carries the request's integrity attribute) |
| §7.3.1.3 | Peer-reflexive remote candidates | **Implemented** (capped by `Limits::max_peer_reflexive`) |
| §7.3.1.4 | Triggered checks | **Implemented** (an in-progress check is cancelled and repeated) |
| §7.3.1.5 | `USE-CANDIDATE` | **Implemented** (honoured by the controlled agent only) |
| §8.1.1 | Regular nomination | **Implemented** (`nomination`; the controlling agent repeats the check that produced the valid pair) |
| §8 | Aggressive nomination | **Not used** (WebRTC profile mandates regular) |
| §9 | ICE restarts | Out of scope for 0.2.0 |

## RFC 8838 — Trickle ICE

| Clause | Topic | Status |
| --- | --- | --- |
| §4.1 | Incremental candidate signaling | **Implemented** (`add_remote_candidate`, candidates trickled through `on_local_candidate`) |
| §4.2 | End-of-candidates | **Implemented** (`end_of_candidates`, `remote_end_of_candidates`); the check list fails once both sides are done, gathering is complete, and every pair failed |
| §8 | Half-trickle / full-trickle | **Full trickle** (checks begin before gathering completes) |

## RFC 7675 — Consent Freshness

| Clause | Topic | Status |
| --- | --- | --- |
| §5.1 | Consent checks every 5 s randomized by 0.8–1.2 | **Implemented** (`consent`) |
| §5.1 | Each consent request sent once; responses to any request in the window count | **Implemented** (requests stay outstanding for 30 s, so a slow path still refreshes consent) |
| §5.1 | Consent expires 30 s after the last authenticated response | **Implemented**; outstanding consent requests are discarded, the failure callback fires, and `send_on_selected` returns `Error::ConsentExpired` |
| §5.2 | Revocation by an authenticated `403` | **Implemented** |

## RFC 8489 — STUN integrity for connectivity checks

| Clause | Topic | Status |
| --- | --- | --- |
| §9.1.2 | Integrity attributes in requests | `MESSAGE-INTEGRITY` by default; `IntegrityMode::Sha256` or `Both` when the peer is known to support SHA-256 |
| §9.1.3 | Integrity attribute of responses | **Implemented** (a response mirrors the attribute that authenticated the request) |
| §9.1.4 | Checking responses | **Implemented** (the response must carry what the request used; `FINGERPRINT` is required) |

## RFC 8839 — SDP candidate grammar

| Clause | Topic | Status |
| --- | --- | --- |
| §5.1 | `a=candidate:` line encoding | **Implemented** (`sdp::to_sdp`) |
| §5.1 | `a=candidate:` line parsing | **Implemented** (`sdp::parse`) |
| §5.1 | `raddr` / `rport` for reflexive/relayed | **Implemented** |
| §5.2 | `a=end-of-candidates` | Handled at the agent API level, not emitted as SDP |
| — | mDNS (`.local`) connection addresses | Rejected unless `MdnsPolicy::Resolve` (system resolver) or `MdnsPolicy::ResolveWith` (caller's resolver) allows them |

## RFC 5764 §5.1.2 — Demultiplexing

| Topic | Status |
| --- | --- |
| First-byte STUN / DTLS / SRTP / ChannelData classification | **Implemented** (`packet::classify`) |
| Source filtering | Non-STUN datagrams reach the `PacketSink` only from the selected pair's remote on its route (or, before selection, from the remote of a valid pair); others are counted in `AgentStats::dropped_unexpected_source` |

## Dependencies delegated to siblings

- **STUN** framing, `MESSAGE-INTEGRITY`(-SHA256), `FINGERPRINT`, transaction IDs,
  and RNG come from `stun-rs`. The agent runs its own Binding transactions on
  its socket; it does not use `StunClient::bind`, which opens a socket of its
  own.
- **TURN** allocation, permissions, and refresh come from `turn-rs`'s
  `TurnClient`, driven over the agent's socket through a private transport.
  `Send` and `Data` indications are built and parsed with `turn::indication`.
- **Interface enumeration** comes from `networkframework`; the socket itself is
  a BSD UDP socket (`libc`).

The third-party runtime dependencies are `libc` and `zeroize`.

## Deliberate simplifications in 0.2.0

These are documented limitations, not bugs:

- **UDP only.** TCP candidate gathering (RFC 6544) is not implemented, and a
  relayed candidate needs a `turn:` server over UDP; `?transport=tcp` and
  `turns:` servers are skipped (`AgentStats::relay_errors`).
- **Send/Data indications only.** Relayed pairs never use `ChannelBind`, so
  every relayed datagram carries the 36-byte indication overhead.
- **Single component.** The agent negotiates one component (RTP); `rtcp-mux` is
  assumed, and candidates for other components are rejected.
- **One socket per agent.** Host candidates share the agent's port. When the
  socket is bound to the unspecified address, the destination and source IP of
  each datagram are handled with `IP_PKTINFO` / `IPV6_PKTINFO`; only addresses
  of the socket's family are gathered (IPv4 by default).
- **Pair limit.** Pairs beyond `Limits::max_pairs` are refused instead of
  pruning lower-priority pairs.
- **Refused TURN permissions are final.** A peer IP the TURN server refuses is
  not requested again, and its relayed pairs fail.
- **Full ICE only.** ICE-lite (RFC 8445 §2.7) is not implemented.
- **No ICE restart.** Re-gathering with fresh ufrag/pwd (RFC 8445 §9) is out of
  scope for this release.

## Verification

- `cargo test` — integration suites for candidate priority, foundations,
  connectivity checks, role conflicts, the check list, nomination, SDP and mDNS
  parsing, demultiplexing, consent timing, and the socket's destination/source
  addresses, plus agent tests on `127.0.0.1` against scripted peers, a scripted
  STUN server, and a scripted relaying TURN server: server-reflexive and
  relayed gathering on the host socket, an end-to-end relayed pair, forged
  `487` and success responses, asymmetric responses, off-path injection,
  limits, consent expiry with an injected clock, and nomination failure
  behind a NAT.
- `cargo clippy --all-targets -- -D warnings` — clean.
- `examples/02_full_gather` and `examples/03_loopback_pair` run entirely on
  `127.0.0.1`.
