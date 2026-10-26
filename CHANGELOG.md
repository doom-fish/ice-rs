# Changelog

All notable changes to this crate are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - Unreleased

### Security

- Non-STUN datagrams from any source address went to the `PacketSink`, so
  attackers off the path could reach the DTLS and SRTP layers. They are now
  delivered only from the selected pair's remote on the pair's route (or,
  before selection, from the remote of a valid pair); the rest are dropped and
  counted in `AgentStats::dropped_unexpected_source`.
- Error responses were acted on without checking `FINGERPRINT` or message
  integrity, so a forged `487` flipped the role and other forged codes failed
  pairs. Success responses were removed from the pending list before they were
  verified, so a forged one left the pair stuck in progress and blocked its
  foundation. Every response is now verified first (the integrity attribute
  must be the one the request used) and forged ones are ignored and counted.
- There were no limits on remote or peer-reflexive candidates or on pairs, and
  checks went to any address the remote side chose. `Limits` caps remote
  candidates (100), peer-reflexive candidates (16, local and remote), and
  pairs (100, RFC 8445 §6.1.2.5); unspecified, multicast, broadcast, and
  port-0 addresses are rejected; peer-reflexive remotes are learned only from
  authenticated checks.
- The controlling agent honoured `USE-CANDIDATE`; it now ignores it.
- Consent (RFC 7675) had a single 500 ms response window, expired after 30–45 s
  instead of 30 s, and `send_on_selected` kept sending after expiry. Consent
  checks now go out every 4–6 s, each stays outstanding for 30 s so slow
  responses still count, consent expires 30 s after the last authenticated
  response (or at once on an authenticated `403`), and `send_on_selected`
  returns `Error::ConsentExpired`.
- The tiebreaker fell back to a clock-derived value when the system RNG
  failed. `IceAgent::new` now returns `Error::Rng` instead.
- `IceConfig` and `CheckParams` derived `Debug`, printing the ICE passwords.
  Both are redacted now, and the passwords are zeroized on drop.

### Fixed

- Server-reflexive candidates came from `StunClient::bind` on a separate
  socket, so the advertised port was the wrong NAT mapping, and relayed
  candidates came from a `TurnClient` that was dropped (releasing the
  allocation) as soon as gathering returned. Binding requests now run on the
  agent's socket, one per host candidate, and the TURN allocation is made over
  that socket by a worker that keeps the `TurnClient`, refreshes the
  allocation and permissions, and releases it when the agent is dropped.
  Relayed pairs now work end to end: checks, responses, and media travel in
  `Send`/`Data` indications, with a permission installed per peer IP.
- Responses were not checked for matching source and destination addresses
  (RFC 8445 §7.2.5.2.1), and `XOR-MAPPED-ADDRESS` was ignored. A response must
  now come from the address the check went to and arrive on the route it left
  from (the socket reports each datagram's destination IP), and the mapped
  address yields the valid pair and any peer-reflexive local candidate.
- Scheduling scanned all pairs for every pair (O(n²)) under the agent lock and
  allocated a foundation string per comparison. It is now linear, with a
  pair index and per-foundation in-progress counts.
- The controlling agent nominated the valid pair directly; behind a NAT a
  failed nominating check then left the generating pair succeeded and ICE
  stalled with no failure. The nominating check now repeats the generating
  pair's check, and its failure also removes the valid pair.
- An in-progress check hit by a triggered check kept retransmitting next to
  the new one. A triggered check now cancels the in-progress transaction
  (RFC 8445 §7.3.1.4). Checks use the RFC 5389 schedule from stun-rs (seven
  transmissions over 39.5 s; the old schedule ran 63.5 s).
- `487` responses carried only `MESSAGE-INTEGRITY-SHA256`, which browsers do
  not check, and checks always carried it too. Responses now mirror the
  request's integrity attribute, and checks carry `MESSAGE-INTEGRITY` only
  unless `IceConfig::integrity` says otherwise.
- Requests with unknown comprehension-required attributes are answered with
  `420` (RFC 8489 §6.3.1).
- mDNS `.local` candidates could not be parsed. They are accepted by explicit
  `MdnsPolicy`.
- The `PRIORITY` of a check was the local candidate's own priority; it is the
  peer-reflexive priority RFC 8445 §7.2.2 asks for.
- Pairs were formed between srflx locals and remotes, and between different
  address families; a socket bound to `0.0.0.0` gathered IPv6 host
  candidates it could not use. Only host and relayed locals of the socket's
  family are paired or gathered.
- `start_gathering` blocked for up to ~20 s per unreachable STUN or TURN
  server. It returns after the host candidates; the others arrive through the
  callback.
- Callbacks and the packet sink ran with the agent lock held, so calling back
  into the agent deadlocked, and a panicking callback killed the event loop.
  They now run after the lock is released, and panics are contained.
- A check list in which every pair failed never reported failure. Once
  gathering is complete, the peer signalled end-of-candidates, and every pair
  failed, the failure callback fires and `wait_for_selected_pair` returns
  `Error::Failed`.

### Changed

- **Breaking:** `IceConfig` gains `integrity`, `limits`, `mdns`, `policy`, and
  `clock`; `legacy_integrity` is removed (`IntegrityMode::Sha1` is the
  default); `local_pwd` and `remote_pwd` are `Zeroizing<String>`.
- **Breaking:** `wait_for_selected_pair` and `selected_pair` return
  `(Candidate, Candidate)`; `IceAgent::socket` is removed. Send with
  `send_on_selected`, which respects consent and relayed routes.
- **Breaking:** `send_on_selected` returns `Error::NoSelectedPair` (was
  `Error::Config`), `Error::ConsentExpired`, or `Error::Failed`.
- **Breaking:** `add_remote_candidate` returns `Error::Unsupported` or
  `Error::Limit` for candidates it cannot use.
- **Breaking:** `start_gathering` no longer blocks for server-reflexive and
  relayed candidates and returns `Error::Config` if called twice.
- **Breaking:** `sdp::parse` takes a `&MdnsPolicy`.
- **Breaking:** `check::CheckParams` has `integrity: IntegrityMode` instead of
  `legacy_integrity` and a `Zeroizing<String>` `remote_pwd`; `build_check`,
  `build_success_response`, and `build_error_response` return `Result`, and
  the responses take the request's `check::Integrity`; `verify_integrity` takes
  the accepted `IntegrityMode` and returns the `Integrity` that verified;
  `ValidatedRequest` gains `integrity` and `unknown_attributes`.
- **Breaking:** `role::random_tiebreaker` returns `Result<u64>`.
- **Breaking:** `ConsentTracker` follows RFC 7675: `on_sent(now)`,
  `on_response(now)`, `poll_expiry(now)`, `revoke`, `is_expired`, and
  `expires_at`; `CONSENT_FAILURE_THRESHOLD`, `outstanding`, and `is_failed`
  are gone, `CONSENT_INTERVAL` is 5 s, and `CONSENT_TIMEOUT` is 30 s.
- **Breaking:** `Checklist::new(role, max_pairs)`; `pairs` is private
  (`pairs()`); `add_pair` returns `Option<usize>` (`None` at the limit);
  `next_check` takes a readiness predicate; `best_succeeded` and
  `nomination::select_nominee` consider valid pairs only;
  `nomination::mark_nominated` is replaced by `Checklist::set_nominated`.
- **Breaking:** `CandidatePair::foundation` returns `&str`; `CandidatePair`
  gains `valid` and `valid_pair`.
- **Breaking:** `gather::gather_host` takes the bound socket address;
  `gather::gather_srflx` and `gather::gather_relay` are removed.
- **Breaking:** `Error` gains `NoSelectedPair`, `ConsentExpired`, `Failed`,
  `Limit`, `Rng`, and `Unsupported`.
- **Breaking:** requires stun-rs 0.2 (`>=0.2, <0.3`), turn-rs 0.2
  (`>=0.2, <0.3`), and networkframework 0.14 (`>=0.14, <0.15`); adds `zeroize`
  (`>=1.6, <1.9`).
- `rust-version` is 1.82.

### Added

- `AgentStats` (`IceAgent::stats`), `IceAgent::gathering_state`,
  `IceAgent::wait_for_gathering`, `Limits`, `IntegrityMode`, `MdnsPolicy`,
  `TransportPolicy` (`Relay` gathers and uses relayed candidates only), and the
  `Clock` trait with `SystemClock`.
- `SharedSocket::recv_with_destination` (with `Received`) and
  `SharedSocket::send_from`.
- `check::build_unknown_attributes_response` and `check::Integrity`.
- Loopback tests against scripted peers, a STUN server, and a relaying TURN
  server, and offline examples: `01_gather_local_candidates` enumerates
  interfaces without binding a socket, and `02_full_gather` gathers against an
  in-process STUN server.

## [0.1.0] - 2026-06-04

Initial release: a synchronous, runtime-free full-ICE agent.

### Added

- **`IceAgent`** — the synchronous public agent with a single background thread
  that owns the socket and drives the `Ta`-paced scheduler, RTO retransmission,
  and the timeout / nomination / consent ticks. State is shared through an
  `Arc<Mutex<…>>`; all public methods are ordinary blocking calls.
- **Candidate gathering** (`gather`, `candidate`) — host, server-reflexive
  (STUN), and relayed (TURN) candidates with RFC 8445 priority and foundation
  computation.
- **Check lists** (`checklist`, `pair`) — foundation freezing/unfreezing, the
  full pair state machine, and a triggered-check queue.
- **Connectivity checks** (`check`) — building and validating Binding requests
  with `USERNAME`, `PRIORITY`, role attributes, `USE-CANDIDATE`,
  `MESSAGE-INTEGRITY`(-SHA256), and `FINGERPRINT`.
- **Role-conflict resolution** (`role`) — `487` tiebreaker handling for
  both-controlling and both-controlled collisions.
- **Regular nomination** (`nomination`) — controller-driven `USE-CANDIDATE`
  nomination and controlled-side selection.
- **Trickle ICE** (`trickle`) — incremental remote-candidate signaling and
  end-of-candidates handling (RFC 8838).
- **Consent freshness** (`consent`) — periodic checks with the three-strike
  failure rule (RFC 7675).
- **SDP candidate grammar** (`sdp`) — `to_sdp` / `parse` for `a=candidate:`
  lines including `raddr` / `rport` (RFC 8839).
- **First-byte demultiplexing** (`packet`) — STUN / DTLS / SRTP / ChannelData
  classification (RFC 5764 §5.1.2).
- Three examples (`01_gather_local_candidates`, `02_full_gather`,
  `03_loopback_pair`) and ten integration test suites covering candidate
  priority, foundations, connectivity checks, role conflict, check-list state,
  nomination, SDP round-trips, demultiplexing, consent freshness, and an
  end-to-end two-agent loopback negotiation.

[0.1.0]: https://github.com/doom-fish/ice-rs/releases/tag/v0.1.0
