//! The [`IceAgent`]: the user-facing ICE state machine (RFC 8445 + RFC 8838 +
//! RFC 7675).
//!
//! # Threading model
//!
//! The public API is fully synchronous and uses **no async runtime**. All
//! protocol work happens on a single background thread that owns the receive
//! loop and the `Ta`-paced check scheduler. Shared state lives behind an
//! `Arc<Mutex<…>>`; public methods lock it briefly to mutate state, and the
//! background loop locks it once per iteration to advance the state machine.
//! Each TURN server gets a worker thread that owns its `TurnClient`; the
//! client's traffic runs over the agent's socket.
//!
//! The background thread blocks in [`SharedSocket::recv_with_destination`]
//! with a short read timeout (`Ta`, 50 ms). Each wake-up:
//!
//! 1. processes one inbound datagram (STUN handled internally, TURN responses
//!    handed to the relay worker, everything else from a validated remote
//!    demuxed to the [`PacketSink`]);
//! 2. runs the paced scheduler (the next server-reflexive Binding, triggered
//!    or ordinary check, or nomination);
//! 3. retransmits or fails timed-out checks;
//! 4. services consent-freshness timers;
//! 5. detects a failed check list.
//!
//! Callbacks and the packet sink run after the state lock is released.
//!
//! When a pair is nominated the selected `(local, remote)` pair is published,
//! and [`IceAgent::wait_for_selected_pair`] returns it.

use std::collections::{HashMap, HashSet, VecDeque};
use std::io;
use std::mem;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::panic::{self, AssertUnwindSafe};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender, TryRecvError};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, TryLockError};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use stun::attribute::types;
use stun::transaction::{RetransmitSchedule, DEFAULT_RTO};
use stun::{Class, Message, Method, TransactionId};
use turn::{AllocateOptions, Allocation, Scheme, TurnClient};

use crate::candidate::{Candidate, CandidateType};
use crate::check::{
    build_check, build_error_response, build_success_response, build_unknown_attributes_response,
    response_error_code, response_mapped_address, validate_request, verify_integrity, CheckParams,
};
use crate::checklist::Checklist;
use crate::component::{ComponentId, Transport};
use crate::config::{IceConfig, IntegrityMode, TransportPolicy, TurnServer};
use crate::consent::{ConsentTracker, CONSENT_TIMEOUT};
use crate::error::{Error, Result};
use crate::gather::{gather_host, GatherState};
use crate::nomination::select_nominee;
use crate::packet::{classify, PacketKind};
use crate::pair::{CandidatePair, PairState};
use crate::relay::{RelayInbox, RelayTransport};
use crate::role::{random_tiebreaker, resolve_conflict, ConflictOutcome, IceRole};
use crate::socket::{PacketSink, SharedSocket};
use crate::trickle::{LocalCandidateCallback, TrickleState};

/// The check-pacing interval `Ta` (RFC 8445 §14.2). Also the socket read
/// timeout, so the event loop wakes at least this often.
const TA: Duration = Duration::from_millis(50);

/// Receive buffer size (a UDP datagram on a typical MTU never exceeds this).
const RECV_BUF: usize = 65_536;

const RELAY_CLOSE_TIMEOUT: Duration = Duration::from_millis(800);
const WORKER_SHUTDOWN: Duration = Duration::from_millis(1500);
const WORKER_FORCED_SHUTDOWN: Duration = Duration::from_millis(500);
const MAINTENANCE_POLL: Duration = Duration::from_secs(5);
const MAINTENANCE_BACKOFF: Duration = Duration::from_secs(1);

#[allow(missing_docs)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct AgentStats {
    pub dropped_unexpected_source: u64,
    pub ignored_unauthenticated_responses: u64,
    pub rejected_requests: u64,
    pub asymmetric_responses: u64,
    pub rejected_candidates: u64,
    pub dropped_pairs: u64,
    pub dropped_peer_reflexive: u64,
    pub send_errors: u64,
    pub relay_errors: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Route {
    Direct(SocketAddr),
    Relay(usize),
}

#[derive(Debug, Clone, Copy)]
enum Purpose {
    Check {
        pair: usize,
        nominating: bool,
        role: IceRole,
        priority: u32,
    },
    Consent,
    Binding {
        server: SocketAddr,
        base: SocketAddr,
    },
}

struct Transaction {
    purpose: Purpose,
    route: Route,
    destination: SocketAddr,
    bytes: Vec<u8>,
    schedule: Option<RetransmitSchedule>,
    deadline: Instant,
    sent: bool,
    cancelled: bool,
    integrity: IntegrityMode,
}

enum RelayCommand {
    Permit(IpAddr),
    Shutdown,
}

struct Relay {
    server: Option<SocketAddr>,
    inbox: Arc<RelayInbox>,
    commands: Sender<RelayCommand>,
    candidate: Option<Candidate>,
    permitted: HashSet<IpAddr>,
    requested: HashSet<IpAddr>,
    refused: HashSet<IpAddr>,
}

enum Event {
    LocalCandidate(Candidate),
    Failed,
}

type Delivery = (PacketKind, Vec<u8>, SocketAddr);

struct Outputs {
    events: Vec<Event>,
    deliveries: Vec<Delivery>,
    sink: Option<Arc<dyn PacketSink>>,
}

/// All mutable agent state, shared between the public API and the event loop.
struct Inner {
    config: IceConfig,
    role: IceRole,
    tiebreaker: u64,
    bound: SocketAddr,
    checklist: Checklist,
    local_candidates: Vec<Candidate>,
    remote_candidates: Vec<Candidate>,
    remote_peer_reflexive: usize,
    local_peer_reflexive: usize,
    selected: Option<usize>,
    transactions: HashMap<TransactionId, Transaction>,
    unsent: VecDeque<TransactionId>,
    pending_nomination: HashSet<usize>,
    consent: Option<ConsentTracker>,
    trickle: TrickleState,
    gather_state: GatherState,
    gather_pending: usize,
    relays: Vec<Relay>,
    next_paced: Instant,
    sink: Option<Arc<dyn PacketSink>>,
    failed: bool,
    stats: AgentStats,
    shutdown: bool,
    events: Vec<Event>,
    deliveries: Vec<Delivery>,
}

#[derive(Default)]
struct Callbacks {
    on_local: Option<LocalCandidateCallback>,
    on_failed: Option<Box<dyn FnMut() + Send>>,
}

struct Shared {
    inner: Mutex<Inner>,
    callbacks: Mutex<Callbacks>,
    queued: Mutex<Vec<Event>>,
    socket: SharedSocket,
}

impl Shared {
    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn with<R>(&self, f: impl FnOnce(&mut Inner, &SharedSocket) -> R) -> R {
        let mut inner = self.lock();
        let result = f(&mut inner, &self.socket);
        let outputs = inner.take_outputs();
        drop(inner);
        self.dispatch(outputs);
        result
    }

    fn dispatch(&self, outputs: Outputs) {
        if let Some(sink) = outputs.sink {
            for (kind, bytes, from) in outputs.deliveries {
                let _ =
                    panic::catch_unwind(AssertUnwindSafe(|| sink.on_packet(kind, &bytes, from)));
            }
        }
        if outputs.events.is_empty() {
            return;
        }
        self.queued
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .extend(outputs.events);
        loop {
            let mut callbacks = match self.callbacks.try_lock() {
                Ok(callbacks) => callbacks,
                Err(TryLockError::Poisoned(poisoned)) => poisoned.into_inner(),
                Err(TryLockError::WouldBlock) => return,
            };
            let batch = mem::take(&mut *self.queued.lock().unwrap_or_else(PoisonError::into_inner));
            for event in batch {
                let _ = panic::catch_unwind(AssertUnwindSafe(|| match event {
                    Event::LocalCandidate(candidate) => {
                        if let Some(callback) = &mut callbacks.on_local {
                            callback(candidate);
                        }
                    }
                    Event::Failed => {
                        if let Some(callback) = &mut callbacks.on_failed {
                            callback();
                        }
                    }
                }));
            }
            drop(callbacks);
            if self
                .queued
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .is_empty()
            {
                return;
            }
        }
    }
}

fn acceptable_remote(addr: SocketAddr) -> bool {
    let ip = addr.ip();
    let broadcast = matches!(ip, IpAddr::V4(v4) if v4.is_broadcast());
    addr.port() != 0 && !ip.is_unspecified() && !ip.is_multicast() && !broadcast
}

fn peer_reflexive_priority(local: &Candidate) -> u32 {
    (CandidateType::PeerReflexive.type_preference() << 24) | (local.priority & 0x00FF_FFFF)
}

fn relay_route(relays: &[Relay], local: &Candidate) -> Route {
    relays
        .iter()
        .position(|relay| {
            relay
                .candidate
                .as_ref()
                .is_some_and(|candidate| candidate.addr == local.base)
        })
        .map_or(Route::Direct(local.base), Route::Relay)
}

fn pair_ready(relays: &[Relay], pair: &CandidatePair) -> bool {
    match relay_route(relays, &pair.local) {
        Route::Direct(_) => true,
        Route::Relay(index) => relays[index].permitted.contains(&pair.remote.addr.ip()),
    }
}

impl Inner {
    fn now(&self) -> Instant {
        self.config.clock.now()
    }

    fn take_outputs(&mut self) -> Outputs {
        let deliveries = mem::take(&mut self.deliveries);
        let sink = if deliveries.is_empty() {
            None
        } else {
            self.sink.clone()
        };
        Outputs {
            events: mem::take(&mut self.events),
            deliveries,
            sink,
        }
    }

    fn route_of(&self, local: &Candidate) -> Route {
        relay_route(&self.relays, local)
    }

    fn transmit(
        &mut self,
        socket: &SharedSocket,
        route: Route,
        destination: SocketAddr,
        bytes: &[u8],
    ) -> io::Result<()> {
        let outcome = match route {
            Route::Direct(local) => {
                if self.bound.ip().is_unspecified() && !local.ip().is_unspecified() {
                    socket.send_from(bytes, local.ip(), destination).map(drop)
                } else {
                    socket.send_to(bytes, destination).map(drop)
                }
            }
            Route::Relay(index) => match self.relays.get(index).and_then(|relay| relay.server) {
                Some(server) => turn::indication::encode_send(destination, bytes)
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))
                    .and_then(|wrapped| socket.send_to(&wrapped, server).map(drop)),
                None => Err(io::Error::new(
                    io::ErrorKind::NotConnected,
                    "relay has no server address",
                )),
            },
        };
        if outcome.is_err() {
            self.stats.send_errors += 1;
        }
        outcome
    }

    fn set_role(&mut self, role: IceRole) {
        self.role = role;
        self.checklist.set_role(role);
    }

    fn fail(&mut self) {
        if !self.failed {
            self.failed = true;
            self.events.push(Event::Failed);
        }
    }

    fn lose_consent(&mut self) {
        if let Some(consent) = &mut self.consent {
            consent.revoke();
        }
        self.transactions
            .retain(|_, tx| !matches!(tx.purpose, Purpose::Consent));
        self.fail();
    }

    fn gather_finished_one(&mut self) {
        self.gather_pending = self.gather_pending.saturating_sub(1);
        if self.gather_pending == 0 && self.gather_state == GatherState::Gathering {
            self.gather_state = GatherState::Complete;
            self.trickle.set_local_done();
        }
    }

    fn add_pair(&mut self, local: Candidate, remote: Candidate) -> Option<usize> {
        if local.addr.is_ipv4() != remote.addr.is_ipv4() || local.component != remote.component {
            return None;
        }
        let route = self.route_of(&local);
        let remote_ip = remote.addr.ip();
        let Some(idx) = self.checklist.add_pair(local, remote) else {
            self.stats.dropped_pairs += 1;
            return None;
        };
        if let Route::Relay(index) = route {
            let relay = &mut self.relays[index];
            if relay.refused.contains(&remote_ip) {
                self.checklist.on_failure(idx);
            } else if relay.requested.insert(remote_ip) {
                let _ = relay.commands.send(RelayCommand::Permit(remote_ip));
            }
        }
        Some(idx)
    }

    fn fail_pair(&mut self, pair: usize) {
        self.pending_nomination.remove(&pair);
        let valid = self.checklist.pairs()[pair].valid_pair;
        self.checklist.on_failure(pair);
        if let Some(valid) = valid.filter(|&valid| valid != pair) {
            self.checklist.on_failure(valid);
        }
    }

    fn add_local_candidate(&mut self, candidate: Candidate) {
        if self
            .local_candidates
            .iter()
            .any(|c| c.addr == candidate.addr && c.base == candidate.base)
        {
            return;
        }
        self.local_candidates.push(candidate.clone());
        if matches!(candidate.typ, CandidateType::Host | CandidateType::Relayed) {
            for remote in self.remote_candidates.clone() {
                self.add_pair(candidate.clone(), remote);
            }
            self.checklist.unfreeze_initial();
        }
        self.events.push(Event::LocalCandidate(candidate));
    }

    fn add_remote_candidate(&mut self, candidate: Candidate) -> Result<()> {
        if candidate.component != ComponentId::RTP || candidate.transport != Transport::Udp {
            self.stats.rejected_candidates += 1;
            return Err(Error::Unsupported(
                "only UDP candidates for component 1 are supported",
            ));
        }
        if !acceptable_remote(candidate.addr) {
            self.stats.rejected_candidates += 1;
            return Err(Error::Unsupported(
                "candidate address is unspecified, multicast, broadcast, or has port 0",
            ));
        }
        if self
            .remote_candidates
            .iter()
            .any(|c| c.addr == candidate.addr)
        {
            return Ok(());
        }
        let signaled = self.remote_candidates.len() - self.remote_peer_reflexive;
        if signaled >= self.config.limits.max_remote_candidates {
            self.stats.rejected_candidates += 1;
            return Err(Error::Limit("remote candidates"));
        }
        self.remote_candidates.push(candidate.clone());
        let locals: Vec<Candidate> = self
            .local_candidates
            .iter()
            .filter(|c| matches!(c.typ, CandidateType::Host | CandidateType::Relayed))
            .cloned()
            .collect();
        for local in locals {
            self.add_pair(local, candidate.clone());
        }
        self.checklist.unfreeze_initial();
        Ok(())
    }

    fn remote_for_request(&mut self, from: SocketAddr, priority: u32) -> Option<Candidate> {
        if let Some(remote) = self.remote_candidates.iter().find(|r| r.addr == from) {
            return Some(remote.clone());
        }
        if self.remote_peer_reflexive >= self.config.limits.max_peer_reflexive
            || !acceptable_remote(from)
        {
            self.stats.dropped_peer_reflexive += 1;
            return None;
        }
        let remote = Candidate::peer_reflexive(from, from, priority, ComponentId::RTP);
        self.remote_candidates.push(remote.clone());
        self.remote_peer_reflexive += 1;
        Some(remote)
    }

    fn arrival_candidate(&self, arrival: Route) -> Option<Candidate> {
        match arrival {
            Route::Direct(local) => self
                .local_candidates
                .iter()
                .find(|c| c.typ == CandidateType::Host && c.addr == local)
                .cloned(),
            Route::Relay(index) => self.relays.get(index)?.candidate.clone(),
        }
    }

    fn validated_source(&self, from: SocketAddr, arrival: Route) -> bool {
        let matches = |pair: &CandidatePair| {
            pair.remote.addr == from && self.route_of(&pair.local) == arrival
        };
        match self.selected {
            Some(idx) => matches(&self.checklist.pairs()[idx]),
            None => self
                .checklist
                .pairs()
                .iter()
                .any(|pair| pair.valid && matches(pair)),
        }
    }

    fn on_datagram(
        &mut self,
        socket: &SharedSocket,
        data: &[u8],
        from: SocketAddr,
        to: Option<IpAddr>,
        now: Instant,
    ) {
        let local = SocketAddr::new(to.unwrap_or_else(|| self.bound.ip()), self.bound.port());
        if let Some(index) = self.relays.iter().position(|r| r.server == Some(from)) {
            self.on_relay_datagram(socket, index, data, from, local, now);
            return;
        }
        if self.config.policy == TransportPolicy::Relay {
            self.stats.dropped_unexpected_source += 1;
            return;
        }
        self.on_arrival(socket, data, from, Route::Direct(local), now);
    }

    fn on_relay_datagram(
        &mut self,
        socket: &SharedSocket,
        index: usize,
        data: &[u8],
        from: SocketAddr,
        local: SocketAddr,
        now: Instant,
    ) {
        if classify(data) != PacketKind::Stun {
            return;
        }
        let Ok(message) = Message::decode(data) else {
            return;
        };
        match message.class() {
            Class::SuccessResponse | Class::ErrorResponse => {
                if self.transactions.contains_key(message.transaction_id()) {
                    self.on_response(&message, from, Route::Direct(local), now);
                } else {
                    self.relays[index].inbox.push(data.to_vec());
                }
            }
            Class::Indication => {
                if let Ok(Some((peer, payload))) = turn::indication::decode_data(&message) {
                    self.on_arrival(socket, &payload, peer, Route::Relay(index), now);
                }
            }
            Class::Request => {}
        }
    }

    fn on_arrival(
        &mut self,
        socket: &SharedSocket,
        data: &[u8],
        from: SocketAddr,
        arrival: Route,
        now: Instant,
    ) {
        let kind = classify(data);
        if kind.is_stun() {
            let Ok(message) = Message::decode(data) else {
                return;
            };
            if message.method() != Method::Binding {
                return;
            }
            match message.class() {
                Class::Request => self.on_request(socket, &message, from, arrival, now),
                Class::SuccessResponse | Class::ErrorResponse => {
                    self.on_response(&message, from, arrival, now);
                }
                Class::Indication => {}
            }
            return;
        }
        if !self.failed && self.validated_source(from, arrival) {
            self.deliveries.push((kind, data.to_vec(), from));
        } else {
            self.stats.dropped_unexpected_source += 1;
        }
    }

    fn on_request(
        &mut self,
        socket: &SharedSocket,
        message: &Message,
        from: SocketAddr,
        arrival: Route,
        now: Instant,
    ) {
        let expected = self.config.expected_inbound_username();
        let Ok(validated) = validate_request(message, &expected, &self.config.local_pwd) else {
            self.stats.rejected_requests += 1;
            return;
        };
        let tid = *message.transaction_id();
        if !validated.unknown_attributes.is_empty() {
            if let Ok(bytes) = build_unknown_attributes_response(
                message,
                &validated.unknown_attributes,
                &self.config.local_pwd,
                validated.integrity,
            ) {
                let _ = self.transmit(socket, arrival, from, &bytes);
            }
            return;
        }

        match resolve_conflict(self.role, self.tiebreaker, validated.role_attr.as_ref()) {
            ConflictOutcome::Reply487 => {
                if let Ok(bytes) = build_error_response(
                    tid,
                    487,
                    "Role Conflict",
                    &self.config.local_pwd,
                    validated.integrity,
                ) {
                    let _ = self.transmit(socket, arrival, from, &bytes);
                }
                return;
            }
            ConflictOutcome::SwitchRole => self.set_role(self.role.opposite()),
            ConflictOutcome::KeepRole => {}
        }

        if let Ok(bytes) =
            build_success_response(tid, from, &self.config.local_pwd, validated.integrity)
        {
            let _ = self.transmit(socket, arrival, from, &bytes);
        }

        if self.selected.is_some() || self.failed {
            return;
        }
        let Some(local) = self.arrival_candidate(arrival) else {
            return;
        };
        let Some(remote) = self.remote_for_request(from, validated.priority) else {
            return;
        };
        let Some(idx) = self.add_pair(local, remote) else {
            return;
        };
        let state = self.checklist.pairs()[idx].state;
        if state == PairState::InProgress {
            self.cancel_checks(Some(idx));
        }
        self.checklist.enqueue_triggered(idx);

        if validated.use_candidate && self.role == IceRole::Controlled {
            match self.checklist.pairs()[idx].valid_pair {
                Some(valid) if state == PairState::Succeeded => self.nominate(valid, now),
                _ => {
                    self.pending_nomination.insert(idx);
                }
            }
        }
    }

    fn cancel_checks(&mut self, pair: Option<usize>) {
        for tx in self.transactions.values_mut() {
            let Purpose::Check { pair: checked, .. } = tx.purpose else {
                continue;
            };
            if tx.cancelled || pair.is_some_and(|pair| pair != checked) {
                continue;
            }
            let remaining: Duration = tx.schedule.take().map(Iterator::sum).unwrap_or_default();
            tx.deadline += remaining;
            tx.cancelled = true;
        }
    }

    fn on_response(&mut self, message: &Message, from: SocketAddr, arrival: Route, now: Instant) {
        let tid = *message.transaction_id();
        let Some(tx) = self.transactions.get(&tid) else {
            return;
        };
        if let Purpose::Binding { server, base } = tx.purpose {
            self.on_binding_response(message, from, &tid, server, base);
            return;
        }
        if message.verify_fingerprint().is_err()
            || verify_integrity(message, &self.config.remote_pwd, tx.integrity).is_err()
        {
            self.stats.ignored_unauthenticated_responses += 1;
            return;
        }
        let Some(tx) = self.transactions.remove(&tid) else {
            return;
        };
        let symmetric = from == tx.destination && arrival == tx.route;
        if !symmetric {
            self.stats.asymmetric_responses += 1;
        }
        match tx.purpose {
            Purpose::Consent => self.on_consent_response(message, symmetric, now),
            Purpose::Check {
                pair,
                nominating,
                role,
                priority,
            } => {
                if symmetric {
                    self.on_check_response(message, pair, nominating, role, priority, now);
                } else {
                    self.fail_pair(pair);
                }
            }
            Purpose::Binding { .. } => {}
        }
    }

    fn on_binding_response(
        &mut self,
        message: &Message,
        from: SocketAddr,
        tid: &TransactionId,
        server: SocketAddr,
        base: SocketAddr,
    ) {
        if from != server
            || (message.get(types::FINGERPRINT).is_some() && message.verify_fingerprint().is_err())
        {
            self.stats.ignored_unauthenticated_responses += 1;
            return;
        }
        self.transactions.remove(tid);
        if message.class() == Class::SuccessResponse {
            if let Some(mapped) = response_mapped_address(message) {
                self.add_local_candidate(Candidate::server_reflexive(
                    mapped,
                    base,
                    server,
                    ComponentId::RTP,
                ));
            }
        }
        self.gather_finished_one();
    }

    fn on_consent_response(&mut self, message: &Message, symmetric: bool, now: Instant) {
        if !symmetric {
            return;
        }
        match message.class() {
            Class::SuccessResponse => {
                if let Some(consent) = &mut self.consent {
                    consent.on_response(now);
                }
            }
            Class::ErrorResponse if response_error_code(message) == Some(403) => {
                self.lose_consent();
            }
            _ => {}
        }
    }

    fn on_check_response(
        &mut self,
        message: &Message,
        pair: usize,
        nominating: bool,
        role: IceRole,
        priority: u32,
        now: Instant,
    ) {
        if message.class() == Class::ErrorResponse {
            if response_error_code(message) == Some(487) {
                self.pending_nomination.remove(&pair);
                if role == self.role {
                    self.set_role(role.opposite());
                    if let Ok(tiebreaker) = random_tiebreaker() {
                        self.tiebreaker = tiebreaker;
                    }
                }
                self.checklist.enqueue_triggered(pair);
            } else {
                self.fail_pair(pair);
            }
            return;
        }
        if message.class() != Class::SuccessResponse {
            return;
        }
        self.checklist.on_success(pair);
        let valid = self.construct_valid_pair(pair, message, priority);
        self.checklist.mark_valid(valid);
        self.checklist.set_valid_pair(pair, valid);
        if Some(valid) == self.selected {
            if let Some(consent) = &mut self.consent {
                consent.on_response(now);
            }
        }
        let nominate = if nominating {
            self.role.is_controlling()
        } else {
            self.pending_nomination.remove(&pair) && self.role == IceRole::Controlled
        };
        if nominate {
            self.nominate(valid, now);
        }
    }

    fn construct_valid_pair(&mut self, pair: usize, message: &Message, priority: u32) -> usize {
        let (local, remote) = {
            let generating = &self.checklist.pairs()[pair];
            (generating.local.clone(), generating.remote.clone())
        };
        let Some(mapped) = response_mapped_address(message) else {
            return pair;
        };
        if mapped == local.addr {
            return pair;
        }
        let known = self
            .local_candidates
            .iter()
            .find(|c| c.addr == mapped && c.base == local.base)
            .cloned();
        let valid_local = match known {
            Some(candidate) => candidate,
            None => {
                if self.local_peer_reflexive >= self.config.limits.max_peer_reflexive {
                    self.stats.dropped_peer_reflexive += 1;
                    return pair;
                }
                let candidate =
                    Candidate::peer_reflexive(mapped, local.base, priority, local.component);
                self.local_candidates.push(candidate.clone());
                self.local_peer_reflexive += 1;
                candidate
            }
        };
        match self.checklist.find(valid_local.addr, remote.addr) {
            Some(idx) => idx,
            None => self
                .checklist
                .add_pair(valid_local, remote)
                .unwrap_or_else(|| {
                    self.stats.dropped_pairs += 1;
                    pair
                }),
        }
    }

    fn nominate(&mut self, valid: usize, now: Instant) {
        if self.selected.is_some() || self.failed {
            return;
        }
        self.checklist.set_nominated(valid);
        self.selected = Some(valid);
        self.consent = Some(ConsentTracker::new(now));
        self.pending_nomination.clear();
        self.cancel_checks(None);
    }

    fn send_check(&mut self, socket: &SharedSocket, pair: usize, nominating: bool, now: Instant) {
        let (local, destination) = {
            let candidate_pair = &self.checklist.pairs()[pair];
            (candidate_pair.local.clone(), candidate_pair.remote.addr)
        };
        let route = self.route_of(&local);
        let priority = peer_reflexive_priority(&local);
        let params = CheckParams {
            username: self.config.outbound_username(),
            remote_pwd: self.config.remote_pwd.clone(),
            priority,
            role: self.role,
            tiebreaker: self.tiebreaker,
            use_candidate: nominating,
            integrity: self.config.integrity,
        };
        let Ok(built) = build_check(&params) else {
            if !nominating {
                self.checklist.on_failure(pair);
            }
            return;
        };
        let _ = self.transmit(socket, route, destination, &built.bytes);
        let mut schedule = RetransmitSchedule::with_rto(DEFAULT_RTO);
        let first = schedule.next().unwrap_or(DEFAULT_RTO);
        self.transactions.insert(
            built.transaction_id,
            Transaction {
                purpose: Purpose::Check {
                    pair,
                    nominating,
                    role: self.role,
                    priority,
                },
                route,
                destination,
                bytes: built.bytes,
                schedule: Some(schedule),
                deadline: now + first,
                sent: true,
                cancelled: false,
                integrity: self.config.integrity,
            },
        );
    }

    fn start_binding(&mut self, server: SocketAddr) {
        let bases: Vec<SocketAddr> = self
            .local_candidates
            .iter()
            .filter(|c| c.typ == CandidateType::Host && c.addr.is_ipv4() == server.is_ipv4())
            .map(|c| c.addr)
            .collect();
        for base in bases {
            let Ok(transaction_id) = TransactionId::try_random() else {
                continue;
            };
            let Ok(bytes) = Message::builder(Method::Binding, Class::Request)
                .transaction_id(transaction_id)
                .with_fingerprint()
                .build_and_encode()
            else {
                continue;
            };
            let now = self.now();
            self.transactions.insert(
                transaction_id,
                Transaction {
                    purpose: Purpose::Binding { server, base },
                    route: Route::Direct(base),
                    destination: server,
                    bytes,
                    schedule: Some(RetransmitSchedule::with_rto(DEFAULT_RTO)),
                    deadline: now,
                    sent: false,
                    cancelled: false,
                    integrity: IntegrityMode::Sha1,
                },
            );
            self.unsent.push_back(transaction_id);
            self.gather_pending += 1;
        }
        self.gather_finished_one();
    }

    fn add_relay_candidate(&mut self, index: usize, allocation: &Allocation, server: SocketAddr) {
        let relayed = allocation.relayed_address();
        let candidate = Candidate::new(
            CandidateType::Relayed,
            ComponentId::RTP,
            Transport::Udp,
            relayed,
            relayed,
            allocation.mapped_address(),
            Some(server),
            u16::MAX,
        );
        self.relays[index].candidate = Some(candidate.clone());
        self.add_local_candidate(candidate);
        self.gather_finished_one();
    }

    fn relay_pairs(&self, index: usize, ip: Option<IpAddr>) -> Vec<usize> {
        self.checklist
            .pairs()
            .iter()
            .enumerate()
            .filter(|(_, pair)| {
                ip.is_none_or(|ip| pair.remote.addr.ip() == ip)
                    && self.route_of(&pair.local) == Route::Relay(index)
            })
            .map(|(idx, _)| idx)
            .collect()
    }

    fn permission_refused(&mut self, index: usize, ip: IpAddr) {
        self.stats.relay_errors += 1;
        self.relays[index].refused.insert(ip);
        for idx in self.relay_pairs(index, Some(ip)) {
            self.fail_pair(idx);
        }
    }

    fn relay_lost(&mut self, index: usize) {
        self.stats.relay_errors += 1;
        for idx in self.relay_pairs(index, None) {
            self.fail_pair(idx);
        }
    }

    fn tick(&mut self, socket: &SharedSocket, now: Instant) {
        self.pace_tick(socket, now);
        self.timeout_tick(socket, now);
        self.consent_tick(socket, now);
        self.failure_tick();
    }

    fn pace_tick(&mut self, socket: &SharedSocket, now: Instant) {
        if now < self.next_paced {
            return;
        }
        while let Some(tid) = self.unsent.pop_front() {
            let Some(tx) = self.transactions.get_mut(&tid) else {
                continue;
            };
            let first = tx
                .schedule
                .as_mut()
                .and_then(Iterator::next)
                .unwrap_or(DEFAULT_RTO);
            tx.deadline = now + first;
            tx.sent = true;
            let (route, destination, bytes) = (tx.route, tx.destination, tx.bytes.clone());
            let _ = self.transmit(socket, route, destination, &bytes);
            self.next_paced = now + TA;
            return;
        }
        if self.selected.is_some() || self.failed {
            return;
        }
        let relays = &self.relays;
        if let Some(pair) = self
            .checklist
            .next_check(|candidate_pair| pair_ready(relays, candidate_pair))
        {
            self.send_check(socket, pair, false, now);
            self.next_paced = now + TA;
            return;
        }
        let nominating = self.transactions.values().any(|tx| {
            matches!(
                tx.purpose,
                Purpose::Check {
                    nominating: true,
                    ..
                }
            ) && !tx.cancelled
        });
        if self.role.is_controlling() && !nominating {
            if let Some(valid) = select_nominee(&self.checklist) {
                let generating = self
                    .checklist
                    .pairs()
                    .iter()
                    .position(|pair| pair.valid_pair == Some(valid))
                    .unwrap_or(valid);
                self.send_check(socket, generating, true, now);
                self.next_paced = now + TA;
            }
        }
    }

    fn timeout_tick(&mut self, socket: &SharedSocket, now: Instant) {
        let due: Vec<TransactionId> = self
            .transactions
            .iter()
            .filter(|(_, tx)| tx.sent && now >= tx.deadline)
            .map(|(tid, _)| *tid)
            .collect();
        for tid in due {
            let Some(tx) = self.transactions.get_mut(&tid) else {
                continue;
            };
            let next = if tx.cancelled {
                None
            } else {
                tx.schedule.as_mut().and_then(Iterator::next)
            };
            if let Some(wait) = next {
                tx.deadline = now + wait;
                let (route, destination, bytes) = (tx.route, tx.destination, tx.bytes.clone());
                let _ = self.transmit(socket, route, destination, &bytes);
                continue;
            }
            let Some(tx) = self.transactions.remove(&tid) else {
                continue;
            };
            match tx.purpose {
                Purpose::Check { pair, .. } if !tx.cancelled => self.fail_pair(pair),
                Purpose::Binding { .. } => self.gather_finished_one(),
                Purpose::Check { .. } | Purpose::Consent => {}
            }
        }
    }

    fn consent_tick(&mut self, socket: &SharedSocket, now: Instant) {
        let Some(selected) = self.selected else {
            return;
        };
        let Some(consent) = self.consent.as_mut() else {
            return;
        };
        if consent.poll_expiry(now) {
            self.lose_consent();
            return;
        }
        if !consent.due(now) {
            return;
        }
        consent.on_sent(now);
        let (local, destination) = {
            let pair = &self.checklist.pairs()[selected];
            (pair.local.clone(), pair.remote.addr)
        };
        let route = self.route_of(&local);
        let params = CheckParams {
            username: self.config.outbound_username(),
            remote_pwd: self.config.remote_pwd.clone(),
            priority: peer_reflexive_priority(&local),
            role: self.role,
            tiebreaker: self.tiebreaker,
            use_candidate: false,
            integrity: self.config.integrity,
        };
        let Ok(built) = build_check(&params) else {
            return;
        };
        let _ = self.transmit(socket, route, destination, &built.bytes);
        self.transactions.insert(
            built.transaction_id,
            Transaction {
                purpose: Purpose::Consent,
                route,
                destination,
                bytes: built.bytes,
                schedule: None,
                deadline: now + CONSENT_TIMEOUT,
                sent: true,
                cancelled: true,
                integrity: self.config.integrity,
            },
        );
    }

    fn failure_tick(&mut self) {
        if self.failed
            || self.selected.is_some()
            || self.gather_state != GatherState::Complete
            || !self.trickle.remote_done()
            || !self.checklist.all_failed()
        {
            return;
        }
        let checking = self
            .transactions
            .values()
            .any(|tx| matches!(tx.purpose, Purpose::Check { .. }));
        if !checking {
            self.fail();
        }
    }

    fn send_selected(&mut self, socket: &SharedSocket, bytes: &[u8]) -> Result<()> {
        let now = self.now();
        if let Some(consent) = self.consent.as_mut() {
            if consent.poll_expiry(now) {
                self.lose_consent();
            }
        }
        let Some(selected) = self.selected else {
            return Err(if self.failed {
                Error::Failed
            } else {
                Error::NoSelectedPair
            });
        };
        if self.failed
            || self
                .consent
                .as_ref()
                .is_some_and(ConsentTracker::is_expired)
        {
            return Err(Error::ConsentExpired);
        }
        let (local, destination) = {
            let pair = &self.checklist.pairs()[selected];
            (pair.local.clone(), pair.remote.addr)
        };
        let route = self.route_of(&local);
        Ok(self.transmit(socket, route, destination, bytes)?)
    }

    fn selected_candidates(&self) -> Option<(Candidate, Candidate)> {
        let pair = &self.checklist.pairs()[self.selected?];
        Some((pair.local.clone(), pair.remote.clone()))
    }
}

/// A full ICE agent for a single session.
///
/// Drive it by gathering local candidates, exchanging them with the peer
/// through your signaling channel, feeding the peer's candidates back in, and
/// waiting for a selected pair. Once selected, send media/DTLS with
/// [`IceAgent::send_on_selected`], which stops working when consent expires.
pub struct IceAgent {
    shared: Arc<Shared>,
    event_loop: Option<JoinHandle<()>>,
    workers: Mutex<Vec<JoinHandle<()>>>,
}

impl IceAgent {
    /// Create an agent, bind its shared socket, and start the event loop.
    ///
    /// The socket binds to [`IceConfig::bind_addr`] when set, otherwise to
    /// `0.0.0.0:0` (an OS-assigned ephemeral port on all interfaces).
    ///
    /// # Errors
    ///
    /// Returns [`Error::Config`] for invalid configuration, [`Error::Rng`] if
    /// no tiebreaker can be drawn, or an I/O error if the socket cannot be
    /// bound.
    pub fn new(config: IceConfig) -> Result<Self> {
        config.validate()?;
        let tiebreaker = random_tiebreaker()?;
        let bind = config
            .bind_addr
            .unwrap_or_else(|| SocketAddr::from(([0, 0, 0, 0], 0)));
        let socket = SharedSocket::bind(bind)?;
        socket.set_read_timeout(TA)?;
        let bound = socket.local_addr()?;

        let role = config.role;
        let now = config.clock.now();
        let max_pairs = config.limits.max_pairs;
        let inner = Inner {
            config,
            role,
            tiebreaker,
            bound,
            checklist: Checklist::new(role, max_pairs),
            local_candidates: Vec::new(),
            remote_candidates: Vec::new(),
            remote_peer_reflexive: 0,
            local_peer_reflexive: 0,
            selected: None,
            transactions: HashMap::new(),
            unsent: VecDeque::new(),
            pending_nomination: HashSet::new(),
            consent: None,
            trickle: TrickleState::new(),
            gather_state: GatherState::New,
            gather_pending: 0,
            relays: Vec::new(),
            next_paced: now,
            sink: None,
            failed: false,
            stats: AgentStats::default(),
            shutdown: false,
            events: Vec::new(),
            deliveries: Vec::new(),
        };
        let shared = Arc::new(Shared {
            inner: Mutex::new(inner),
            callbacks: Mutex::new(Callbacks::default()),
            queued: Mutex::new(Vec::new()),
            socket,
        });

        let loop_shared = Arc::clone(&shared);
        let handle = thread::Builder::new()
            .name("ice-agent".into())
            .spawn(move || run_loop(&loop_shared))
            .map_err(|_| Error::Config("failed to spawn ICE event loop"))?;

        Ok(Self {
            shared,
            event_loop: Some(handle),
            workers: Mutex::new(Vec::new()),
        })
    }

    /// Install the sink that receives non-STUN packets (DTLS, SRTP, …)
    /// demultiplexed off the shared socket. Only packets from the selected
    /// pair's remote (or, before selection, from the remote of a validated
    /// pair) reach it; everything else is dropped and counted in
    /// [`AgentStats::dropped_unexpected_source`].
    pub fn set_packet_sink(&self, sink: Arc<dyn PacketSink>) {
        self.shared.lock().sink = Some(sink);
    }

    /// Register a callback fired once for each freshly gathered local candidate
    /// (trickle ICE, RFC 8838). The callback runs on an agent thread after the
    /// agent's state lock is released; it may call back into the agent but
    /// must not register callbacks.
    pub fn on_local_candidate<F>(&self, callback: F)
    where
        F: FnMut(Candidate) + Send + 'static,
    {
        self.shared
            .callbacks
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .on_local = Some(Box::new(callback));
    }

    /// Register a callback fired when consent is lost (RFC 7675) or every
    /// candidate pair failed, and the connection has failed.
    pub fn on_connection_failed<F>(&self, callback: F)
    where
        F: FnMut() + Send + 'static,
    {
        self.shared
            .callbacks
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .on_failed = Some(Box::new(callback));
    }

    /// Gather local candidates: host addresses, then (if configured) server-
    /// reflexive and relayed candidates. Each candidate is delivered through the
    /// [`IceAgent::on_local_candidate`] callback and paired against any remote
    /// candidates already added.
    ///
    /// Host candidates are gathered before this returns. Server-reflexive
    /// candidates come from STUN Binding requests sent from the agent's own
    /// socket, and relayed candidates from TURN allocations made over that
    /// socket; both arrive later through the callback. Use
    /// [`IceAgent::wait_for_gathering`] to wait for them.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Config`] if gathering was already started.
    pub fn start_gathering(&self) -> Result<()> {
        let (stun_servers, relays) = self.shared.with(|inner, _| {
            if inner.gather_state != GatherState::New {
                return Err(Error::Config("gathering already started"));
            }
            inner.gather_state = GatherState::Gathering;
            inner.gather_pending = 1;
            let mut stun_servers = Vec::new();
            if inner.config.policy == TransportPolicy::All {
                for candidate in gather_host(inner.bound, ComponentId::RTP) {
                    inner.add_local_candidate(candidate);
                }
                stun_servers = inner.config.stun_servers.clone();
                inner.gather_pending += stun_servers.len();
            }
            let mut relays = Vec::new();
            for server in inner.config.turn_servers.clone() {
                let (commands, receiver) = mpsc::channel();
                let inbox = Arc::new(RelayInbox::default());
                inner.relays.push(Relay {
                    server: None,
                    inbox: Arc::clone(&inbox),
                    commands,
                    candidate: None,
                    permitted: HashSet::new(),
                    requested: HashSet::new(),
                    refused: HashSet::new(),
                });
                inner.gather_pending += 1;
                relays.push((inner.relays.len() - 1, server, inbox, receiver));
            }
            Ok((stun_servers, relays))
        })?;

        let mut workers = self.workers.lock().unwrap_or_else(PoisonError::into_inner);
        let ipv4 = self.shared.lock().bound.is_ipv4();
        if !stun_servers.is_empty() {
            let servers = stun_servers.len();
            let shared = Arc::clone(&self.shared);
            let spawned = thread::Builder::new()
                .name("ice-gather".into())
                .spawn(move || {
                    for server in stun_servers {
                        let resolved = resolve(server.host(), server.port(), ipv4);
                        shared.with(|inner, _| match resolved {
                            Some(address) => inner.start_binding(address),
                            None => inner.gather_finished_one(),
                        });
                    }
                });
            match spawned {
                Ok(handle) => workers.push(handle),
                Err(_) => self.shared.with(|inner, _| {
                    for _ in 0..servers {
                        inner.gather_finished_one();
                    }
                }),
            }
        }
        for (index, server, inbox, receiver) in relays {
            let shared = Arc::clone(&self.shared);
            let spawned = thread::Builder::new()
                .name("ice-turn".into())
                .spawn(move || relay_worker(&shared, index, server, inbox, &receiver, ipv4));
            match spawned {
                Ok(handle) => workers.push(handle),
                Err(_) => self.shared.with(|inner, _| inner.gather_finished_one()),
            }
        }
        drop(workers);
        self.shared.with(|inner, _| inner.gather_finished_one());
        Ok(())
    }

    /// Add a remote candidate learned from signaling, forming pairs with all
    /// local candidates and unfreezing them for checking (trickle ICE).
    ///
    /// # Errors
    ///
    /// Returns [`Error::Unsupported`] for candidates this agent cannot use
    /// (not UDP, not component 1, or an unspecified, multicast, broadcast, or
    /// port-0 address) and [`Error::Limit`] once
    /// [`crate::Limits::max_remote_candidates`] is reached.
    pub fn add_remote_candidate(&self, c: Candidate) -> Result<()> {
        self.shared.with(|inner, _| inner.add_remote_candidate(c))
    }

    /// Signal that we have gathered our last local candidate (RFC 8838 §8).
    pub fn end_of_candidates(&self) {
        self.shared.lock().trickle.set_local_done();
    }

    /// Record that the peer signaled end-of-candidates (RFC 8838 §8).
    pub fn remote_end_of_candidates(&self) {
        self.shared.lock().trickle.set_remote_done();
    }

    #[allow(missing_docs)]
    #[must_use]
    pub fn gathering_state(&self) -> GatherState {
        self.shared.lock().gather_state
    }

    #[allow(missing_docs)]
    pub fn wait_for_gathering(&self, timeout: Duration) -> Result<()> {
        let deadline = Instant::now().checked_add(timeout);
        while self.gathering_state() != GatherState::Complete {
            if deadline.is_some_and(|deadline| Instant::now() >= deadline) {
                return Err(Error::Timeout);
            }
            thread::sleep(Duration::from_millis(10));
        }
        Ok(())
    }

    /// Block until a candidate pair is nominated, returning the selected local
    /// and remote candidates.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Timeout`] if no pair is selected within `timeout`, or
    /// [`Error::Failed`] if the check list failed first.
    pub fn wait_for_selected_pair(&self, timeout: Duration) -> Result<(Candidate, Candidate)> {
        let deadline = Instant::now().checked_add(timeout);
        loop {
            {
                let inner = self.shared.lock();
                if let Some(pair) = inner.selected_candidates() {
                    return Ok(pair);
                }
                if inner.failed {
                    return Err(Error::Failed);
                }
            }
            if deadline.is_some_and(|deadline| Instant::now() >= deadline) {
                return Err(Error::Timeout);
            }
            thread::sleep(Duration::from_millis(10));
        }
    }

    /// The currently selected pair, if any.
    #[must_use]
    pub fn selected_pair(&self) -> Option<(Candidate, Candidate)> {
        self.shared.lock().selected_candidates()
    }

    /// Send `bytes` to the remote of the selected pair, through the TURN
    /// server when the pair's local candidate is relayed.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NoSelectedPair`] if no pair has been selected yet,
    /// [`Error::ConsentExpired`] once consent has expired (RFC 7675),
    /// [`Error::Failed`] if the check list failed, or an I/O error on send
    /// failure.
    pub fn send_on_selected(&self, bytes: &[u8]) -> Result<()> {
        self.shared
            .with(|inner, socket| inner.send_selected(socket, bytes))
    }

    /// A snapshot of the local candidates gathered so far.
    #[must_use]
    pub fn local_candidates(&self) -> Vec<Candidate> {
        self.shared
            .lock()
            .local_candidates
            .iter()
            .filter(|c| c.typ != CandidateType::PeerReflexive)
            .cloned()
            .collect()
    }

    /// The current ICE role (which may have changed via role-conflict
    /// resolution).
    #[must_use]
    pub fn role(&self) -> IceRole {
        self.shared.lock().role
    }

    #[allow(missing_docs)]
    #[must_use]
    pub fn stats(&self) -> AgentStats {
        self.shared.lock().stats
    }

    /// The local transport address the agent is bound to.
    ///
    /// # Errors
    ///
    /// Returns the underlying I/O error if the address cannot be read.
    pub fn local_addr(&self) -> Result<SocketAddr> {
        Ok(self.shared.socket.local_addr()?)
    }
}

impl Drop for IceAgent {
    fn drop(&mut self) {
        let inboxes: Vec<Arc<RelayInbox>> = {
            let inner = self.shared.lock();
            for relay in &inner.relays {
                let _ = relay.commands.send(RelayCommand::Shutdown);
            }
            inner
                .relays
                .iter()
                .map(|relay| Arc::clone(&relay.inbox))
                .collect()
        };
        let mut workers =
            mem::take(&mut *self.workers.lock().unwrap_or_else(PoisonError::into_inner));
        join_until(&mut workers, Instant::now() + WORKER_SHUTDOWN);
        for inbox in &inboxes {
            inbox.close();
        }
        join_until(&mut workers, Instant::now() + WORKER_FORCED_SHUTDOWN);
        self.shared.lock().shutdown = true;
        if let Some(handle) = self.event_loop.take() {
            let _ = handle.join();
        }
    }
}

impl std::fmt::Debug for IceAgent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IceAgent")
            .field("socket", &self.shared.socket)
            .finish_non_exhaustive()
    }
}

fn join_until(workers: &mut Vec<JoinHandle<()>>, deadline: Instant) {
    loop {
        let (done, pending): (Vec<_>, Vec<_>) = mem::take(workers)
            .into_iter()
            .partition(JoinHandle::is_finished);
        for handle in done {
            let _ = handle.join();
        }
        *workers = pending;
        if workers.is_empty() || Instant::now() >= deadline {
            return;
        }
        thread::sleep(Duration::from_millis(5));
    }
}

fn resolve(host: &str, port: u16, ipv4: bool) -> Option<SocketAddr> {
    (host, port)
        .to_socket_addrs()
        .ok()?
        .find(|addr| addr.is_ipv4() == ipv4)
}

fn relay_worker(
    shared: &Shared,
    index: usize,
    server: TurnServer,
    inbox: Arc<RelayInbox>,
    commands: &Receiver<RelayCommand>,
    ipv4: bool,
) {
    let address = if server.uri.scheme == Scheme::Udp {
        resolve(&server.uri.host, server.uri.port, ipv4)
    } else {
        None
    };
    let Some(address) = address else {
        shared.with(|inner, _| {
            inner.stats.relay_errors += 1;
            inner.gather_finished_one();
        });
        return;
    };
    shared.with(|inner, _| inner.relays[index].server = Some(address));
    let transport = Arc::new(RelayTransport {
        socket: shared.socket.clone(),
        server: address,
        inbox,
    });
    let Ok(mut client) = TurnClient::with_transport(transport, server.credential) else {
        shared.with(|inner, _| {
            inner.stats.relay_errors += 1;
            inner.gather_finished_one();
        });
        return;
    };
    match client.allocate(&AllocateOptions::default()) {
        Ok(allocation) => {
            shared.with(|inner, _| inner.add_relay_candidate(index, &allocation, address));
        }
        Err(_) => {
            shared.with(|inner, _| {
                inner.stats.relay_errors += 1;
                inner.gather_finished_one();
            });
            let _ = client.close(RELAY_CLOSE_TIMEOUT);
            return;
        }
    }
    let mut shutdown = false;
    let mut backoff = Duration::ZERO;
    let mut retry_at: Option<Instant> = None;
    while !shutdown {
        let due = client
            .next_maintenance()
            .map_or(MAINTENANCE_POLL, |due| due.min(MAINTENANCE_POLL));
        let wait = retry_at.map_or(due, |at| {
            due.max(at.saturating_duration_since(Instant::now()))
        });
        match commands.recv_timeout(wait) {
            Ok(RelayCommand::Permit(ip)) => {
                let mut ips = vec![ip];
                loop {
                    match commands.try_recv() {
                        Ok(RelayCommand::Permit(more)) => ips.push(more),
                        Ok(RelayCommand::Shutdown) | Err(TryRecvError::Disconnected) => {
                            shutdown = true;
                            break;
                        }
                        Err(TryRecvError::Empty) => break,
                    }
                }
                for ip in ips {
                    let outcome = client.create_permission(&[SocketAddr::new(ip, 0)]);
                    shared.with(|inner, _| match outcome {
                        Ok(()) => {
                            inner.relays[index].permitted.insert(ip);
                        }
                        Err(_) => inner.permission_refused(index, ip),
                    });
                }
            }
            Ok(RelayCommand::Shutdown) | Err(RecvTimeoutError::Disconnected) => shutdown = true,
            Err(RecvTimeoutError::Timeout) => {
                if retry_at.is_some_and(|at| Instant::now() < at) {
                    continue;
                }
                if client.maintain().is_ok() {
                    backoff = Duration::ZERO;
                    retry_at = None;
                    continue;
                }
                if client.allocation().is_none() {
                    shared.with(|inner, _| inner.relay_lost(index));
                    break;
                }
                backoff = (backoff * 2).clamp(MAINTENANCE_BACKOFF, MAINTENANCE_POLL * 6);
                retry_at = Instant::now().checked_add(backoff);
                shared.with(|inner, _| inner.stats.relay_errors += 1);
            }
        }
    }
    let _ = client.close(RELAY_CLOSE_TIMEOUT);
}

/// The background event loop: receive, then advance the state machine.
fn run_loop(shared: &Shared) {
    let mut buf = vec![0u8; RECV_BUF];
    loop {
        let received = shared.socket.recv_with_destination(&mut buf);
        let mut inner = shared.lock();
        if inner.shutdown {
            break;
        }
        let now = inner.now();
        if let Ok(received) = received {
            inner.on_datagram(
                &shared.socket,
                &buf[..received.len],
                received.from,
                received.to,
                now,
            );
        }
        inner.tick(&shared.socket, now);
        let outputs = inner.take_outputs();
        drop(inner);
        shared.dispatch(outputs);
    }
}
