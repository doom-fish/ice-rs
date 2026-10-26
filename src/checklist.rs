//! The ordered check list with foundation-based freezing (RFC 8445 §6.1.2).

use std::collections::{HashMap, HashSet, VecDeque};
use std::net::SocketAddr;

use crate::candidate::Candidate;
use crate::pair::{CandidatePair, PairState};
use crate::role::IceRole;

#[allow(missing_docs)]
pub const DEFAULT_MAX_PAIRS: usize = 100;

/// An ordered list of candidate pairs plus the triggered-check queue.
///
/// Pairs are stored in insertion order so their indices stay stable (they are
/// used as identifiers in the triggered-check queue). Ordering by priority is
/// computed on demand when selecting the next check.
#[derive(Debug)]
pub struct Checklist {
    role: IceRole,
    pairs: Vec<CandidatePair>,
    index: HashMap<(SocketAddr, SocketAddr), usize>,
    triggered: VecDeque<usize>,
    in_progress: HashMap<String, usize>,
    max_pairs: usize,
}

impl Checklist {
    /// Create an empty check list for the given role, holding at most
    /// `max_pairs` pairs (RFC 8445 §6.1.2.5).
    #[must_use]
    pub fn new(role: IceRole, max_pairs: usize) -> Self {
        Self {
            role,
            pairs: Vec::new(),
            index: HashMap::new(),
            triggered: VecDeque::new(),
            in_progress: HashMap::new(),
            max_pairs,
        }
    }

    /// Update the role and recompute every pair's priority (after a role
    /// conflict resolution).
    pub fn set_role(&mut self, role: IceRole) {
        self.role = role;
        for pair in &mut self.pairs {
            pair.recompute_priority(role);
        }
    }

    /// The current role.
    #[must_use]
    pub const fn role(&self) -> IceRole {
        self.role
    }

    #[allow(missing_docs)]
    #[must_use]
    pub fn pairs(&self) -> &[CandidatePair] {
        &self.pairs
    }

    /// Add a pair for `(local, remote)` if no pair with the same endpoints
    /// already exists. Returns the index of the new or existing pair, or `None`
    /// when the pair limit is reached.
    pub fn add_pair(&mut self, local: Candidate, remote: Candidate) -> Option<usize> {
        let endpoints = (local.addr, remote.addr);
        if let Some(&idx) = self.index.get(&endpoints) {
            return Some(idx);
        }
        if self.pairs.len() >= self.max_pairs {
            return None;
        }
        self.pairs
            .push(CandidatePair::new(local, remote, self.role));
        let idx = self.pairs.len() - 1;
        self.index.insert(endpoints, idx);
        Some(idx)
    }

    /// Find the index of a pair by its `(local.addr, remote.addr)` endpoints.
    #[must_use]
    pub fn find(&self, local: SocketAddr, remote: SocketAddr) -> Option<usize> {
        self.index.get(&(local, remote)).copied()
    }

    /// Perform initial foundation-based unfreezing (RFC 8445 §6.1.2.6).
    ///
    /// For each distinct combined foundation, the highest-priority pair is set
    /// to [`PairState::Waiting`]; all other pairs stay [`PairState::Frozen`].
    pub fn unfreeze_initial(&mut self) {
        let mut seen: HashSet<String> = self
            .pairs
            .iter()
            .filter(|p| p.state != PairState::Frozen)
            .map(|p| p.foundation().to_owned())
            .collect();
        let mut order: Vec<usize> = (0..self.pairs.len())
            .filter(|&idx| self.pairs[idx].state == PairState::Frozen)
            .collect();
        order.sort_by(|&a, &b| self.pairs[b].priority.cmp(&self.pairs[a].priority));
        for idx in order {
            if seen.insert(self.pairs[idx].foundation().to_owned()) {
                self.transition(idx, PairState::Waiting);
            }
        }
    }

    /// Queue a triggered check for the pair at `idx` (RFC 8445 §7.3.1.4).
    ///
    /// A [`PairState::Frozen`], [`PairState::Failed`], or
    /// [`PairState::InProgress`] pair is reset to [`PairState::Waiting`] so it
    /// can be checked again; a succeeded pair is left alone.
    pub fn enqueue_triggered(&mut self, idx: usize) {
        let Some(pair) = self.pairs.get(idx) else {
            return;
        };
        if pair.state == PairState::Succeeded {
            return;
        }
        self.transition(idx, PairState::Waiting);
        if !self.triggered.contains(&idx) {
            self.triggered.push_back(idx);
        }
    }

    /// Select the next pair to check and mark it [`PairState::InProgress`].
    ///
    /// Triggered checks take priority over ordinary checks. An ordinary check
    /// is the highest-priority [`PairState::Waiting`] pair whose foundation has
    /// no in-progress pair (foundation freezing). Pairs for which `ready`
    /// returns `false` are skipped for now. Returns the chosen index.
    pub fn next_check(&mut self, ready: impl Fn(&CandidatePair) -> bool) -> Option<usize> {
        let mut deferred = Vec::new();
        let mut chosen = None;
        while let Some(idx) = self.triggered.pop_front() {
            let Some(pair) = self.pairs.get(idx) else {
                continue;
            };
            if pair.state != PairState::Waiting {
                continue;
            }
            if ready(pair) {
                chosen = Some(idx);
                break;
            }
            deferred.push(idx);
        }
        for idx in deferred.into_iter().rev() {
            self.triggered.push_front(idx);
        }
        if chosen.is_none() {
            for (idx, pair) in self.pairs.iter().enumerate() {
                if pair.state != PairState::Waiting
                    || self.in_progress.contains_key(pair.foundation())
                    || !ready(pair)
                {
                    continue;
                }
                match chosen {
                    Some(best) if self.pairs[best].priority >= pair.priority => {}
                    _ => chosen = Some(idx),
                }
            }
        }
        if let Some(idx) = chosen {
            self.transition(idx, PairState::InProgress);
            self.pairs[idx].attempts += 1;
        }
        chosen
    }

    /// Mark a pair succeeded and unfreeze pairs sharing its foundation
    /// (RFC 8445 §7.2.5.3.3).
    pub fn on_success(&mut self, idx: usize) {
        if idx >= self.pairs.len() {
            return;
        }
        self.transition(idx, PairState::Succeeded);
        let foundation = self.pairs[idx].foundation().to_owned();
        for other in 0..self.pairs.len() {
            if self.pairs[other].state == PairState::Frozen
                && self.pairs[other].foundation() == foundation
            {
                self.transition(other, PairState::Waiting);
            }
        }
    }

    #[allow(missing_docs)]
    pub fn mark_valid(&mut self, idx: usize) {
        self.on_success(idx);
        if let Some(pair) = self.pairs.get_mut(idx) {
            pair.valid = true;
        }
    }

    #[allow(missing_docs)]
    pub fn set_valid_pair(&mut self, idx: usize, valid: usize) {
        if let Some(pair) = self.pairs.get_mut(idx) {
            pair.valid_pair = Some(valid);
        }
    }

    #[allow(missing_docs)]
    pub fn set_nominated(&mut self, idx: usize) {
        if let Some(pair) = self.pairs.get_mut(idx) {
            pair.nominated = true;
        }
    }

    /// Mark a pair failed and, if no live pair of its foundation remains,
    /// promote the highest-priority frozen pair of that foundation to Waiting.
    pub fn on_failure(&mut self, idx: usize) {
        if idx >= self.pairs.len() {
            return;
        }
        self.transition(idx, PairState::Failed);
        if let Some(pair) = self.pairs.get_mut(idx) {
            pair.valid = false;
        }
        let foundation = self.pairs[idx].foundation().to_owned();
        let live = self.pairs.iter().any(|p| {
            p.foundation() == foundation
                && matches!(p.state, PairState::Waiting | PairState::InProgress)
        });
        if live {
            return;
        }
        let next = (0..self.pairs.len())
            .filter(|&i| {
                self.pairs[i].state == PairState::Frozen && self.pairs[i].foundation() == foundation
            })
            .max_by_key(|&i| self.pairs[i].priority);
        if let Some(i) = next {
            self.transition(i, PairState::Waiting);
        }
    }

    /// The highest-priority valid pair, if any.
    #[must_use]
    pub fn best_succeeded(&self) -> Option<usize> {
        (0..self.pairs.len())
            .filter(|&i| self.pairs[i].valid && self.pairs[i].state == PairState::Succeeded)
            .max_by_key(|&i| self.pairs[i].priority)
    }

    /// The index of the nominated, succeeded pair, if one exists.
    #[must_use]
    pub fn nominated(&self) -> Option<usize> {
        self.pairs
            .iter()
            .position(|p| p.nominated && p.state == PairState::Succeeded)
    }

    /// Returns `true` if every pair has reached a terminal state.
    #[must_use]
    pub fn all_terminal(&self) -> bool {
        !self.pairs.is_empty() && self.pairs.iter().all(|p| p.state.is_terminal())
    }

    #[allow(missing_docs)]
    #[must_use]
    pub fn all_failed(&self) -> bool {
        self.pairs.iter().all(|p| p.state == PairState::Failed)
    }

    /// The number of pairs currently in `state`.
    #[must_use]
    pub fn count(&self, state: PairState) -> usize {
        self.pairs.iter().filter(|p| p.state == state).count()
    }

    fn transition(&mut self, idx: usize, state: PairState) {
        let old = self.pairs[idx].state;
        if old == state {
            return;
        }
        if old == PairState::InProgress {
            let foundation = self.pairs[idx].foundation();
            if let Some(count) = self.in_progress.get_mut(foundation) {
                *count -= 1;
                if *count == 0 {
                    self.in_progress.remove(foundation);
                }
            }
        }
        if state == PairState::InProgress {
            *self
                .in_progress
                .entry(self.pairs[idx].foundation().to_owned())
                .or_insert(0) += 1;
        }
        self.pairs[idx].state = state;
    }
}
