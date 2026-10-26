use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};

use crate::socket::SharedSocket;

const INBOX_CAPACITY: usize = 64;

#[derive(Default)]
struct InboxState {
    frames: VecDeque<Vec<u8>>,
    closed: bool,
}

#[derive(Default)]
pub(crate) struct RelayInbox {
    state: Mutex<InboxState>,
    ready: Condvar,
}

impl RelayInbox {
    fn lock(&self) -> MutexGuard<'_, InboxState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    pub(crate) fn push(&self, frame: Vec<u8>) {
        let mut state = self.lock();
        if state.closed {
            return;
        }
        if state.frames.len() >= INBOX_CAPACITY {
            state.frames.pop_front();
        }
        state.frames.push_back(frame);
        drop(state);
        self.ready.notify_all();
    }

    pub(crate) fn close(&self) {
        self.lock().closed = true;
        self.ready.notify_all();
    }

    fn pop(&self) -> Option<Vec<u8>> {
        let mut state = self.lock();
        loop {
            if state.closed {
                return None;
            }
            if let Some(frame) = state.frames.pop_front() {
                return Some(frame);
            }
            state = self
                .ready
                .wait(state)
                .unwrap_or_else(PoisonError::into_inner);
        }
    }
}

pub(crate) struct RelayTransport {
    pub(crate) socket: SharedSocket,
    pub(crate) server: SocketAddr,
    pub(crate) inbox: Arc<RelayInbox>,
}

impl turn::Transport for RelayTransport {
    fn send(&self, data: &[u8]) -> turn::Result<()> {
        self.socket
            .send_to(data, self.server)
            .map(drop)
            .map_err(|e| turn::Error::Network(e.to_string()))
    }

    fn receive(&self) -> turn::Result<Vec<u8>> {
        self.inbox
            .pop()
            .ok_or_else(|| turn::Error::Network("relay transport closed".to_owned()))
    }

    fn close(&self) {
        self.inbox.close();
    }

    fn is_stream(&self) -> bool {
        false
    }
}
