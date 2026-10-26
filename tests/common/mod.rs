#![allow(dead_code)]

use std::collections::HashSet;
use std::io::ErrorKind;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use ice::{Candidate, Clock, ComponentId, IceConfig, IceRole, PacketKind, PacketSink};
use stun::attribute::types;
use stun::auth::short_term_key;
use stun::{Attribute, Class, ErrorCode, Message, Method, TransactionId};

pub const AGENT_UFRAG: &str = "agentUfrag";
pub const AGENT_PWD: &str = "agentPasswordValue123456";
pub const PEER_UFRAG: &str = "peerUfrag";
pub const PEER_PWD: &str = "peerPasswordValue1234567";

pub const TURN_USER: &str = "relay-user";
pub const TURN_PASSWORD: &str = "relay-password";
pub const TURN_REALM: &str = "relay.test";
pub const TURN_NONCE: &str = "relay-nonce";

pub fn loopback() -> SocketAddr {
    SocketAddr::from((Ipv4Addr::LOCALHOST, 0))
}

pub fn agent_config(role: IceRole) -> IceConfig {
    let mut config = IceConfig::new(role, AGENT_UFRAG, AGENT_PWD, PEER_UFRAG, PEER_PWD);
    config.bind_addr = Some(loopback());
    config
}

pub fn peer_config(role: IceRole) -> IceConfig {
    let mut config = IceConfig::new(role, PEER_UFRAG, PEER_PWD, AGENT_UFRAG, AGENT_PWD);
    config.bind_addr = Some(loopback());
    config
}

pub fn wait_until(timeout: Duration, mut condition: impl FnMut() -> bool) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if condition() {
            return true;
        }
        thread::sleep(Duration::from_millis(5));
    }
    condition()
}

#[derive(Debug, Default)]
pub struct ManualClock {
    offset: Mutex<Duration>,
}

impl ManualClock {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    pub fn advance(&self, by: Duration) {
        *self.offset.lock().unwrap() += by;
    }
}

impl Clock for ManualClock {
    fn now(&self) -> Instant {
        Instant::now() + *self.offset.lock().unwrap()
    }
}

pub type Delivered = (PacketKind, Vec<u8>, SocketAddr);

pub struct ChannelSink(Mutex<mpsc::Sender<Delivered>>);

impl PacketSink for ChannelSink {
    fn on_packet(&self, kind: PacketKind, bytes: &[u8], from: SocketAddr) {
        let _ = self.0.lock().unwrap().send((kind, bytes.to_vec(), from));
    }
}

pub fn channel_sink() -> (Arc<ChannelSink>, Receiver<Delivered>) {
    let (tx, rx) = mpsc::channel();
    (Arc::new(ChannelSink(Mutex::new(tx))), rx)
}

pub fn bound_socket() -> UdpSocket {
    let socket = UdpSocket::bind(loopback()).unwrap();
    socket
        .set_read_timeout(Some(Duration::from_millis(20)))
        .unwrap();
    socket
}

pub fn recv_stun(socket: &UdpSocket, timeout: Duration) -> Option<(Message, SocketAddr)> {
    let deadline = Instant::now() + timeout;
    let mut buf = [0u8; 2048];
    while Instant::now() < deadline {
        match socket.recv_from(&mut buf) {
            Ok((n, from)) => {
                if let Ok(message) = Message::decode(&buf[..n]) {
                    return Some((message, from));
                }
            }
            Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {}
            Err(e) => panic!("receive failed: {e}"),
        }
    }
    None
}

pub fn host(addr: SocketAddr) -> Candidate {
    Candidate::host(addr, ComponentId::RTP)
}

pub fn success(request: &Message, mapped: SocketAddr, pwd: &str) -> Vec<u8> {
    Message::builder(Method::Binding, Class::SuccessResponse)
        .transaction_id(*request.transaction_id())
        .attribute(Attribute::XorMappedAddress(mapped))
        .with_message_integrity_sha1(&short_term_key(pwd))
        .with_fingerprint()
        .build_and_encode()
        .unwrap()
}

pub fn error(request: &Message, code: u16, key: Option<&str>) -> Vec<u8> {
    let mut builder = Message::builder(Method::Binding, Class::ErrorResponse)
        .transaction_id(*request.transaction_id())
        .attribute(Attribute::ErrorCode(ErrorCode::new(code, "Error")));
    if let Some(pwd) = key {
        builder = builder.with_message_integrity_sha1(&short_term_key(pwd));
    }
    builder.with_fingerprint().build_and_encode().unwrap()
}

pub struct CheckOptions {
    pub use_candidate: bool,
    pub role: Attribute,
    pub pwd: &'static str,
    pub extra: Vec<Attribute>,
    pub sha256: bool,
}

impl Default for CheckOptions {
    fn default() -> Self {
        Self {
            use_candidate: false,
            role: Attribute::IceControlled(1),
            pwd: AGENT_PWD,
            extra: Vec::new(),
            sha256: false,
        }
    }
}

pub fn check_to_agent(options: CheckOptions) -> (TransactionId, Vec<u8>) {
    let tid = TransactionId::try_random().unwrap();
    let mut builder = Message::builder(Method::Binding, Class::Request)
        .transaction_id(tid)
        .attribute(Attribute::Username(format!("{AGENT_UFRAG}:{PEER_UFRAG}")))
        .attribute(Attribute::Priority(0x6E00_01FF))
        .attribute(options.role);
    if options.use_candidate {
        builder = builder.attribute(Attribute::UseCandidate);
    }
    for attribute in options.extra {
        builder = builder.attribute(attribute);
    }
    let key = short_term_key(options.pwd);
    builder = if options.sha256 {
        builder.with_message_integrity_sha256(&key)
    } else {
        builder.with_message_integrity_sha1(&key)
    };
    (tid, builder.with_fingerprint().build_and_encode().unwrap())
}

pub fn is_check_from_agent(message: &Message) -> bool {
    message.method() == Method::Binding
        && message.class() == Class::Request
        && matches!(message.get(types::USERNAME), Some(Attribute::Username(u)) if *u == format!("{PEER_UFRAG}:{AGENT_UFRAG}"))
        && message
            .verify_message_integrity(&short_term_key(PEER_PWD))
            .is_ok()
}

pub struct Scripted {
    pub addr: SocketAddr,
    stop: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

impl Scripted {
    pub fn spawn(
        socket: UdpSocket,
        mut handler: impl FnMut(&UdpSocket, &Message, SocketAddr) + Send + 'static,
    ) -> Self {
        let addr = socket.local_addr().unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&stop);
        let handle = thread::spawn(move || {
            while !flag.load(Ordering::SeqCst) {
                if let Some((message, from)) = recv_stun(&socket, Duration::from_millis(50)) {
                    handler(&socket, &message, from);
                }
            }
        });
        Self {
            addr,
            stop,
            handle: Some(handle),
        }
    }

    pub fn candidate(&self) -> Candidate {
        host(self.addr)
    }
}

impl Drop for Scripted {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

pub fn answering_peer() -> Scripted {
    Scripted::spawn(bound_socket(), |socket, message, from| {
        if is_check_from_agent(message) {
            socket
                .send_to(&success(message, from, PEER_PWD), from)
                .unwrap();
        }
    })
}

pub struct StunServer {
    pub server: Scripted,
    pub sources: Arc<Mutex<Vec<SocketAddr>>>,
}

pub fn stun_server(mapped: Option<SocketAddr>) -> StunServer {
    let sources = Arc::new(Mutex::new(Vec::new()));
    let log = Arc::clone(&sources);
    let server = Scripted::spawn(bound_socket(), move |socket, message, from| {
        if message.method() != Method::Binding || message.class() != Class::Request {
            return;
        }
        log.lock().unwrap().push(from);
        let response = Message::builder(Method::Binding, Class::SuccessResponse)
            .transaction_id(*message.transaction_id())
            .attribute(Attribute::XorMappedAddress(mapped.unwrap_or(from)))
            .with_fingerprint()
            .build_and_encode()
            .unwrap();
        socket.send_to(&response, from).unwrap();
    });
    StunServer { server, sources }
}

#[derive(Default)]
pub struct TurnState {
    pub client: Option<SocketAddr>,
    pub permissions: HashSet<IpAddr>,
    pub requests: Vec<(u16, Option<u32>)>,
    pub released: bool,
    pub refuse_permissions: bool,
    pub lifetime: u32,
    pub refresh_error: Option<u16>,
}

impl TurnState {
    pub fn count(&self, method: turn::Method) -> usize {
        self.requests
            .iter()
            .filter(|(code, _)| *code == method.as_u16())
            .count()
    }
}

pub struct FakeTurn {
    pub addr: SocketAddr,
    pub relay_addr: SocketAddr,
    pub state: Arc<Mutex<TurnState>>,
    stop: Arc<AtomicBool>,
    handles: Vec<JoinHandle<()>>,
}

fn turn_key() -> Vec<u8> {
    stun::auth::long_term_key(TURN_USER, TURN_REALM, TURN_PASSWORD).to_vec()
}

fn turn_error(request: &Message, code: u16) -> Vec<u8> {
    Message::builder(request.method(), Class::ErrorResponse)
        .transaction_id(*request.transaction_id())
        .attribute(Attribute::ErrorCode(ErrorCode::new(code, "Refused")))
        .with_message_integrity_sha1(&turn_key())
        .with_fingerprint()
        .build_and_encode()
        .unwrap()
}

fn turn_response(request: &Message, attributes: Vec<Attribute>) -> Vec<u8> {
    let mut builder = Message::builder(request.method(), Class::SuccessResponse)
        .transaction_id(*request.transaction_id());
    for attribute in attributes {
        builder = builder.attribute(attribute);
    }
    builder
        .with_message_integrity_sha1(&turn_key())
        .with_fingerprint()
        .build_and_encode()
        .unwrap()
}

fn handle_turn(
    control: &UdpSocket,
    relay: &UdpSocket,
    relay_addr: SocketAddr,
    state: &Mutex<TurnState>,
    message: &Message,
    from: SocketAddr,
) {
    let xor = turn::attribute::xor_key(message.transaction_id().as_bytes());
    let turn_attributes: Vec<turn::Attribute> = message
        .attributes()
        .iter()
        .filter_map(|a| turn::Attribute::from_stun(a, &xor).ok().flatten())
        .collect();
    if message.class() == Class::Indication && message.method() == turn::Method::Send.to_stun() {
        let peer = turn_attributes.iter().find_map(|a| match a {
            turn::Attribute::XorPeerAddress(p) => Some(*p),
            _ => None,
        });
        let data = turn_attributes.iter().find_map(|a| match a {
            turn::Attribute::Data(d) => Some(d.clone()),
            _ => None,
        });
        if let (Some(peer), Some(data)) = (peer, data) {
            if state.lock().unwrap().permissions.contains(&peer.ip()) {
                let _ = relay.send_to(&data, peer);
            }
        }
        return;
    }
    if message.class() != Class::Request {
        return;
    }
    let lifetime = turn_attributes.iter().find_map(|a| match a {
        turn::Attribute::Lifetime(l) => Some(*l),
        _ => None,
    });
    state
        .lock()
        .unwrap()
        .requests
        .push((message.method().as_u16(), lifetime));
    let authenticated = matches!(message.get(types::NONCE), Some(Attribute::Nonce(n)) if n == TURN_NONCE)
        && message.verify_message_integrity(&turn_key()).is_ok();
    if !authenticated {
        let challenge = Message::builder(message.method(), Class::ErrorResponse)
            .transaction_id(*message.transaction_id())
            .attribute(Attribute::ErrorCode(ErrorCode::new(401, "Unauthorized")))
            .attribute(Attribute::Realm(TURN_REALM.to_owned()))
            .attribute(Attribute::Nonce(TURN_NONCE.to_owned()))
            .build_and_encode()
            .unwrap();
        let _ = control.send_to(&challenge, from);
        return;
    }
    let method = message.method();
    let (refuse_permissions, granted, refresh_error) = {
        let guard = state.lock().unwrap();
        (
            guard.refuse_permissions,
            guard.lifetime,
            guard.refresh_error,
        )
    };
    let response = if method == turn::Method::Allocate.to_stun() {
        state.lock().unwrap().client = Some(from);
        turn_response(
            message,
            vec![
                turn::Attribute::XorRelayedAddress(relay_addr).to_stun(&xor),
                Attribute::XorMappedAddress(from),
                turn::Attribute::Lifetime(granted).to_stun(&xor),
            ],
        )
    } else if method == turn::Method::CreatePermission.to_stun() && refuse_permissions {
        turn_error(message, 403)
    } else if method == turn::Method::Refresh.to_stun() && refresh_error.is_some() {
        turn_error(message, refresh_error.unwrap_or(500))
    } else if method == turn::Method::CreatePermission.to_stun() {
        let mut guard = state.lock().unwrap();
        for attribute in &turn_attributes {
            if let turn::Attribute::XorPeerAddress(peer) = attribute {
                guard.permissions.insert(peer.ip());
            }
        }
        drop(guard);
        turn_response(message, Vec::new())
    } else if method == turn::Method::Refresh.to_stun() {
        if lifetime == Some(0) {
            state.lock().unwrap().released = true;
        }
        turn_response(
            message,
            vec![turn::Attribute::Lifetime(lifetime.unwrap_or(600)).to_stun(&xor)],
        )
    } else {
        turn_response(message, Vec::new())
    };
    let _ = control.send_to(&response, from);
}

impl FakeTurn {
    pub fn spawn() -> Self {
        Self::spawn_with(|_| {})
    }

    pub fn spawn_with(configure: impl FnOnce(&mut TurnState)) -> Self {
        let control = bound_socket();
        let relay = bound_socket();
        let addr = control.local_addr().unwrap();
        let relay_addr = relay.local_addr().unwrap();
        let mut initial = TurnState {
            lifetime: 600,
            ..TurnState::default()
        };
        configure(&mut initial);
        let state = Arc::new(Mutex::new(initial));
        let stop = Arc::new(AtomicBool::new(false));

        let control_thread = {
            let control = control.try_clone().unwrap();
            let relay = relay.try_clone().unwrap();
            let state = Arc::clone(&state);
            let stop = Arc::clone(&stop);
            thread::spawn(move || {
                while !stop.load(Ordering::SeqCst) {
                    if let Some((message, from)) = recv_stun(&control, Duration::from_millis(50)) {
                        handle_turn(&control, &relay, relay_addr, &state, &message, from);
                    }
                }
            })
        };
        let relay_thread = {
            let state = Arc::clone(&state);
            let stop = Arc::clone(&stop);
            thread::spawn(move || {
                let mut buf = [0u8; 2048];
                while !stop.load(Ordering::SeqCst) {
                    let (n, from) = match relay.recv_from(&mut buf) {
                        Ok(received) => received,
                        Err(e)
                            if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) =>
                        {
                            continue
                        }
                        Err(e) => panic!("relay receive failed: {e}"),
                    };
                    let guard = state.lock().unwrap();
                    let (Some(client), true) =
                        (guard.client, guard.permissions.contains(&from.ip()))
                    else {
                        continue;
                    };
                    drop(guard);
                    let tid = TransactionId::try_random().unwrap();
                    let xor = turn::attribute::xor_key(tid.as_bytes());
                    let indication =
                        Message::builder(turn::Method::Data.to_stun(), Class::Indication)
                            .transaction_id(tid)
                            .attribute(turn::Attribute::XorPeerAddress(from).to_stun(&xor))
                            .attribute(turn::Attribute::Data(buf[..n].to_vec()).to_stun(&xor))
                            .build_and_encode()
                            .unwrap();
                    let _ = control.send_to(&indication, client);
                }
            })
        };
        Self {
            addr,
            relay_addr,
            state,
            stop,
            handles: vec![control_thread, relay_thread],
        }
    }

    pub fn config(&self) -> ice::TurnServer {
        ice::TurnServer {
            uri: format!("turn:127.0.0.1:{}", self.addr.port())
                .parse()
                .unwrap(),
            credential: turn::Credential::long_term(TURN_USER, "", TURN_PASSWORD),
        }
    }
}

impl Drop for FakeTurn {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        for handle in self.handles.drain(..) {
            let _ = handle.join();
        }
    }
}
