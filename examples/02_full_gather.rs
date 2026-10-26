//! Full gathering (host + server-reflexive) against an in-process STUN server
//! on `127.0.0.1`, so no network access is needed.
//!
//! Run with: `cargo run --example 02_full_gather`

use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use ice::sdp;
use ice::{IceAgent, IceConfig, IceRole};
use stun::{Attribute, Class, Message, Method};

fn serve(socket: &UdpSocket, mapped: SocketAddr) {
    let mut buf = [0u8; 1500];
    while let Ok((n, from)) = socket.recv_from(&mut buf) {
        let Ok(request) = Message::decode(&buf[..n]) else {
            continue;
        };
        if request.method() != Method::Binding || request.class() != Class::Request {
            continue;
        }
        println!("STUN server: Binding request from {from}");
        if let Ok(response) = Message::builder(Method::Binding, Class::SuccessResponse)
            .transaction_id(*request.transaction_id())
            .attribute(Attribute::XorMappedAddress(mapped))
            .with_fingerprint()
            .build_and_encode()
        {
            let _ = socket.send_to(&response, from);
        }
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let server = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))?;
    let port = server.local_addr()?.port();
    let pretend_nat_mapping: SocketAddr = "203.0.113.20:40000".parse()?;
    thread::spawn(move || serve(&server, pretend_nat_mapping));

    let mut config = IceConfig::new(
        IceRole::Controlling,
        "localUfrag",
        "localPasswordValueAtLeast22",
        "remoteUfrag",
        "remotePasswordValueAtLeast22",
    );
    config.bind_addr = Some(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)));
    config
        .stun_servers
        .push(stun::Endpoint::new("127.0.0.1", port));

    let agent = IceAgent::new(config)?;
    let (tx, rx) = mpsc::channel();
    agent.on_local_candidate(move |c| {
        let _ = tx.send(c);
    });

    println!("Agent socket: {}\n", agent.local_addr()?);
    agent.start_gathering()?;
    agent.wait_for_gathering(Duration::from_secs(5))?;

    while let Ok(c) = rx.recv_timeout(Duration::from_millis(100)) {
        println!("  [{:?}] {}", c.typ, sdp::to_sdp(&c));
    }
    Ok(())
}
