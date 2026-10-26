//! Two in-process ICE agents complete a connectivity check and nominate a pair
//! over the loopback interface — no network required.
//!
//! Run with: `cargo run --example 03_loopback_pair`

use std::sync::mpsc;
use std::time::Duration;

use ice::{IceAgent, IceConfig, IceRole};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let loopback = "127.0.0.1:0".parse().unwrap();

    // Controlling agent.
    let mut cfg_a = IceConfig::new(
        IceRole::Controlling,
        "ufragAAAA",
        "passwordAAAAAAAAAAAAAA",
        "ufragBBBB",
        "passwordBBBBBBBBBBBBBB",
    );
    cfg_a.bind_addr = Some(loopback);

    // Controlled agent: mirror of the credentials.
    let mut cfg_b = IceConfig::new(
        IceRole::Controlled,
        "ufragBBBB",
        "passwordBBBBBBBBBBBBBB",
        "ufragAAAA",
        "passwordAAAAAAAAAAAAAA",
    );
    cfg_b.bind_addr = Some(loopback);

    let agent_a = IceAgent::new(cfg_a)?;
    let agent_b = IceAgent::new(cfg_b)?;

    let (tx_a, rx_a) = mpsc::channel();
    agent_a.on_local_candidate(move |c| {
        let _ = tx_a.send(c);
    });
    let (tx_b, rx_b) = mpsc::channel();
    agent_b.on_local_candidate(move |c| {
        let _ = tx_b.send(c);
    });

    agent_a.start_gathering()?;
    agent_b.start_gathering()?;

    // Exchange host candidates as signaling would.
    for c in rx_a.try_iter() {
        println!("A gathered {}", c.addr);
        agent_b.add_remote_candidate(c)?;
    }
    for c in rx_b.try_iter() {
        println!("B gathered {}", c.addr);
        agent_a.add_remote_candidate(c)?;
    }
    agent_a.end_of_candidates();
    agent_b.end_of_candidates();
    agent_a.remote_end_of_candidates();
    agent_b.remote_end_of_candidates();

    let (la, ra) = agent_a.wait_for_selected_pair(Duration::from_secs(5))?;
    let (lb, rb) = agent_b.wait_for_selected_pair(Duration::from_secs(5))?;

    println!("\nController A selected pair: {} -> {}", la.addr, ra.addr);
    println!("Controlled B selected pair: {} -> {}", lb.addr, rb.addr);

    // Send an application datagram over the negotiated path.
    agent_a.send_on_selected(b"hello over the nominated pair")?;
    println!("\nLoopback ICE negotiation succeeded.");
    Ok(())
}
