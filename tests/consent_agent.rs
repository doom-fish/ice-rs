mod common;

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use common::{
    agent_config, bound_socket, is_check_from_agent, success, wait_until, ManualClock, Scripted,
    PEER_PWD,
};
use ice::{Error, IceAgent, IceRole};

struct Setup {
    agent: IceAgent,
    clock: Arc<ManualClock>,
    alive: Arc<AtomicBool>,
    answered: Arc<AtomicUsize>,
    failed: mpsc::Receiver<()>,
    _peer: Scripted,
}

fn selected(delay_after: usize, delay: Duration) -> Setup {
    let alive = Arc::new(AtomicBool::new(true));
    let answered = Arc::new(AtomicUsize::new(0));
    let (peer_alive, peer_answered) = (Arc::clone(&alive), Arc::clone(&answered));
    let peer = Scripted::spawn(bound_socket(), move |socket, message, from| {
        if !is_check_from_agent(message) || !peer_alive.load(Ordering::SeqCst) {
            return;
        }
        if peer_answered.fetch_add(1, Ordering::SeqCst) >= delay_after {
            thread::sleep(delay);
        }
        socket
            .send_to(&success(message, from, PEER_PWD), from)
            .unwrap();
    });
    let clock = ManualClock::new();
    let mut config = agent_config(IceRole::Controlling);
    config.clock = clock.clone();
    let agent = IceAgent::new(config).unwrap();
    let (tx, failed) = mpsc::channel();
    agent.on_connection_failed(move || {
        let _ = tx.send(());
    });
    agent.add_remote_candidate(peer.candidate()).unwrap();
    agent.start_gathering().unwrap();
    agent
        .wait_for_selected_pair(Duration::from_secs(5))
        .unwrap();
    Setup {
        agent,
        clock,
        alive,
        answered,
        failed,
        _peer: peer,
    }
}

#[test]
fn consent_is_kept_while_the_peer_answers_and_expires_when_it_stops() {
    let setup = selected(usize::MAX, Duration::ZERO);
    setup.agent.send_on_selected(&[23, 0]).unwrap();

    for _ in 0..8 {
        let before = setup.answered.load(Ordering::SeqCst);
        setup.clock.advance(Duration::from_secs(6));
        assert!(wait_until(Duration::from_secs(2), || {
            setup.answered.load(Ordering::SeqCst) > before
        }));
    }
    setup.agent.send_on_selected(&[23, 1]).unwrap();
    assert!(setup.failed.try_recv().is_err());

    setup.alive.store(false, Ordering::SeqCst);
    setup.clock.advance(Duration::from_secs(31));
    setup
        .failed
        .recv_timeout(Duration::from_secs(2))
        .expect("consent loss fires the failure callback");
    assert!(matches!(
        setup.agent.send_on_selected(&[23, 2]),
        Err(Error::ConsentExpired)
    ));

    setup.alive.store(true, Ordering::SeqCst);
    setup.clock.advance(Duration::from_secs(6));
    thread::sleep(Duration::from_millis(300));
    assert!(matches!(
        setup.agent.send_on_selected(&[23, 3]),
        Err(Error::ConsentExpired)
    ));
}

#[test]
fn late_consent_responses_still_count() {
    let setup = selected(2, Duration::from_millis(900));
    let before = setup.answered.load(Ordering::SeqCst);
    setup.clock.advance(Duration::from_secs(6));
    assert!(wait_until(Duration::from_secs(3), || {
        setup.answered.load(Ordering::SeqCst) > before
    }));
    thread::sleep(Duration::from_millis(1200));
    setup.alive.store(false, Ordering::SeqCst);

    setup.clock.advance(Duration::from_secs(26));
    thread::sleep(Duration::from_millis(200));
    setup.agent.send_on_selected(&[23, 4]).unwrap();
    assert!(setup.failed.try_recv().is_err());

    setup.clock.advance(Duration::from_secs(10));
    setup
        .failed
        .recv_timeout(Duration::from_secs(2))
        .expect("consent expires once responses stop");
    assert!(matches!(
        setup.agent.send_on_selected(&[23, 5]),
        Err(Error::ConsentExpired)
    ));
}

#[test]
fn nothing_is_sent_before_a_pair_is_selected() {
    let agent = IceAgent::new(agent_config(IceRole::Controlling)).unwrap();
    assert!(matches!(
        agent.send_on_selected(&[23, 0]),
        Err(Error::NoSelectedPair)
    ));
}
