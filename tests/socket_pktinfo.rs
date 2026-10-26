use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::time::Duration;

use ice::SharedSocket;

fn exchange(local: IpAddr) {
    let socket = SharedSocket::bind(SocketAddr::new(local, 0)).unwrap();
    socket.set_read_timeout(Duration::from_secs(2)).unwrap();
    let peer = UdpSocket::bind(SocketAddr::new(local, 0)).unwrap();
    peer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();

    peer.send_to(b"ping", socket.local_addr().unwrap()).unwrap();
    let mut buf = [0u8; 64];
    let received = socket.recv_with_destination(&mut buf).unwrap();
    assert_eq!(&buf[..received.len], b"ping");
    assert_eq!(received.from, peer.local_addr().unwrap());
    assert_eq!(received.to, Some(local));

    socket
        .send_from(b"pong", local, peer.local_addr().unwrap())
        .unwrap();
    let (n, from) = peer.recv_from(&mut buf).unwrap();
    assert_eq!(&buf[..n], b"pong");
    assert_eq!(from, socket.local_addr().unwrap());
}

#[test]
fn ipv4_destination_and_source_addresses() {
    exchange(IpAddr::V4(Ipv4Addr::LOCALHOST));
}

#[test]
fn ipv6_destination_and_source_addresses() {
    exchange(IpAddr::V6(Ipv6Addr::LOCALHOST));
}

#[test]
fn oversized_datagrams_are_reported_as_truncated() {
    let socket = SharedSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).unwrap();
    socket.set_read_timeout(Duration::from_secs(2)).unwrap();
    let peer = UdpSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).unwrap();
    peer.send_to(&[7u8; 100], socket.local_addr().unwrap())
        .unwrap();
    let mut small = [0u8; 10];
    let error = socket.recv_with_destination(&mut small).unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
}
