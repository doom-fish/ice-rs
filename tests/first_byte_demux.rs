//! First-byte demultiplexing of incoming datagrams (RFC 5764 §5.1.2).

use ice::packet::{classify, is_stun, PacketKind};

#[test]
fn stun_range() {
    assert_eq!(classify(&[0x00]), PacketKind::Stun);
    assert_eq!(classify(&[0x13]), PacketKind::Stun);
    assert!(is_stun(&[0x00, 0x01, 0x00, 0x00]));
}

#[test]
fn dtls_range() {
    assert_eq!(classify(&[20]), PacketKind::Dtls);
    assert_eq!(classify(&[63]), PacketKind::Dtls);
    assert!(!is_stun(&[22]));
}

#[test]
fn channel_data_range() {
    assert_eq!(classify(&[64]), PacketKind::ChannelData);
    assert_eq!(classify(&[79]), PacketKind::ChannelData);
}

#[test]
fn srtp_range() {
    assert_eq!(classify(&[128]), PacketKind::Srtp);
    assert_eq!(classify(&[191]), PacketKind::Srtp);
}

#[test]
fn other_and_empty() {
    assert_eq!(classify(&[80]), PacketKind::Other);
    assert_eq!(classify(&[255]), PacketKind::Other);
    assert_eq!(classify(&[]), PacketKind::Other);
    assert!(!is_stun(&[]));
}
