#![cfg(feature = "tokio")]
#![deny(deprecated)]

//! External coverage for UDP bearer initialization and peer addressing.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6};

use quic_lite::bearer_udp::{
    HOST_UDP_SOCKET_BUFFER_BYTES, TokioUdpBearer, UdpBearerError, UdpSocketConfig, parse_peer,
    wildcard_bind,
};
use quic_lite::{BearerName, PacketBearer};

type TestPool = quic_lite::packet_pool::PacketPool<2, { quic_lite::DEFAULT_PACKET_POOL_SLOT_SIZE }>;

#[test]
fn endpoint_parser_and_wildcard_bind_preserve_address_family() {
    let defaults = UdpSocketConfig::default();
    assert_eq!(defaults.dscp, None);
    assert_eq!(
        defaults.receive_buffer_bytes,
        Some(HOST_UDP_SOCKET_BUFFER_BYTES)
    );
    assert_eq!(
        defaults.send_buffer_bytes,
        Some(HOST_UDP_SOCKET_BUFFER_BYTES)
    );

    assert_eq!(
        parse_peer("udp://192.0.2.1:4444", 3339).unwrap(),
        "192.0.2.1:4444".parse().unwrap()
    );
    assert_eq!(
        parse_peer("192.0.2.1", 3339).unwrap(),
        "192.0.2.1:3339".parse().unwrap()
    );
    assert_eq!(
        parse_peer("[2001:db8::1]", 3339).unwrap(),
        "[2001:db8::1]:3339".parse().unwrap()
    );
    assert_eq!(
        parse_peer("[fe80::1%7]:4444", 3339).unwrap(),
        SocketAddr::V6(SocketAddrV6::new("fe80::1".parse().unwrap(), 4444, 0, 7))
    );
    assert!(parse_peer("not an endpoint", 3339).is_err());

    assert_eq!(
        wildcard_bind("192.0.2.1:4444".parse().unwrap(), 12),
        SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 12)
    );
    assert_eq!(
        wildcard_bind("[2001:db8::1]:4444".parse().unwrap(), 13),
        SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 13)
    );
}

#[tokio::test]
async fn bearer_configuration_and_peer_table_use_only_public_contracts() {
    let config = UdpSocketConfig {
        dscp: Some(8),
        receive_buffer_bytes: None,
        send_buffer_bytes: None,
    };
    let mut bearer = TokioUdpBearer::<2>::bind_with_config("127.0.0.1:0".parse().unwrap(), config)
        .await
        .unwrap();
    assert_eq!(
        bearer.local_addr().unwrap(),
        bearer.socket().local_addr().unwrap()
    );

    bearer.set_name(BearerName::new("test-udp").unwrap());
    assert_eq!(
        <TokioUdpBearer<2> as PacketBearer<TestPool>>::info(&bearer)
            .name
            .as_str(),
        "test-udp"
    );

    let first: SocketAddr = "127.0.0.1:41001".parse().unwrap();
    let second: SocketAddr = "127.0.0.1:41002".parse().unwrap();
    let first_id = bearer.register_peer(first).unwrap();
    assert_eq!(bearer.register_peer(first).unwrap(), first_id);
    let second_id = bearer.register_peer(second).unwrap();
    assert_ne!(first_id, second_id);
    assert_eq!(bearer.peer(first_id), Some(first));
    assert_eq!(bearer.peer_l2_address(second), Some(second_id));
    assert_eq!(bearer.remove_peer(first_id), Some(first));
    assert_eq!(bearer.peer(first_id), None);

    assert!(matches!(
        TokioUdpBearer::<1>::bind("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap()
            .register_peer(first),
        Ok(_)
    ));
}

#[tokio::test]
async fn adopted_std_socket_and_configuration_validation_are_public() {
    let invalid = UdpSocketConfig {
        dscp: Some(64),
        receive_buffer_bytes: None,
        send_buffer_bytes: None,
    };
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    assert!(TokioUdpBearer::<1>::configure_existing(&socket, invalid).is_err());

    let std_socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let adopted = TokioUdpBearer::<1>::from_std_with_config(
        std_socket,
        UdpSocketConfig {
            dscp: None,
            receive_buffer_bytes: None,
            send_buffer_bytes: None,
        },
    )
    .unwrap();
    assert!(adopted.local_addr().unwrap().port() != 0);

    let std_socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    assert!(TokioUdpBearer::<1>::from_std(std_socket).is_ok());
}

#[tokio::test]
async fn fixed_peer_table_reports_capacity_exhaustion() {
    let bearer = TokioUdpBearer::<1>::bind("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    bearer
        .register_peer("127.0.0.1:42001".parse().unwrap())
        .unwrap();
    assert!(matches!(
        bearer.register_peer("127.0.0.1:42002".parse().unwrap()),
        Err(UdpBearerError::PeerTableFull)
    ));
}
