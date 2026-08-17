use dmesh_server::protocol::{decode_get, encode_get};
use quic_lite::{
    ConnectionId, ConnectionIds, ConnectionLimits, EndpointState, FIRST_CLIENT_BIDI_STREAM_ID,
    INITIAL_MAX_STREAM_DATA, Role,
};

#[test]
fn object_get_crosses_transport_stream_boundary() {
    let mut get = [0u8; 64];
    let get_len = encode_get(&mut get, Some(b"main"), 13, 6).unwrap();

    let dcid = ConnectionId::new(1).unwrap();
    let mut sender = EndpointState::<2>::new_established(
        Role::Client,
        ConnectionLimits::default(),
        1200,
        ConnectionIds::new(ConnectionId::new(2).unwrap(), dcid).unwrap(),
    );
    sender
        .open_send_stream(FIRST_CLIENT_BIDI_STREAM_ID, INITIAL_MAX_STREAM_DATA)
        .unwrap();
    let mut packet = [0u8; 256];
    let (packet_len, _) = sender
        .encode_stream_packet(
            dcid,
            FIRST_CLIENT_BIDI_STREAM_ID,
            0,
            true,
            &get[..get_len],
            &mut packet,
        )
        .unwrap();

    let mut receiver = EndpointState::<2>::new_established(
        Role::Server,
        ConnectionLimits::default(),
        1200,
        ConnectionIds::new(dcid, ConnectionId::new(2).unwrap()).unwrap(),
    );
    let quic_lite::TransportPacket::Stream { frame: stream, .. } =
        receiver.receive_datagram(&packet[..packet_len]).unwrap()
    else {
        panic!("expected stream");
    };
    let request = decode_get(stream.data).unwrap();
    assert_eq!(request.name, Some(&b"main"[..]));
    assert_eq!(request.cpu, 13);
    assert_eq!(request.target, 6);

    receiver
        .stream_consumed(stream.id, stream.data.len())
        .unwrap();
    let mut control = [0u8; 128];
    let control_len = receiver.poll_transmit(&mut control).unwrap().unwrap();
    assert!(control_len > 0);
}
