use std::cell::RefCell;
use std::sync::atomic::{AtomicU64, Ordering};

const HOT_COUNTER_FLUSH_PACKETS: u64 = 64;

#[derive(Default)]
pub struct MeshTunStats {
    pub control_capture_ok: AtomicU64,
    pub control_capture_err: AtomicU64,
    pub route_hit: AtomicU64,
    pub route_miss: AtomicU64,
    pub route_send_full: AtomicU64,
    pub tun_input_queue_full: AtomicU64,
    pub tun_output_queue_full: AtomicU64,
    pub fallback_queue_full: AtomicU64,
    pub egress_listener_start: AtomicU64,
    pub egress_accept: AtomicU64,
    pub egress_accept_error: AtomicU64,
    pub egress_connect_error: AtomicU64,
    pub egress_original_dst_error: AtomicU64,
    pub egress_bytes_to_upstream: AtomicU64,
    pub egress_bytes_to_guest: AtomicU64,
    pub tap_frame_rx: AtomicU64,
    pub tap_frame_rx_bytes: AtomicU64,
    pub tap_ip_rx: AtomicU64,
    pub tap_ip_rx_bytes: AtomicU64,
    pub arp_request_rx: AtomicU64,
    pub arp_reply_tx: AtomicU64,
    pub tap_inject_packet: AtomicU64,
    pub tap_inject_bytes: AtomicU64,
    pub tap_inject_error: AtomicU64,
    pub tap_inject_queue_full: AtomicU64,
    pub tap_inject_queue_rx: AtomicU64,
    pub tap_last_inject_dst_mac_hi: AtomicU64,
    pub tap_last_inject_dst_mac_lo: AtomicU64,
    pub tap_last_inject_src_mac_hi: AtomicU64,
    pub tap_last_inject_src_mac_lo: AtomicU64,
    pub tap_last_inject_ethertype: AtomicU64,
    pub tap_last_inject_len: AtomicU64,
    pub tap_last_inject_write_rc: AtomicU64,
    pub tap_last_inject_ipv4_src: AtomicU64,
    pub tap_last_inject_ipv4_dst: AtomicU64,
    pub tap_last_inject_tcp_flags: AtomicU64,
    pub tap_last_inject_ip_checksum_ok: AtomicU64,
    pub tap_last_inject_tcp_checksum_ok: AtomicU64,
    pub tcp_packet: AtomicU64,
    pub tcp_packet_payload_bytes: AtomicU64,
    pub tcp_syn: AtomicU64,
    pub tcp_inbound_syn_sent: AtomicU64,
    pub tcp_inbound_ack_sent: AtomicU64,
    pub tcp_inbound_open: AtomicU64,
    pub tcp_inbound_rejected: AtomicU64,
    pub tcp_flow_rejected: AtomicU64,
    pub tcp_flow_open: AtomicU64,
    pub tcp_flow_packet: AtomicU64,
    pub tcp_flow_queue_full: AtomicU64,
    pub tcp_backend_flow_control: AtomicU64,
    pub tcp_handshake_timeout: AtomicU64,
    pub tcp_payload_guest_to_host: AtomicU64,
    pub tcp_guest_write_calls: AtomicU64,
    pub tcp_payload_host_to_guest: AtomicU64,
    pub tcp_host_read_calls: AtomicU64,
    pub tcp_syn_ack_sent: AtomicU64,
    pub tcp_ack_after_syn: AtomicU64,
    pub tcp_handshake_skip: AtomicU64,
    pub tcp_last_handshake_flags: AtomicU64,
    pub tcp_last_handshake_seq: AtomicU64,
    pub tcp_last_handshake_ack: AtomicU64,
    pub tcp_last_handshake_expected_ack: AtomicU64,
    pub tcp_last_handshake_payload_len: AtomicU64,
    pub tcp_ack_sent: AtomicU64,
    pub tcp_data_sent: AtomicU64,
    pub tcp_fin_sent: AtomicU64,
    pub tcp_flow_close: AtomicU64,
    pub tcp_flow_error: AtomicU64,
    pub tcp_window_wait: AtomicU64,
    pub tcp_window_wake: AtomicU64,
    pub tcp_window_timeout: AtomicU64,
    pub tcp_last_send_seq: AtomicU64,
    pub tcp_last_send_end: AtomicU64,
    pub tcp_last_send_len: AtomicU64,
    pub tcp_last_acked: AtomicU64,
    pub tcp_last_in_flight: AtomicU64,
    pub tcp_last_ack_num: AtomicU64,
    pub tcp_last_ack_flags: AtomicU64,
    pub tcp_bulk_window_wait: AtomicU64,
    pub tcp_bulk_window_wake: AtomicU64,
    pub tcp_bulk_last_send_seq: AtomicU64,
    pub tcp_bulk_last_send_end: AtomicU64,
    pub tcp_bulk_last_send_len: AtomicU64,
    pub tcp_bulk_last_acked: AtomicU64,
    pub tcp_bulk_last_in_flight: AtomicU64,
    pub tcp_bulk_last_ack_num: AtomicU64,
    pub tcp_bulk_last_ack_flags: AtomicU64,
    pub tcp_bulk_max_in_flight: AtomicU64,
    pub tcp_bulk_window_wait_ns: AtomicU64,
    pub tcp_bulk_window_wait_slow: AtomicU64,
    pub tcp_bulk_backend_read_wait_ns: AtomicU64,
    pub tcp_bulk_backend_read_wait_slow: AtomicU64,
    pub tcp_bulk_output_send_wait_ns: AtomicU64,
    pub tcp_bulk_output_send_wait_slow: AtomicU64,
    pub tcp_bulk_output_send_wait_max_ns: AtomicU64,
    pub uds_broadcast_sent: AtomicU64,
    pub uds_broadcast_no_subscribers: AtomicU64,
    pub uds_client_lagged_frames: AtomicU64,
    pub uds_client_write_error: AtomicU64,
}

static STATS: MeshTunStats = MeshTunStats {
    control_capture_ok: AtomicU64::new(0),
    control_capture_err: AtomicU64::new(0),
    route_hit: AtomicU64::new(0),
    route_miss: AtomicU64::new(0),
    route_send_full: AtomicU64::new(0),
    tun_input_queue_full: AtomicU64::new(0),
    tun_output_queue_full: AtomicU64::new(0),
    fallback_queue_full: AtomicU64::new(0),
    egress_listener_start: AtomicU64::new(0),
    egress_accept: AtomicU64::new(0),
    egress_accept_error: AtomicU64::new(0),
    egress_connect_error: AtomicU64::new(0),
    egress_original_dst_error: AtomicU64::new(0),
    egress_bytes_to_upstream: AtomicU64::new(0),
    egress_bytes_to_guest: AtomicU64::new(0),
    tap_frame_rx: AtomicU64::new(0),
    tap_frame_rx_bytes: AtomicU64::new(0),
    tap_ip_rx: AtomicU64::new(0),
    tap_ip_rx_bytes: AtomicU64::new(0),
    arp_request_rx: AtomicU64::new(0),
    arp_reply_tx: AtomicU64::new(0),
    tap_inject_packet: AtomicU64::new(0),
    tap_inject_bytes: AtomicU64::new(0),
    tap_inject_error: AtomicU64::new(0),
    tap_inject_queue_full: AtomicU64::new(0),
    tap_inject_queue_rx: AtomicU64::new(0),
    tap_last_inject_dst_mac_hi: AtomicU64::new(0),
    tap_last_inject_dst_mac_lo: AtomicU64::new(0),
    tap_last_inject_src_mac_hi: AtomicU64::new(0),
    tap_last_inject_src_mac_lo: AtomicU64::new(0),
    tap_last_inject_ethertype: AtomicU64::new(0),
    tap_last_inject_len: AtomicU64::new(0),
    tap_last_inject_write_rc: AtomicU64::new(0),
    tap_last_inject_ipv4_src: AtomicU64::new(0),
    tap_last_inject_ipv4_dst: AtomicU64::new(0),
    tap_last_inject_tcp_flags: AtomicU64::new(0),
    tap_last_inject_ip_checksum_ok: AtomicU64::new(0),
    tap_last_inject_tcp_checksum_ok: AtomicU64::new(0),
    tcp_packet: AtomicU64::new(0),
    tcp_packet_payload_bytes: AtomicU64::new(0),
    tcp_syn: AtomicU64::new(0),
    tcp_inbound_syn_sent: AtomicU64::new(0),
    tcp_inbound_ack_sent: AtomicU64::new(0),
    tcp_inbound_open: AtomicU64::new(0),
    tcp_inbound_rejected: AtomicU64::new(0),
    tcp_flow_rejected: AtomicU64::new(0),
    tcp_flow_open: AtomicU64::new(0),
    tcp_flow_packet: AtomicU64::new(0),
    tcp_flow_queue_full: AtomicU64::new(0),
    tcp_backend_flow_control: AtomicU64::new(0),
    tcp_handshake_timeout: AtomicU64::new(0),
    tcp_payload_guest_to_host: AtomicU64::new(0),
    tcp_guest_write_calls: AtomicU64::new(0),
    tcp_payload_host_to_guest: AtomicU64::new(0),
    tcp_host_read_calls: AtomicU64::new(0),
    tcp_syn_ack_sent: AtomicU64::new(0),
    tcp_ack_after_syn: AtomicU64::new(0),
    tcp_handshake_skip: AtomicU64::new(0),
    tcp_last_handshake_flags: AtomicU64::new(0),
    tcp_last_handshake_seq: AtomicU64::new(0),
    tcp_last_handshake_ack: AtomicU64::new(0),
    tcp_last_handshake_expected_ack: AtomicU64::new(0),
    tcp_last_handshake_payload_len: AtomicU64::new(0),
    tcp_ack_sent: AtomicU64::new(0),
    tcp_data_sent: AtomicU64::new(0),
    tcp_fin_sent: AtomicU64::new(0),
    tcp_flow_close: AtomicU64::new(0),
    tcp_flow_error: AtomicU64::new(0),
    tcp_window_wait: AtomicU64::new(0),
    tcp_window_wake: AtomicU64::new(0),
    tcp_window_timeout: AtomicU64::new(0),
    tcp_last_send_seq: AtomicU64::new(0),
    tcp_last_send_end: AtomicU64::new(0),
    tcp_last_send_len: AtomicU64::new(0),
    tcp_last_acked: AtomicU64::new(0),
    tcp_last_in_flight: AtomicU64::new(0),
    tcp_last_ack_num: AtomicU64::new(0),
    tcp_last_ack_flags: AtomicU64::new(0),
    tcp_bulk_window_wait: AtomicU64::new(0),
    tcp_bulk_window_wake: AtomicU64::new(0),
    tcp_bulk_last_send_seq: AtomicU64::new(0),
    tcp_bulk_last_send_end: AtomicU64::new(0),
    tcp_bulk_last_send_len: AtomicU64::new(0),
    tcp_bulk_last_acked: AtomicU64::new(0),
    tcp_bulk_last_in_flight: AtomicU64::new(0),
    tcp_bulk_last_ack_num: AtomicU64::new(0),
    tcp_bulk_last_ack_flags: AtomicU64::new(0),
    tcp_bulk_max_in_flight: AtomicU64::new(0),
    tcp_bulk_window_wait_ns: AtomicU64::new(0),
    tcp_bulk_window_wait_slow: AtomicU64::new(0),
    tcp_bulk_backend_read_wait_ns: AtomicU64::new(0),
    tcp_bulk_backend_read_wait_slow: AtomicU64::new(0),
    tcp_bulk_output_send_wait_ns: AtomicU64::new(0),
    tcp_bulk_output_send_wait_slow: AtomicU64::new(0),
    tcp_bulk_output_send_wait_max_ns: AtomicU64::new(0),
    uds_broadcast_sent: AtomicU64::new(0),
    uds_broadcast_no_subscribers: AtomicU64::new(0),
    uds_client_lagged_frames: AtomicU64::new(0),
    uds_client_write_error: AtomicU64::new(0),
};

#[derive(Default)]
struct HotCounters {
    tap_frame_rx: u64,
    tap_frame_rx_bytes: u64,
    tap_ip_rx: u64,
    tap_ip_rx_bytes: u64,
    tap_inject_packet: u64,
    tap_inject_bytes: u64,
    tap_inject_seen: u64,
    tcp_packet: u64,
    tcp_packet_payload_bytes: u64,
    tcp_flow_packet: u64,
    tcp_payload_guest_to_host: u64,
    tcp_payload_host_to_guest: u64,
    tcp_ack_sent: u64,
    tcp_data_sent: u64,
    pending_events: u64,
}

impl HotCounters {
    fn add_event(&mut self) {
        self.pending_events += 1;
        if self.pending_events >= HOT_COUNTER_FLUSH_PACKETS {
            self.flush();
        }
    }

    fn flush(&mut self) {
        let stats = stats();
        flush_one(&stats.tap_frame_rx, &mut self.tap_frame_rx);
        flush_one(&stats.tap_frame_rx_bytes, &mut self.tap_frame_rx_bytes);
        flush_one(&stats.tap_ip_rx, &mut self.tap_ip_rx);
        flush_one(&stats.tap_ip_rx_bytes, &mut self.tap_ip_rx_bytes);
        flush_one(&stats.tap_inject_packet, &mut self.tap_inject_packet);
        flush_one(&stats.tap_inject_bytes, &mut self.tap_inject_bytes);
        flush_one(&stats.tcp_packet, &mut self.tcp_packet);
        flush_one(
            &stats.tcp_packet_payload_bytes,
            &mut self.tcp_packet_payload_bytes,
        );
        flush_one(&stats.tcp_flow_packet, &mut self.tcp_flow_packet);
        flush_one(
            &stats.tcp_payload_guest_to_host,
            &mut self.tcp_payload_guest_to_host,
        );
        flush_one(
            &stats.tcp_payload_host_to_guest,
            &mut self.tcp_payload_host_to_guest,
        );
        flush_one(&stats.tcp_ack_sent, &mut self.tcp_ack_sent);
        flush_one(&stats.tcp_data_sent, &mut self.tcp_data_sent);
        self.pending_events = 0;
    }
}

thread_local! {
    static HOT_COUNTERS: RefCell<HotCounters> = RefCell::new(HotCounters::default());
}

fn flush_one(counter: &AtomicU64, pending: &mut u64) {
    if *pending != 0 {
        counter.fetch_add(*pending, Ordering::Relaxed);
        *pending = 0;
    }
}

pub fn stats() -> &'static MeshTunStats {
    &STATS
}

pub fn flush_hot_counters() {
    HOT_COUNTERS.with(|counters| counters.borrow_mut().flush());
}

pub fn record_tap_frame_rx(bytes: usize) {
    HOT_COUNTERS.with(|counters| {
        let mut counters = counters.borrow_mut();
        counters.tap_frame_rx += 1;
        counters.tap_frame_rx_bytes += bytes as u64;
        counters.add_event();
    });
}

pub fn record_tap_ip_rx(bytes: usize) {
    HOT_COUNTERS.with(|counters| {
        let mut counters = counters.borrow_mut();
        counters.tap_ip_rx += 1;
        counters.tap_ip_rx_bytes += bytes as u64;
        counters.add_event();
    });
}

pub fn record_tap_inject(bytes: usize) -> u64 {
    HOT_COUNTERS.with(|counters| {
        let mut counters = counters.borrow_mut();
        counters.tap_inject_packet += 1;
        counters.tap_inject_bytes += bytes as u64;
        counters.tap_inject_seen += 1;
        let packet_count = counters.tap_inject_seen;
        counters.add_event();
        packet_count
    })
}

pub fn record_tcp_packet(payload_bytes: usize) {
    HOT_COUNTERS.with(|counters| {
        let mut counters = counters.borrow_mut();
        counters.tcp_packet += 1;
        counters.tcp_packet_payload_bytes += payload_bytes as u64;
        counters.add_event();
    });
}

pub fn record_tcp_flow_packet() {
    HOT_COUNTERS.with(|counters| {
        let mut counters = counters.borrow_mut();
        counters.tcp_flow_packet += 1;
        counters.add_event();
    });
}

pub fn record_tcp_guest_to_host(bytes: usize) {
    HOT_COUNTERS.with(|counters| {
        let mut counters = counters.borrow_mut();
        counters.tcp_payload_guest_to_host += bytes as u64;
        counters.add_event();
    });
}

pub fn record_tcp_host_to_guest(bytes: usize) {
    HOT_COUNTERS.with(|counters| {
        let mut counters = counters.borrow_mut();
        counters.tcp_payload_host_to_guest += bytes as u64;
        counters.add_event();
    });
}

pub fn record_tcp_ack_sent() {
    HOT_COUNTERS.with(|counters| {
        let mut counters = counters.borrow_mut();
        counters.tcp_ack_sent += 1;
        counters.add_event();
    });
}

pub fn record_tcp_data_sent() {
    HOT_COUNTERS.with(|counters| {
        let mut counters = counters.borrow_mut();
        counters.tcp_data_sent += 1;
        counters.add_event();
    });
}

impl MeshTunStats {
    pub fn reset(&self) {
        HOT_COUNTERS.with(|counters| *counters.borrow_mut() = HotCounters::default());
        for counter in self.counters() {
            counter.1.store(0, Ordering::Relaxed);
        }
    }

    pub fn snapshot_lines(&self) -> Vec<String> {
        flush_hot_counters();
        self.counters()
            .into_iter()
            .map(|(name, counter)| format!("{name}={}", counter.load(Ordering::Relaxed)))
            .collect()
    }

    fn counters(&self) -> Vec<(&'static str, &AtomicU64)> {
        vec![
            ("control_capture_ok", &self.control_capture_ok),
            ("control_capture_err", &self.control_capture_err),
            ("route_hit", &self.route_hit),
            ("route_miss", &self.route_miss),
            ("route_send_full", &self.route_send_full),
            ("tun_input_queue_full", &self.tun_input_queue_full),
            ("tun_output_queue_full", &self.tun_output_queue_full),
            ("fallback_queue_full", &self.fallback_queue_full),
            ("egress_listener_start", &self.egress_listener_start),
            ("egress_accept", &self.egress_accept),
            ("egress_accept_error", &self.egress_accept_error),
            ("egress_connect_error", &self.egress_connect_error),
            ("egress_original_dst_error", &self.egress_original_dst_error),
            ("egress_bytes_to_upstream", &self.egress_bytes_to_upstream),
            ("egress_bytes_to_guest", &self.egress_bytes_to_guest),
            ("tap_frame_rx", &self.tap_frame_rx),
            ("tap_frame_rx_bytes", &self.tap_frame_rx_bytes),
            ("tap_ip_rx", &self.tap_ip_rx),
            ("tap_ip_rx_bytes", &self.tap_ip_rx_bytes),
            ("arp_request_rx", &self.arp_request_rx),
            ("arp_reply_tx", &self.arp_reply_tx),
            ("tap_inject_packet", &self.tap_inject_packet),
            ("tap_inject_bytes", &self.tap_inject_bytes),
            ("tap_inject_error", &self.tap_inject_error),
            ("tap_inject_queue_full", &self.tap_inject_queue_full),
            ("tap_inject_queue_rx", &self.tap_inject_queue_rx),
            (
                "tap_last_inject_dst_mac_hi",
                &self.tap_last_inject_dst_mac_hi,
            ),
            (
                "tap_last_inject_dst_mac_lo",
                &self.tap_last_inject_dst_mac_lo,
            ),
            (
                "tap_last_inject_src_mac_hi",
                &self.tap_last_inject_src_mac_hi,
            ),
            (
                "tap_last_inject_src_mac_lo",
                &self.tap_last_inject_src_mac_lo,
            ),
            ("tap_last_inject_ethertype", &self.tap_last_inject_ethertype),
            ("tap_last_inject_len", &self.tap_last_inject_len),
            ("tap_last_inject_write_rc", &self.tap_last_inject_write_rc),
            ("tap_last_inject_ipv4_src", &self.tap_last_inject_ipv4_src),
            ("tap_last_inject_ipv4_dst", &self.tap_last_inject_ipv4_dst),
            ("tap_last_inject_tcp_flags", &self.tap_last_inject_tcp_flags),
            (
                "tap_last_inject_ip_checksum_ok",
                &self.tap_last_inject_ip_checksum_ok,
            ),
            (
                "tap_last_inject_tcp_checksum_ok",
                &self.tap_last_inject_tcp_checksum_ok,
            ),
            ("tcp_packet", &self.tcp_packet),
            ("tcp_packet_payload_bytes", &self.tcp_packet_payload_bytes),
            ("tcp_syn", &self.tcp_syn),
            ("tcp_inbound_syn_sent", &self.tcp_inbound_syn_sent),
            ("tcp_inbound_ack_sent", &self.tcp_inbound_ack_sent),
            ("tcp_inbound_open", &self.tcp_inbound_open),
            ("tcp_inbound_rejected", &self.tcp_inbound_rejected),
            ("tcp_flow_rejected", &self.tcp_flow_rejected),
            ("tcp_flow_open", &self.tcp_flow_open),
            ("tcp_flow_packet", &self.tcp_flow_packet),
            ("tcp_flow_queue_full", &self.tcp_flow_queue_full),
            ("tcp_backend_flow_control", &self.tcp_backend_flow_control),
            ("tcp_handshake_timeout", &self.tcp_handshake_timeout),
            ("tcp_payload_guest_to_host", &self.tcp_payload_guest_to_host),
            ("tcp_guest_write_calls", &self.tcp_guest_write_calls),
            ("tcp_payload_host_to_guest", &self.tcp_payload_host_to_guest),
            ("tcp_host_read_calls", &self.tcp_host_read_calls),
            ("tcp_syn_ack_sent", &self.tcp_syn_ack_sent),
            ("tcp_ack_after_syn", &self.tcp_ack_after_syn),
            ("tcp_handshake_skip", &self.tcp_handshake_skip),
            ("tcp_last_handshake_flags", &self.tcp_last_handshake_flags),
            ("tcp_last_handshake_seq", &self.tcp_last_handshake_seq),
            ("tcp_last_handshake_ack", &self.tcp_last_handshake_ack),
            (
                "tcp_last_handshake_expected_ack",
                &self.tcp_last_handshake_expected_ack,
            ),
            (
                "tcp_last_handshake_payload_len",
                &self.tcp_last_handshake_payload_len,
            ),
            ("tcp_ack_sent", &self.tcp_ack_sent),
            ("tcp_data_sent", &self.tcp_data_sent),
            ("tcp_fin_sent", &self.tcp_fin_sent),
            ("tcp_flow_close", &self.tcp_flow_close),
            ("tcp_flow_error", &self.tcp_flow_error),
            ("tcp_window_wait", &self.tcp_window_wait),
            ("tcp_window_wake", &self.tcp_window_wake),
            ("tcp_window_timeout", &self.tcp_window_timeout),
            ("tcp_last_send_seq", &self.tcp_last_send_seq),
            ("tcp_last_send_end", &self.tcp_last_send_end),
            ("tcp_last_send_len", &self.tcp_last_send_len),
            ("tcp_last_acked", &self.tcp_last_acked),
            ("tcp_last_in_flight", &self.tcp_last_in_flight),
            ("tcp_last_ack_num", &self.tcp_last_ack_num),
            ("tcp_last_ack_flags", &self.tcp_last_ack_flags),
            ("tcp_bulk_window_wait", &self.tcp_bulk_window_wait),
            ("tcp_bulk_window_wake", &self.tcp_bulk_window_wake),
            ("tcp_bulk_last_send_seq", &self.tcp_bulk_last_send_seq),
            ("tcp_bulk_last_send_end", &self.tcp_bulk_last_send_end),
            ("tcp_bulk_last_send_len", &self.tcp_bulk_last_send_len),
            ("tcp_bulk_last_acked", &self.tcp_bulk_last_acked),
            ("tcp_bulk_last_in_flight", &self.tcp_bulk_last_in_flight),
            ("tcp_bulk_last_ack_num", &self.tcp_bulk_last_ack_num),
            ("tcp_bulk_last_ack_flags", &self.tcp_bulk_last_ack_flags),
            ("tcp_bulk_max_in_flight", &self.tcp_bulk_max_in_flight),
            ("tcp_bulk_window_wait_ns", &self.tcp_bulk_window_wait_ns),
            ("tcp_bulk_window_wait_slow", &self.tcp_bulk_window_wait_slow),
            (
                "tcp_bulk_backend_read_wait_ns",
                &self.tcp_bulk_backend_read_wait_ns,
            ),
            (
                "tcp_bulk_backend_read_wait_slow",
                &self.tcp_bulk_backend_read_wait_slow,
            ),
            (
                "tcp_bulk_output_send_wait_ns",
                &self.tcp_bulk_output_send_wait_ns,
            ),
            (
                "tcp_bulk_output_send_wait_slow",
                &self.tcp_bulk_output_send_wait_slow,
            ),
            (
                "tcp_bulk_output_send_wait_max_ns",
                &self.tcp_bulk_output_send_wait_max_ns,
            ),
            ("uds_broadcast_sent", &self.uds_broadcast_sent),
            (
                "uds_broadcast_no_subscribers",
                &self.uds_broadcast_no_subscribers,
            ),
            ("uds_client_lagged_frames", &self.uds_client_lagged_frames),
            ("uds_client_write_error", &self.uds_client_write_error),
        ]
    }
}
