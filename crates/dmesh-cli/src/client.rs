//! Direct serial L2 adapter for the standalone `dmesh-cli` host client.
//!
//! This belongs to `dmesh-cli`, not Recovery or firmware. It
//! opens an explicitly supplied serial port with no managed forward. The
//! optional initial record is opaque: commands/logs remain higher-level
//! transport services and this adapter never decodes them.

use crate::{
    device::{DeviceProfile, load_device, resolve_udp_peer},
    l2::UartEgressPacer,
    schema::{
        FirmwareSchema, encode_direct_command, encode_direct_command_with_id,
        encode_stream_command_with_id, encode_stream_fields_with_id, render_device_record,
    },
};
use dmesh_server::{
    announce,
    probe::{ProbeRun, ProbeServicePlan},
    uart::{UartIngress, classify_uart_payload, encode_uart_datagram},
};
use quic_lite::{
    ClientAssociation, ConnectionLimits, DatagramClient, PathId, StreamFrame,
    path_bridge::{PathBridge, PathBridgeAction},
};
use serde::Deserialize;
use std::{
    collections::VecDeque,
    env,
    fs::{File, OpenOptions},
    io::{BufRead, BufReader, ErrorKind, Read, Write},
    net::{Ipv6Addr, SocketAddr, SocketAddrV6, UdpSocket},
    os::fd::AsRawFd,
    os::unix::{
        fs::{FileTypeExt, OpenOptionsExt},
        net::{UnixListener, UnixStream},
    },
    path::{Path, PathBuf},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use uart_codec::codec::{Decoder, encode_payload};

/// A bounded observation made by a persistent physical-UART device session.
///
/// The serial bearer is shared by command/reply traffic, normal QUIC-lite
/// packets, and the small out-of-band boot/crash diagnostic channel.  Keeping
/// these observations together lets a hardware test retain the last useful
/// context when a later operation fails, without treating text as protocol.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DeviceSessionEvent {
    DirectRecord(Vec<u8>),
    TransportPacket(Vec<u8>),
    Diagnostic(String),
}

/// One explicitly owned UART connection to a firmware device.
///
/// A suite opens this once before its cases and closes it after all cases.
/// It deliberately does not implement an application protocol: callers send
/// a direct CBOR command or a QUIC-lite packet and inspect the bounded event
/// history through the same L2 owner.
pub struct DeviceSession {
    path: String,
    serial: File,
    decoder: Decoder,
    text_tap: RawTextTap,
    history: VecDeque<DeviceSessionEvent>,
    history_limit: usize,
    fatal_diagnostic: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SerialProbeResult {
    pub bytes: u64,
    pub normal_bytes: u64,
    pub high_bytes: u64,
    pub low_bytes: u64,
    pub elapsed_us: u64,
    pub bps: u64,
    pub tx_packets: u64,
    pub rx_packets: u64,
    pub retransmits: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SerialObjectUploadResult {
    pub response: Vec<u8>,
    pub records: usize,
    pub bytes: usize,
    pub tx_packets: u64,
    pub rx_packets: u64,
    pub retransmits: u64,
}

impl DeviceSession {
    pub const DEFAULT_HISTORY_LIMIT: usize = 64;

    /// Open one non-controlling, nonblocking UART owner.  Startup backlog is
    /// discarded before the session starts so a previous CLI invocation cannot
    /// be mistaken for a callback from the current test case.
    pub fn open(path: impl Into<String>, baud: Option<u32>) -> Result<Self, String> {
        let path = path.into();
        let mut serial = open_serial(&path)?;
        configure_serial(&serial, baud)?;
        let mut stale = [0u8; 256];
        loop {
            match serial.read(&mut stale) {
                Ok(used) if used != 0 => {}
                Ok(_) => break,
                Err(ref error) if error.kind() == ErrorKind::WouldBlock => break,
                Err(error) => return Err(error.to_string()),
            }
        }
        Ok(Self {
            path,
            serial,
            decoder: Decoder::with_max(quic_lite::DEFAULT_MAX_DATAGRAM_SIZE + 1),
            text_tap: RawTextTap::default(),
            history: VecDeque::with_capacity(Self::DEFAULT_HISTORY_LIMIT),
            history_limit: Self::DEFAULT_HISTORY_LIMIT,
            fatal_diagnostic: None,
        })
    }

    pub fn path(&self) -> &str {
        &self.path
    }

    /// Run the normal QUIC `probe` stream through this session's UART path.
    /// UART supplies complete frames only; bootstrap, CIDs, stream validation,
    /// flow control, and probe semantics are shared with every other path.
    pub fn probe(&mut self, bytes: u64, packet_size: u16) -> Result<SerialProbeResult, String> {
        self.probe_request(dmesh_server::probe::ProbeServiceRequest::new(
            bytes,
            packet_size,
        ))
    }

    pub fn probe_request(
        &mut self,
        request: dmesh_server::probe::ProbeServiceRequest,
    ) -> Result<SerialProbeResult, String> {
        self.assert_healthy()?;
        let cid = fresh_connection_id()?;
        let mut client = dmesh_server::transport::ProbeClient::<
            16,
            { quic_lite::DEFAULT_MAX_DATAGRAM_SIZE },
        >::from_request(cid, request)
        .map_err(|error| format!("probe client: {error:?}"))?;
        let started = Instant::now();
        let mut driver = quic_lite::DatagramClientDriver::start(&mut client, 0)
            .map_err(|error| format!("probe OPEN: {error:?}"))?;
        send_uart_transport(
            &mut self.serial,
            driver.packet().expect("a started driver has an OPEN"),
        )?;
        driver.mark_sent(0);
        let deadline = started + Duration::from_secs(45);
        let mut buffer = [0u8; quic_lite::DEFAULT_MAX_DATAGRAM_SIZE + 1];
        while Instant::now() < deadline {
            match self.serial.read(&mut buffer) {
                Ok(used) if used != 0 => {
                    for line in self.text_tap.push(&buffer[..used]) {
                        if is_fatal_diagnostic(&line) {
                            self.fatal_diagnostic.get_or_insert_with(|| line.clone());
                        }
                        self.push_event(DeviceSessionEvent::Diagnostic(line));
                    }
                    for frame in self
                        .decoder
                        .push(&buffer[..used])
                        .map_err(|error| error.to_string())?
                    {
                        match classify_uart_payload(&frame) {
                            Ok(UartIngress::Unmarked(packet)) => {
                                if let Some(record) =
                                    dmesh_server::direct::ConnectionlessMessage::decode(packet)
                                {
                                    self.push_event(DeviceSessionEvent::DirectRecord(
                                        record.to_vec(),
                                    ));
                                }
                            }
                            Ok(UartIngress::Transport(input)) => {
                                self.push_event(DeviceSessionEvent::TransportPacket(
                                    input.to_vec(),
                                ));
                                let now_ms = started.elapsed().as_millis() as u64;
                                if driver
                                    .receive(&mut client, input, now_ms)
                                    .map_err(|error| format!("probe receive: {error:?}"))?
                                    && let Some(packet) = driver.packet()
                                {
                                    send_uart_transport(&mut self.serial, packet)?;
                                    driver.mark_sent(now_ms);
                                }
                            }
                            Err(_) => {}
                        }
                    }
                }
                Ok(_) => {}
                Err(ref error) if error.kind() == ErrorKind::WouldBlock => {}
                Err(error) => return Err(error.to_string()),
            }

            let now_ms = started.elapsed().as_millis() as u64;
            driver
                .poll(&mut client, now_ms, 600, 400)
                .map_err(|error| format!("probe poll: {error:?}"))?;
            if let Some(packet) = driver.packet() {
                send_uart_transport(&mut self.serial, packet)?;
                driver.mark_sent(now_ms);
            }
            if client.is_complete() {
                self.assert_healthy()?;
                let elapsed_us = started.elapsed().as_micros().max(1) as u64;
                let transferred = client.bytes();
                // This is a one-shot MeshClient operation.  Retire its
                // association while the UART path is still live: otherwise
                // a bounded firmware association table retains one CID for
                // every standalone probe until an idle timeout.  The close
                // packet is ordinary QUIC-lite framing, never UART policy.
                let mut close_packet = [0u8; quic_lite::DEFAULT_MAX_DATAGRAM_SIZE];
                if let Some(close) = client
                    .poll_close(&mut close_packet)
                    .map_err(|error| format!("probe close: {error:?}"))?
                {
                    send_uart_transport(&mut self.serial, &close_packet[..close])?;
                }
                return Ok(SerialProbeResult {
                    bytes: transferred,
                    normal_bytes: client.normal_bytes(),
                    high_bytes: client.high_bytes(),
                    low_bytes: client.low_bytes(),
                    elapsed_us,
                    bps: transferred.saturating_mul(8_000_000) / elapsed_us,
                    tx_packets: driver.tx_packets(),
                    rx_packets: driver.rx_packets(),
                    retransmits: driver.retransmit_packets(),
                });
            }
            thread::sleep(Duration::from_millis(2));
        }
        self.assert_healthy()?;
        Err(format!(
            "probe timeout: bytes={}/{} packet_classes={:?} callback_errors={:?}",
            client.bytes(),
            request.bytes,
            client.packet_classes(),
            client.callback_errors(),
        ))
    }

    /// Run the ordinary two-stream `object.flash` operation over this UART.
    /// The UART adapter moves only framed datagrams; `ObjectUploadClient` and
    /// `DatagramClientDriver` own streams, ACKs, credit, and retransmission.
    pub fn object_upload(
        &mut self,
        command: &[u8],
        records: dmesh_server::verified_object::ObjectBodyStream,
    ) -> Result<SerialObjectUploadResult, String> {
        self.assert_healthy()?;
        let cid = fresh_connection_id()?;
        let mut client = dmesh_server::transport::ObjectUploadClient::<
            512,
            { quic_lite::DEFAULT_MAX_DATAGRAM_SIZE },
        >::new(cid, command, records)
        .map_err(|error| format!("object upload client: {error:?}"))?;
        let started = Instant::now();
        let mut driver = quic_lite::DatagramClientDriver::start(&mut client, 0)
            .map_err(|error| format!("object upload OPEN: {error:?}"))?;
        send_uart_transport(
            &mut self.serial,
            driver.packet().expect("a started driver has an OPEN"),
        )?;
        driver.mark_sent(0);
        let deadline = started + object_upload_timeout();
        let mut buffer = [0u8; quic_lite::DEFAULT_MAX_DATAGRAM_SIZE + 1];
        let mut operation_diagnostics = VecDeque::new();
        while Instant::now() < deadline {
            match self.serial.read(&mut buffer) {
                Ok(used) if used != 0 => {
                    for line in self.text_tap.push(&buffer[..used]) {
                        if is_fatal_diagnostic(&line) {
                            self.fatal_diagnostic.get_or_insert_with(|| line.clone());
                        }
                        if line.contains("DMESH") || line.contains("flash") {
                            operation_diagnostics.push_back(line.clone());
                            if operation_diagnostics.len() > 32 {
                                operation_diagnostics.pop_front();
                            }
                        }
                        self.push_event(DeviceSessionEvent::Diagnostic(line));
                    }
                    for frame in self
                        .decoder
                        .push(&buffer[..used])
                        .map_err(|error| error.to_string())?
                    {
                        match classify_uart_payload(&frame) {
                            Ok(UartIngress::Unmarked(packet)) => {
                                if let Some(record) =
                                    dmesh_server::direct::ConnectionlessMessage::decode(packet)
                                {
                                    operation_diagnostics.push_back(render_device_record(
                                        &FirmwareSchema::load(),
                                        record,
                                    ));
                                    if operation_diagnostics.len() > 32 {
                                        operation_diagnostics.pop_front();
                                    }
                                    self.push_event(DeviceSessionEvent::DirectRecord(
                                        record.to_vec(),
                                    ));
                                }
                            }
                            Ok(UartIngress::Transport(input)) => {
                                self.push_event(DeviceSessionEvent::TransportPacket(
                                    input.to_vec(),
                                ));
                                let now_ms = started.elapsed().as_millis() as u64;
                                let received = match driver.receive(&mut client, input, now_ms) {
                                    Ok(received) => received,
                                    Err(error) => {
                                        self.assert_healthy()?;
                                        return Err(format!(
                                            "object upload receive: {error:?} records={} bytes={} tx_packets={} rx_packets={} retransmits={}",
                                            client.record_index(),
                                            client.sent_bytes(),
                                            driver.tx_packets(),
                                            driver.rx_packets(),
                                            driver.retransmit_packets()
                                        ));
                                    }
                                };
                                if received && let Some(packet) = driver.packet() {
                                    send_uart_transport(&mut self.serial, packet)?;
                                    driver.mark_sent(now_ms);
                                }
                            }
                            Err(_) => {}
                        }
                    }
                }
                Ok(_) => {}
                Err(ref error) if error.kind() == ErrorKind::WouldBlock => {}
                Err(error) => return Err(error.to_string()),
            }
            let now_ms = started.elapsed().as_millis() as u64;
            driver
                .poll(&mut client, now_ms, 600, 400)
                .map_err(|error| format!("object upload poll: {error:?}"))?;
            if let Some(packet) = driver.packet() {
                send_uart_transport(&mut self.serial, packet)?;
                driver.mark_sent(now_ms);
            }
            if client.is_complete() {
                self.assert_healthy()?;
                let mut close_packet = [0u8; quic_lite::DEFAULT_MAX_DATAGRAM_SIZE];
                if let Some(close) = client
                    .poll_close(&mut close_packet)
                    .map_err(|error| format!("object upload close: {error:?}"))?
                {
                    send_uart_transport(&mut self.serial, &close_packet[..close])?;
                }
                if let Some(response) = client.rejected_response() {
                    let reason = object_upload_rejection(response);
                    return Err(format!(
                        "object upload rejected: {} records={} bytes={} blocked={:?} admission={:?}",
                        reason,
                        client.record_index(),
                        client.sent_bytes(),
                        client.last_admission_block(),
                        client.admission_state(),
                    ));
                }
                return Ok(SerialObjectUploadResult {
                    response: client.response().unwrap_or_default().to_vec(),
                    records: client.record_index(),
                    bytes: client.sent_bytes(),
                    tx_packets: driver.tx_packets(),
                    rx_packets: driver.rx_packets(),
                    retransmits: driver.retransmit_packets(),
                });
            }
            thread::sleep(Duration::from_millis(2));
        }
        self.assert_healthy()?;
        let recent = self
            .history
            .iter()
            .filter_map(|event| match event {
                DeviceSessionEvent::Diagnostic(line) => Some(line.clone()),
                DeviceSessionEvent::DirectRecord(record) => {
                    Some(render_device_record(&FirmwareSchema::load(), record))
                }
                _ => None,
            })
            .rev()
            .take(16)
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect::<Vec<_>>()
            .join(" | ");
        let diagnostics = operation_diagnostics
            .into_iter()
            .collect::<Vec<_>>()
            .join(" | ");
        Err(format!(
            "object upload timeout records={} bytes={} blocked={:?} admission={:?} connection={:?} tx_packets={} rx_packets={} retransmits={} operation_diagnostics={diagnostics:?} recent={recent:?}",
            client.record_index(),
            client.sent_bytes(),
            client.last_admission_block(),
            client.admission_state(),
            client.connection_debug_state(),
            driver.tx_packets(),
            driver.rx_packets(),
            driver.retransmit_packets()
        ))
    }

    pub fn set_history_limit(&mut self, limit: usize) {
        self.history_limit = limit.max(1);
        while self.history.len() > self.history_limit {
            self.history.pop_front();
        }
    }

    /// Discard delayed boot output before a caller starts its first operation.
    ///
    /// This is for a USB-pair fixture immediately after it obtains exclusive
    /// ownership of a CP210x port.  Some boards reset when the previous test
    /// process closes its last port owner; their ROM/ESP-IDF text can arrive
    /// after the next process has opened the same device.  Waiting and
    /// draining here keeps that *pre-test* reset from being attributed to the
    /// first radio operation.  It never runs during a probe: after the caller
    /// sends any record, [`poll_until`] retains diagnostics and treats a reset
    /// as a real failure.
    pub fn discard_startup_backlog(&mut self, settle: Duration) -> Result<(), String> {
        let deadline = Instant::now() + settle;
        let mut discarded = [0u8; quic_lite::DEFAULT_MAX_DATAGRAM_SIZE + 1];
        while Instant::now() < deadline {
            match self.serial.read(&mut discarded) {
                Ok(_) => {}
                Err(ref error) if error.kind() == ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(2));
                }
                Err(error) => return Err(error.to_string()),
            }
        }
        // A reset can split a PPP delimiter across the drain boundary.  Start
        // the actual test with no partial binary frame, diagnostic line, or
        // stale fatal marker from the preceding serial owner.
        self.decoder = Decoder::with_max(quic_lite::DEFAULT_MAX_DATAGRAM_SIZE + 1);
        self.text_tap = RawTextTap::default();
        self.history.clear();
        self.fatal_diagnostic = None;
        Ok(())
    }

    pub fn recent_events(&self) -> impl ExactSizeIterator<Item = &DeviceSessionEvent> {
        self.history.iter()
    }

    pub fn assert_healthy(&self) -> Result<(), String> {
        self.fatal_diagnostic.as_ref().map_or(Ok(()), |diagnostic| {
            // The first marker makes the session unhealthy, but its position
            // matters. ESP-IDF prints the panic/reset cause, register dump,
            // and backtrace footer as distinct UART lines. Keep the ordered
            // diagnostic window surrounding the *first* fatal line so a
            // long-running bearer test can distinguish a device reset from
            // an unrelated later boot banner. This is diagnostics only; the
            // serial session still stops at the first fatal condition.
            let diagnostics = self
                .history
                .iter()
                .filter_map(|event| match event {
                    DeviceSessionEvent::Diagnostic(line) => Some(line.as_str()),
                    _ => None,
                })
                .collect::<Vec<_>>();
            let first_fatal = diagnostics
                .iter()
                .position(|line| is_fatal_diagnostic(line))
                .unwrap_or(0);
            let context_start = first_fatal.saturating_sub(12);
            let context_end = (first_fatal + 33).min(diagnostics.len());
            let context = diagnostics[context_start..context_end].to_vec();
            Err(format!(
                "device {} reported fatal diagnostic={diagnostic:?}; ordered UART diagnostics around first fatal={context:?}",
                self.path,
            ))
        })
    }

    /// Send a PPP-framed custom-version long-header direct record. The UART
    /// PPP layer remains physical framing only; control receives the same
    /// packet used by the UDP direct-record plane.
    pub fn send_direct_record(&mut self, record: &[u8]) -> Result<(), String> {
        if record.is_empty() || record.len() > quic_lite::DEFAULT_MAX_DATAGRAM_SIZE - 6 {
            return Err("direct record is empty or exceeds the UART MTU".into());
        }
        self.assert_healthy()?;
        let mut packet = [0u8; quic_lite::DEFAULT_MAX_DATAGRAM_SIZE];
        let used = dmesh_server::direct::ConnectionlessMessage::encode(record, &mut packet)
            .ok_or_else(|| "UART connectionless record exceeds the MTU".to_owned())?;
        send_ppp(&mut self.serial, &packet[..used])
    }

    /// Check the device on this directed UART path using the same
    /// `announce.discovery` request/reply used by every connectionless bearer.
    pub fn check(&mut self, timeout: Duration) -> Result<announce::Announce, String> {
        let id = fresh_request_id();
        let mut request = [0u8; 64];
        let used = announce::encode_discovery_request(id, &mut request)
            .ok_or("encode directed discovery request")?;
        let mut response = None;
        let matched = self.request_direct_record_until(&request[..used], timeout, |event| {
            let DeviceSessionEvent::DirectRecord(payload) = event else {
                return false;
            };
            let Some(record) = dmesh_server::tagged::decode(payload) else {
                return false;
            };
            if record.id != Some(id) {
                return false;
            }
            let Some(discovery) = announce::decode_record(record) else {
                return false;
            };
            if discovery.kind != announce::ANNOUNCE_DISCOVERY {
                return false;
            }
            response = Some(discovery);
            true
        })?;
        if !matched {
            return Err(format!("directed discovery timed out on {}", self.path));
        }
        response.ok_or_else(|| "directed discovery response disappeared".to_owned())
    }

    /// Poll the one UART owner and append all received observations to its
    /// bounded history. Returns the number of complete PPP records received.
    pub fn poll(&mut self, timeout: Duration) -> Result<usize, String> {
        self.poll_until(timeout, |_| false)
            .map(|(_, records)| records)
    }

    /// Poll until a caller-selected decoded event arrives or the bounded
    /// interval expires.  This lets an E2E suite retain one UART owner while
    /// correlating a real response instead of sleeping for every command.
    /// The callback sees the exact event retained in history, so no
    /// UART-specific response protocol is introduced here.
    pub fn poll_until<F>(
        &mut self,
        timeout: Duration,
        mut matched: F,
    ) -> Result<(bool, usize), String>
    where
        F: FnMut(&DeviceSessionEvent) -> bool,
    {
        let deadline = Instant::now() + timeout;
        let mut buffer = [0u8; quic_lite::DEFAULT_MAX_DATAGRAM_SIZE + 1];
        let mut records = 0;
        while Instant::now() < deadline {
            match self.serial.read(&mut buffer) {
                Ok(used) if used != 0 => {
                    for line in self.text_tap.push(&buffer[..used]) {
                        if is_fatal_diagnostic(&line) {
                            self.fatal_diagnostic.get_or_insert_with(|| line.clone());
                        }
                        self.push_event(DeviceSessionEvent::Diagnostic(line));
                    }
                    for frame in self
                        .decoder
                        .push(&buffer[..used])
                        .map_err(|error| error.to_string())?
                    {
                        records += 1;
                        match classify_uart_payload(&frame) {
                            Ok(UartIngress::Unmarked(packet)) => {
                                if let Some(record) =
                                    dmesh_server::direct::ConnectionlessMessage::decode(packet)
                                {
                                    let event = DeviceSessionEvent::DirectRecord(record.to_vec());
                                    let is_match = matched(&event);
                                    self.push_event(event);
                                    if is_match {
                                        self.assert_healthy()?;
                                        return Ok((true, records));
                                    }
                                }
                            }
                            Ok(UartIngress::Transport(packet)) => {
                                let event = DeviceSessionEvent::TransportPacket(packet.to_vec());
                                let is_match = matched(&event);
                                self.push_event(event);
                                if is_match {
                                    self.assert_healthy()?;
                                    return Ok((true, records));
                                }
                            }
                            Err(_) => {}
                        }
                    }
                }
                Ok(_) => {
                    thread::sleep(Duration::from_millis(2));
                }
                Err(ref error) if error.kind() == ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(2));
                }
                Err(error) => return Err(error.to_string()),
            }
        }
        self.assert_healthy()?;
        Ok((false, records))
    }

    /// Send a direct record and retain callbacks for the requested interval.
    /// Callers select/correlate replies from `recent_events`; raw records do
    /// not have a universal response envelope to manufacture here.
    pub fn request_direct_record(
        &mut self,
        record: &[u8],
        timeout: Duration,
    ) -> Result<(), String> {
        self.send_direct_record(record)?;
        self.poll(timeout)?;
        Ok(())
    }

    /// Send one direct record and stop once its caller-defined response is
    /// observed.  The generic predicate keeps raw CBOR, stream packets, and
    /// future schema-defined diagnostics on the same UART L2 path.
    pub fn request_direct_record_until<F>(
        &mut self,
        record: &[u8],
        timeout: Duration,
        matched: F,
    ) -> Result<bool, String>
    where
        F: FnMut(&DeviceSessionEvent) -> bool,
    {
        self.send_direct_record(record)?;
        self.poll_until(timeout, matched)
            .map(|(matched, _)| matched)
    }

    fn push_event(&mut self, event: DeviceSessionEvent) {
        if self.history.len() == self.history_limit {
            self.history.pop_front();
        }
        self.history.push_back(event);
    }
}

fn is_fatal_diagnostic(line: &str) -> bool {
    let line = line.to_ascii_lowercase();
    [
        "panic",
        "guru meditation",
        "assert failed",
        "backtrace",
        "abort()",
        // A ROM reset after the initial session drain means the device
        // restarted during this suite even if it did not print a panic.
        "rst:",
    ]
    .iter()
    .any(|marker| line.contains(marker))
}

/// Bearer-neutral path policy accepted by the host CLI and the future
/// `lmesh-wifi` egress handler. The policy chooses among registered paths;
/// it never changes the command, probe, or log-watch stream protocol.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClientPathPolicy {
    HighestMeasuredSpeed,
    Aggregate,
    Udp,
    Uart,
    UartSpillover,
}

impl ClientPathPolicy {
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "aggregate" => Some(Self::Aggregate),
            "fastest" => Some(Self::HighestMeasuredSpeed),
            "udp" => Some(Self::Udp),
            "uart" => Some(Self::Uart),
            "spill" | "uart-spill-udp" => Some(Self::UartSpillover),
            _ => None,
        }
    }

    /// Compact policy value shared with the firmware transport profile.
    pub const fn wire(self) -> u8 {
        match self {
            Self::HighestMeasuredSpeed => 0,
            Self::Udp => 1,
            Self::Uart => 2,
            Self::UartSpillover => 3,
            Self::Aggregate => 4,
        }
    }
}

fn usage() -> ! {
    eprintln!(
        "usage: dmesh-cli SERIAL|DEVICE --reset\n       dmesh-cli SERIAL|DEVICE --watch [--reset] [--interactive] [--baud PHYSICAL_UART_BAUD] [--timeout-secs N]\n       dmesh-cli NODE SERVICE [field=value ...]\n       dmesh-cli hosts check\n       dmesh-cli discover\n       dmesh-cli flash TARGET [--file MAIN_IMAGE]\n       dmesh-cli SERIAL|DEVICE [--msg TEXT | --direct-hex HEX] [--timeout-secs N]\n       dmesh-cli uds:///run/mesh/lmesh[-wifi]/mesh.sock|lmesh://lmesh[-wifi] --method METHOD [--data JSON] [--to NODE]\n       dmesh-cli SERIAL|DEVICE BOOTSTRAP_BIND BACKEND [--baud PHYSICAL_UART_BAUD] [--bearer uart|udp|aggregate|spill] [--msg TEXT | --direct-hex HEX] [--timeout-secs N]\n       dmesh-cli NODE check\n       dmesh-cli udp://HOST:PORT --socket PATH"
    );
    std::process::exit(2)
}

fn hex(value: &str) -> Result<Vec<u8>, String> {
    if value.len() % 2 != 0 {
        return Err("hex length must be even".into());
    }
    (0..value.len())
        .step_by(2)
        .map(|offset| {
            u8::from_str_radix(&value[offset..offset + 2], 16).map_err(|error| error.to_string())
        })
        .collect()
}

fn hex_encode(value: &[u8]) -> String {
    value.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Render a 6-byte radio MAC as a colon-separated lowercase hex string.
fn mac_encode(value: &[u8]) -> String {
    value.iter().map(|byte| format!("{byte:02x}")).collect::<Vec<_>>().join(":")
}

fn physical_baud(value: u32) -> Option<libc::speed_t> {
    match value {
        9_600 => Some(libc::B9600),
        19_200 => Some(libc::B19200),
        38_400 => Some(libc::B38400),
        57_600 => Some(libc::B57600),
        115_200 => Some(libc::B115200),
        230_400 => Some(libc::B230400),
        460_800 => Some(libc::B460800),
        921_600 => Some(libc::B921600),
        _ => None,
    }
}

/// Configure record framing without imposing a physical UART speed on a
/// packetized USB serial device. `--baud` is deliberately opt-in: it both
/// configures a real UART and enables matching 8N1 pacing in the L2 adapter.
fn configure_serial(file: &File, baud: Option<u32>) -> Result<(), String> {
    unsafe {
        let mut value: libc::termios = core::mem::zeroed();
        if libc::tcgetattr(file.as_raw_fd(), &mut value) != 0 {
            return Err(std::io::Error::last_os_error().to_string());
        }
        let original = value;
        libc::cfmakeraw(&mut value);
        // A direct QUIC-lite session is a packet bearer, not a modem call.
        // Leave carrier local and suppress HUPCL so closing a short-lived
        // CLI request cannot drop DTR/RTS and reset an attached ESP board.
        // Modem-line experiments are explicit service operations elsewhere.
        value.c_cflag |= libc::CLOCAL;
        value.c_cflag &= !libc::HUPCL;
        if let Some(baud) = baud {
            let speed = physical_baud(baud).ok_or_else(|| {
                format!("unsupported physical UART baud {baud}; use 9600..921600 standard rates")
            })?;
            if libc::cfsetispeed(&mut value, speed) != 0
                || libc::cfsetospeed(&mut value, speed) != 0
            {
                return Err(std::io::Error::last_os_error().to_string());
            }
        }
        // Avoid a redundant TCSETS: a CP2102 may treat even an identical
        // termios update as a modem-state transition.  The common case is an
        // already-configured 115200 8N1 raw console, so leave it untouched.
        if libc::memcmp(
            (&original as *const libc::termios).cast(),
            (&value as *const libc::termios).cast(),
            core::mem::size_of::<libc::termios>(),
        ) != 0
            && libc::tcsetattr(file.as_raw_fd(), libc::TCSANOW, &value) != 0
        {
            return Err(std::io::Error::last_os_error().to_string());
        }
        let flags = libc::fcntl(file.as_raw_fd(), libc::F_GETFL);
        if flags < 0 || libc::fcntl(file.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) != 0
        {
            return Err(std::io::Error::last_os_error().to_string());
        }
    }
    Ok(())
}

/// Open a physical serial bearer without acquiring it as this process's
/// controlling terminal.  CP2102 bridges can change modem outputs when a
/// process opens the port as a controlling TTY, which resets ESP boards before
/// the first QUIC-lite packet.  Normal sessions never need DTR or RTS; reset
/// remains an explicit command path below.
fn open_serial(path: &str) -> Result<File, String> {
    OpenOptions::new()
        .read(true)
        .write(true)
        // Apply nonblocking at open time too.  Doing so only after `open(2)`
        // can let the USB serial driver assert its default modem state for
        // one transition on CP2102-backed ESP boards.
        .custom_flags(libc::O_NOCTTY | libc::O_NONBLOCK)
        .open(path)
        .map_err(|error| error.to_string())
}

fn send_ppp(serial: &mut File, payload: &[u8]) -> Result<(), String> {
    let wire = encode_payload(payload, quic_lite::DEFAULT_MAX_DATAGRAM_SIZE + 1)
        .map_err(|error| error.to_string())?;
    serial.write_all(&wire).map_err(|error| error.to_string())
}

/// Run the standalone DMesh client using process arguments.
pub fn run_dmesh_cli() -> Result<(), String> {
    run_dmesh_cli_args(env::args().skip(1))
}

/// Run the exact CLI client with supplied arguments. Managed callers use this
/// instead of spawning the executable, so tests, the CLI, and the Wi-Fi
/// gateway keep one L2/session implementation.
pub fn run_dmesh_cli_args(args: impl IntoIterator<Item = String>) -> Result<(), String> {
    let mut arguments: Vec<String> = args.into_iter().collect();
    if arguments.as_slice() == ["hosts", "check"] {
        return run_hosts_check();
    }
    if arguments.as_slice() == ["discover"] {
        return run_hosts_discovery();
    }
    if arguments.first().is_some_and(|argument| argument == "flash") {
        return run_automated_flash(&arguments[1..]);
    }
    if arguments.get(1).is_some_and(|argument| argument == "check") {
        let explicit_baud = match arguments.as_slice() {
            [_, _] => None,
            [_, _, flag, value] if flag == "--baud" => Some(
                value
                    .parse::<u32>()
                    .map_err(|error| format!("invalid check --baud: {error}"))?,
            ),
            _ => {
                return Err("check accepts NODE [--baud PHYSICAL_UART_BAUD]".into());
            }
        };
        let target = arguments.first().cloned().unwrap_or_else(|| usage());
        if target.starts_with("udp://") {
            if explicit_baud.is_some() {
                return Err("--baud applies only to a UART check".into());
            }
            return run_udp_direct_discovery(parse_udp_peer(target.trim_start_matches("udp://"))?);
        }
        if !target.starts_with('/') {
            match resolve_udp_peer(&target) {
                Ok(Some(peer)) => {
                    if explicit_baud.is_some() {
                        return Err("--baud applies only to a UART check".into());
                    }
                    return run_udp_direct_discovery(peer);
                }
                Ok(None) | Err(_) => {}
            }
            let profile = load_device(&target)?;
            let serial = profile
                .serial_path()?
                .ok_or_else(|| format!("device {target:?} has no reachable check path"))?;
            arguments[0] = serial.display().to_string();
            return run_serial_direct_discovery(&arguments[0], explicit_baud.or(profile.uart_baud));
        }
        return run_serial_direct_discovery(&arguments[0], explicit_baud);
    }
    if arguments
        .first()
        .is_some_and(|target| proxy_socket_target(target).is_some())
    {
        return run_lmesh_proxy_client(&arguments);
    }
    if arguments
        .get(1)
        .is_some_and(|argument| argument == "--reset")
    {
        if arguments.len() != 2 {
            return Err("--reset accepts exactly one serial target".into());
        }
        let target = arguments.first().cloned().unwrap_or_else(|| usage());
        if !target.starts_with('/') {
            let profile = load_device(&target)?;
            let serial = profile
                .serial_path()?
                .ok_or_else(|| format!("device {target:?} has no serial_id for --reset"))?;
            arguments[0] = serial.display().to_string();
        }
        return reset_serial(&arguments[0]);
    }
    // Watch is explicitly a physical UART operation. A device profile with
    // both serial and static-UDP paths must not silently choose UDP here.
    if arguments
        .get(1)
        .is_some_and(|argument| argument == "--watch")
    {
        let target = arguments.first().cloned().unwrap_or_else(|| usage());
        if !target.starts_with('/') {
            if target.contains(':') {
                return Err(
                    "--watch requires a serial path or device profile, not an IP target".into(),
                );
            }
            let profile = load_device(&target)?;
            let serial = profile
                .serial_path()?
                .ok_or_else(|| format!("device {target:?} has no serial_id for --watch"))?;
            arguments[0] = serial.display().to_string();
            append_catalog_uart_baud(&mut arguments, &profile);
        }
        return run_serial_watch(&arguments);
    }
    // Raw records are an intentional, bounded physical-bearer lane for
    // schema-defined bootstrap/control and diagnostics.  An explicit UDP URI
    // selects the companion's private direct-control lane; a named profile remains
    // serial-first so a routine local command cannot silently use the radio.
    if arguments
        .get(1)
        .is_some_and(|argument| matches!(argument.as_str(), "--direct-hex" | "--msg"))
    {
        let target = arguments.first().cloned().unwrap_or_else(|| usage());
        if target.starts_with("udp://") {
            return run_udp_direct_record(&arguments);
        }
        if !target.starts_with('/') {
            if target.contains(':') {
                return Err(
                    "--msg requires an explicit udp:// target, serial path, or device profile"
                        .into(),
                );
            }
            let profile = load_device(&target)?;
            let serial = profile
                .serial_path()?
                .ok_or_else(|| format!("device {target:?} has no serial_id for --msg"))?;
            arguments[0] = serial.display().to_string();
            append_catalog_uart_baud(&mut arguments, &profile);
        }
        return run_serial_direct_record(&arguments);
    }
    if let Some(target) = arguments
        .first()
        .cloned()
        .filter(|target| !target.starts_with("udp://"))
    {
        match resolve_udp_peer(&target) {
            Ok(Some(peer)) => {
                arguments[0] = format!("udp://{peer}");
                return run_udp_service_client(&arguments);
            }
            Ok(None) => {}
            // A serial-only device profile is still a valid shell target.
            // Preserve the existing explicit UART backend arguments after
            // replacing its name with the resolved `/dev/serial/by-id` path.
            Err(_) if !target.starts_with('/') && !target.contains(':') => {
                let profile = load_device(&target)?;
                let serial = profile.serial_path()?.ok_or_else(|| {
                    format!("device {target:?} has neither static_ipv4 nor serial_id")
                })?;
                arguments[0] = serial.display().to_string();
                append_catalog_uart_baud(&mut arguments, &profile);
            }
            Err(error) => return Err(error),
        }
    }
    if arguments
        .first()
        .is_some_and(|target| target.starts_with("udp://"))
    {
        return run_udp_service_client(&arguments);
    }
    // A serial service probe is a direct QUIC-lite client, not the older
    // UART-to-UDP bridge mode below.  It is the smallest end-to-end check for
    // the shared firmware dispatcher and lets a failed UDP bearer be isolated
    // without reintroducing a command-specific UART protocol.
    if arguments
        .get(1)
        .is_some_and(|argument| FirmwareSchema::load().is_stream_command_name(argument))
    {
        return run_serial_stream_command(&arguments);
    }
    let mut args = arguments.into_iter();
    let path = args.next().unwrap_or_else(|| usage());
    let bootstrap = parse_udp_peer(&args.next().unwrap_or_else(|| usage()))?;
    let backend: SocketAddr = args
        .next()
        .unwrap_or_else(|| usage())
        .parse::<SocketAddr>()
        .map_err(|error| error.to_string())?;
    if backend.ip().is_unspecified() {
        return Err(
            "BACKEND must be a routable host address (for example 10.78.0.1:3340), not 0.0.0.0"
                .into(),
        );
    }
    let mut direct = None;
    let mut timeout = Duration::from_secs(90);
    // No `--baud` means packetized USB serial (the e6 USB-JTAG case), which
    // is governed by actual driver backpressure rather than a fake 115200
    // 8N1 link.  A physical UART must opt in with `--baud`.
    let mut baud = None;
    // Host egress policy. Recovery retains its normal dynamic return-path
    // policy and merely receives complete packets on whichever bearer wins.
    let mut host_policy = ClientPathPolicy::Uart;
    while let Some(argument) = args.next() {
        match argument.as_str() {
            "--direct-hex" => direct = Some(hex(&args.next().unwrap_or_else(|| usage()))?),
            "--msg" => {
                if direct.is_some() {
                    return Err("choose one of --msg and --direct-hex".into());
                }
                let command = args.next().unwrap_or_else(|| usage());
                direct = Some(encode_direct_command(&command).map_err(|error| error.to_string())?);
            }
            "--timeout-secs" => {
                timeout = Duration::from_secs(
                    args.next()
                        .unwrap_or_else(|| usage())
                        .parse::<u64>()
                        .map_err(|error| error.to_string())?,
                )
            }
            "--baud" => {
                baud = Some(
                    args.next()
                        .unwrap_or_else(|| usage())
                        .parse::<u32>()
                        .map_err(|error| error.to_string())?,
                )
            }
            "--bearer" => {
                host_policy = ClientPathPolicy::parse(&args.next().unwrap_or_else(|| usage()))
                    .ok_or("bearer must be uart, udp, aggregate, fastest, or spill")?;
            }
            _ => usage(),
        }
    }
    let socket = UdpSocket::bind(bootstrap).map_err(|error| error.to_string())?;
    socket
        .set_nonblocking(true)
        .map_err(|error| error.to_string())?;
    let mut serial = open_serial(&path)?;
    configure_serial(&serial, None)?;
    if let Some(record) = direct {
        send_ppp(&mut serial, &record)?;
    }

    let schema = FirmwareSchema::load();
    let mut bridge = PathBridge::default();
    let mut decoder = Decoder::with_max(quic_lite::DEFAULT_MAX_DATAGRAM_SIZE + 1);
    // A USB driver accepting a burst is not evidence that the device has
    // consumed it. Keep the normal initial transport flight outstanding until
    // validated packets return on this L2 path; that is actual receiver
    // feedback rather than a made-up USB baud rate. A physical UART gains its
    // own wire pacing from `--baud` as well.
    let mut egress = baud.map_or_else(
        || UartEgressPacer::unpaced(8),
        |baud| UartEgressPacer::new(baud, 8),
    );
    let mut buffer = [0u8; quic_lite::DEFAULT_MAX_DATAGRAM_SIZE + 1];
    let mut bootstrap_peer = None;
    let mut established_backend_packets = 0u64;
    let mut primary_packets = 0u64;
    let mut secondary_packets = 0u64;
    let started = Instant::now();
    let deadline = started + timeout;
    while Instant::now() < deadline {
        // A UART is a slow, bounded datagram bearer. Do not drain a faster
        // backend into a full serial queue: leave data in the socket so
        // QUIC-lite ACK/credit applies pressure before local loss occurs.
        // Keep receiving backend packets when the UART queue is full.  For
        // `uart-spill-udp` that fullness is the signal to send the packet on
        // the bootstrap/UDP path; gating this recv behind UART capacity would
        // turn spillover into an artificial connection-wide stall.
        // Explicit UART is a comparison mode: retain socket backpressure
        // rather than changing the selected bearer. Only the spill policy is
        // allowed to keep receiving once UART reports a full local queue.
        if host_policy != ClientPathPolicy::Uart || egress.has_capacity() {
            match socket.recv_from(&mut buffer) {
                Ok((used, peer)) if peer == backend => {
                    let uart = match host_policy {
                        // Keep most traffic on the faster UDP bearer while
                        // periodically exercising the UART path as well.
                        ClientPathPolicy::HighestMeasuredSpeed => {
                            established_backend_packets =
                                established_backend_packets.saturating_add(1);
                            established_backend_packets % 32 == 0
                        }
                        // Fill a bounded UART egress queue; excess server
                        // traffic continues over UDP instead of stalling the
                        // shared connection behind UART wire time.
                        ClientPathPolicy::Aggregate | ClientPathPolicy::UartSpillover => {
                            quic_lite::PathCapacity::new(egress.occupied(), egress.capacity())
                                .has_capacity()
                        }
                        ClientPathPolicy::Udp => false,
                        ClientPathPolicy::Uart => true,
                    };
                    match bridge.on_backend_datagram_on_path(&buffer[..used], uart) {
                        PathBridgeAction::ToBootstrapPath(packet) => {
                            primary_packets = primary_packets.saturating_add(1);
                            if let Some(peer) = bootstrap_peer {
                                socket
                                    .send_to(packet, peer)
                                    .map_err(|error| error.to_string())?;
                            }
                        }
                        PathBridgeAction::ToSecondaryPath(packet) => {
                            secondary_packets = secondary_packets.saturating_add(1);
                            let mut payload = [0u8; quic_lite::DEFAULT_MAX_DATAGRAM_SIZE + 1];
                            let used = encode_uart_datagram(packet, &mut payload)
                                .ok_or("UART packet too large")?;
                            let wire = encode_payload(
                                &payload[..used],
                                quic_lite::DEFAULT_MAX_DATAGRAM_SIZE + 1,
                            )
                            .map_err(|error| error.to_string())?;
                            debug_assert!(egress.enqueue(wire));
                        }
                        _ => {}
                    }
                }
                Ok((used, peer)) => {
                    bootstrap_peer = Some(peer);
                    if let PathBridgeAction::ToBackend(packet) =
                        bridge.on_bootstrap_path(&buffer[..used])
                    {
                        socket
                            .send_to(packet, backend)
                            .map_err(|error| error.to_string())?;
                    }
                }
                Err(error) if error.kind() == ErrorKind::WouldBlock => {}
                Err(error) => return Err(error.to_string()),
            }
        }
        match serial.read(&mut buffer) {
            Ok(used) if used != 0 => {
                for record in decoder
                    .push(&buffer[..used])
                    .map_err(|error| error.to_string())?
                {
                    match classify_uart_payload(&record) {
                        Ok(UartIngress::Transport(packet)) => {
                            egress.on_path_feedback();
                            if let PathBridgeAction::ToBackend(packet) =
                                bridge.on_secondary_path(packet)
                            {
                                socket
                                    .send_to(packet, backend)
                                    .map_err(|error| error.to_string())?;
                            }
                        }
                        Ok(UartIngress::Unmarked(packet)) => {
                            if let Some(record) =
                                dmesh_server::direct::ConnectionlessMessage::decode(packet)
                            {
                                eprintln!(
                                    "dmesh_device_record bearer=uart bytes={} {}",
                                    record.len(),
                                    render_device_record(&schema, record)
                                );
                            }
                        }
                        Err(_) => {}
                    }
                }
            }
            Ok(_) => {}
            Err(error) if error.kind() == ErrorKind::WouldBlock => {}
            Err(error) => return Err(error.to_string()),
        }
        let now_us = Instant::now().duration_since(started).as_micros() as u64;
        if let Some(wire) = egress.take_ready(now_us) {
            match serial.write(&wire) {
                Ok(written) if written == wire.len() => egress.completed_write(wire.len(), now_us),
                Ok(written) if written != 0 => egress.retry_front(wire[written..].to_vec(), now_us),
                Ok(_) => egress.retry_front(wire, now_us),
                Err(error) if error.kind() == ErrorKind::WouldBlock => {
                    egress.retry_front(wire, now_us)
                }
                Err(error) => return Err(error.to_string()),
            }
        }
        // Do not turn this packetized USB L2 into a millisecond-paced UART.
        // `egress.has_capacity()` is the actual bounded receiver feedback;
        // yield only to avoid monopolizing a host core while both descriptors
        // are empty.
        thread::yield_now();
    }
    Err("UART L2 bridge timed out".into())
}

/// Resolve a supervised host-radio control endpoint.  This is intentionally a
/// control-plane client, not a serial forwarder: `lmesh-wifi` or `lmesh` owns
/// NOW/NAN selection and returns its receiver-side counters in the response.
fn proxy_socket_target(target: &str) -> Option<&str> {
    match target {
        "lmesh://lmesh-wifi" => Some("/run/mesh/lmesh-wifi/mesh.sock"),
        "lmesh://lmesh" => Some("/run/mesh/lmesh/mesh.sock"),
        _ => target.strip_prefix("uds://"),
    }
}

fn proxy_request(
    method: &str,
    data: serde_json::Value,
    to: Option<String>,
) -> Result<serde_json::Value, String> {
    let mut data = data;
    if !data.is_object() {
        return Err("--data must be a JSON object".into());
    }
    let object = data.as_object_mut().expect("checked object");
    object.insert(
        "id".into(),
        serde_json::json!(format!("dmesh-cli-{}", fresh_request_id())),
    );
    object.insert(
        "method".into(),
        serde_json::Value::String(method.to_owned()),
    );
    if let Some(to) = to {
        object.insert("to".into(), serde_json::Value::String(to));
    }
    Ok(data)
}

/// Invoke one existing reviewed lmesh method over its JSONL UDS.  The CLI does
/// not interpret a successful host TX as peer success; it prints the service's
/// complete result, including NOW response/counter fields where applicable.
fn run_lmesh_proxy_client(arguments: &[String]) -> Result<(), String> {
    let target = arguments.first().ok_or("missing proxy target")?;
    let socket = proxy_socket_target(target).ok_or("invalid proxy target")?;
    let mut method = None;
    let mut to = None;
    let mut data = serde_json::json!({});
    let mut index = 1;
    while index < arguments.len() {
        match arguments[index].as_str() {
            "--method" => {
                index += 1;
                method = Some(
                    arguments
                        .get(index)
                        .ok_or("missing --method value")?
                        .clone(),
                );
            }
            "--data" => {
                index += 1;
                data = serde_json::from_str(arguments.get(index).ok_or("missing --data value")?)
                    .map_err(|error| format!("invalid --data JSON: {error}"))?;
            }
            "--to" => {
                index += 1;
                to = Some(arguments.get(index).ok_or("missing --to value")?.clone());
            }
            unknown => return Err(format!("unknown proxy argument {unknown}")),
        }
        index += 1;
    }
    let method = method.ok_or("proxy requests require --method METHOD")?;
    let request = proxy_request(&method, data, to)?;
    let mut stream =
        UnixStream::connect(socket).map_err(|error| format!("connect {socket}: {error}"))?;
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .map_err(|error| error.to_string())?;
    writeln!(stream, "{request}").map_err(|error| error.to_string())?;
    stream.flush().map_err(|error| error.to_string())?;
    let mut response = String::new();
    BufReader::new(stream)
        .read_line(&mut response)
        .map_err(|error| error.to_string())?;
    if response.trim().is_empty() {
        return Err(format!("proxy {socket} returned no response for {method}"));
    }
    println!(
        "dmesh_cli_proxy_response endpoint={socket} method={method} {}",
        response.trim()
    );
    Ok(())
}

/// Direct physical reset for the client that owns the serial port.  This is
/// intentionally outside any retired forwarding service.
fn reset_serial(path: &str) -> Result<(), String> {
    let file = open_serial(path)?;
    pulse_serial_reset(&file)?;
    println!("dmesh_cli_reset target={path} line=RTS pulse_ms=120");
    Ok(())
}

/// Pulse RTS while the caller retains exclusive ownership of the serial port.
///
/// A boot diagnostic watch must use this instead of the standalone reset
/// command: closing and reopening a CP210x port after the pulse can lose the
/// ROM, Stage2, and early Main records that explain an otherwise silent UART
/// bootstrap failure.  It is intentionally available only to the direct
/// physical UART client, never to a routed transport operation.
fn pulse_serial_reset(file: &File) -> Result<(), String> {
    // CP210x LoRa boards wire RTS to EN and DTR to GPIO0.  RTS is therefore
    // the only reset line; DTR must be released before it, otherwise a reset
    // can enter the ROM serial downloader rather than Stage2/Main.  A prior
    // flasher owns these lines and may have closed while DTR was asserted, so
    // do not rely on the port driver's inherited modem state here.
    let mut released = libc::TIOCM_DTR | libc::TIOCM_RTS;
    unsafe {
        if libc::ioctl(file.as_raw_fd(), libc::TIOCMBIC, &mut released) < 0 {
            return Err(std::io::Error::last_os_error().to_string());
        }
    }
    let mut rts = libc::TIOCM_RTS;
    unsafe {
        if libc::ioctl(file.as_raw_fd(), libc::TIOCMBIS, &mut rts) < 0 {
            return Err(std::io::Error::last_os_error().to_string());
        }
    }
    thread::sleep(Duration::from_millis(120));
    unsafe {
        if libc::ioctl(file.as_raw_fd(), libc::TIOCMBIC, &mut rts) < 0 {
            return Err(std::io::Error::last_os_error().to_string());
        }
    }
    Ok(())
}

fn send_uart_transport(serial: &mut File, packet: &[u8]) -> Result<(), String> {
    let mut marked = [0u8; quic_lite::DEFAULT_MAX_DATAGRAM_SIZE + 1];
    let used = encode_uart_datagram(packet, &mut marked).ok_or("UART packet too large")?;
    send_ppp(serial, &marked[..used])
}

/// The UART session is the sole serial owner. Direct records are never used
/// as services, but retaining them here makes the narrowly permitted
/// UART-QUIC diagnostic line visible when transport setup itself fails.
fn report_uart_direct_record(path: &str, record: &[u8], filter: &mut WatchTextFilter) {
    match core::str::from_utf8(record) {
        Ok(text) if filter.retain(text) => eprintln!("dmesh_uart_diagnostic target={path} {text}"),
        Ok(_) => {}
        Err(_) => eprintln!(
            "dmesh_uart_diagnostic target={path} nontext_record_bytes={} hex={}",
            record.len(),
            hex_encode(record)
        ),
    }
}

/// Observe line-oriented ASCII emitted outside PPP framing. This is only the
/// UART/QUIC-lite troubleshooting channel used for boot, crash, and narrow
/// transport diagnostics; normal firmware logs are still read through the
/// flow-controlled `log-watch` service.
///
/// A PPP delimiter discards an unfinished text candidate. Consecutive PPP
/// frames may share a delimiter, but their binary payload cannot produce a
/// line because non-printable bytes discard the candidate. Keeping this tap
/// in the host shell avoids giving raw text any role in the L2 protocol.
#[derive(Default)]
struct RawTextTap {
    line: Vec<u8>,
}

/// The ESP-IDF sniffer teardown diagnostic may repeat at a fixed cadence while
/// the radio settles.  Keep the first line for diagnosis but avoid drowning a
/// bounded boot watch in identical text.
#[derive(Default)]
struct WatchTextFilter {
    seen_disable_sniffer: bool,
    suppressed_disable_sniffer: u64,
}

impl WatchTextFilter {
    fn retain(&mut self, line: &str) -> bool {
        if line.contains("ic_disable_sniffer") {
            if self.seen_disable_sniffer {
                self.suppressed_disable_sniffer = self.suppressed_disable_sniffer.saturating_add(1);
                return false;
            }
            self.seen_disable_sniffer = true;
        }
        true
    }
}

impl RawTextTap {
    const MAX_LINE: usize = 512;

    fn push(&mut self, bytes: &[u8]) -> Vec<String> {
        let mut lines = Vec::new();
        for byte in bytes {
            match *byte {
                0x7e => self.line.clear(),
                b'\r' => {}
                b'\n' if !self.line.is_empty() => {
                    if let Ok(line) = String::from_utf8(core::mem::take(&mut self.line)) {
                        lines.push(line);
                    }
                }
                b'\n' => {}
                byte if byte.is_ascii_graphic() || byte == b' ' || byte == b'\t' => {
                    if self.line.len() < Self::MAX_LINE {
                        self.line.push(byte);
                    } else {
                        self.line.clear();
                    }
                }
                _ => self.line.clear(),
            }
        }
        lines
    }
}

/// Directly list a device's registered stream handlers through its UART L2.
/// This intentionally shares the exact bootstrap and request packets used by
/// the UDP client; only PPP framing and file I/O differ.
fn run_serial_stream_command(arguments: &[String]) -> Result<(), String> {
    let mut service_arguments = Vec::new();
    let mut baud = None;
    let mut index = 1;
    while index < arguments.len() {
        if arguments[index] == "--baud" {
            index += 1;
            baud = Some(
                arguments
                    .get(index)
                    .ok_or("missing --baud value")?
                    .parse::<u32>()
                    .map_err(|error| error.to_string())?,
            );
        } else {
            service_arguments.push(arguments[index].clone());
        }
        index += 1;
    }
    let command = service_arguments.join(" ");
    let body = encode_stream_command_with_id(&command, fresh_request_id())
        .map_err(|error| error.to_string())?;
    let path = arguments.first().ok_or("missing serial path")?;
    let tagged_probe = dmesh_server::tagged::decode(&body)
        .and_then(dmesh_server::probe::decode_probe_run_record)
        .map(|(_, request)| request);
    if let Some(request) = tagged_probe {
        let mut session = DeviceSession::open(path.clone(), baud)?;
        let result = session.probe_request(request)?;
        println!(
            "dmesh_cli_probe_result bearer=uart bytes={} normal_bytes={} high_bytes={} low_bytes={} elapsed_us={} bps={} tx_packets={} rx_packets={} retransmits={}",
            result.bytes,
            result.normal_bytes,
            result.high_bytes,
            result.low_bytes,
            result.elapsed_us,
            result.bps,
            result.tx_packets,
            result.rx_packets,
            result.retransmits,
        );
        return Ok(());
    }
    if let Some((_, flash)) = dmesh_server::verified_object::decode_flash_handler_request(&body) {
        let artifact_root = env::var_os("DMESH_OBJECT_ROOT")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("target/flash"));
        let (manifest, image) = dmesh_server::ObjectServer::new(dmesh_server::ServerConfig {
            artifact_root: artifact_root.clone(),
            ..dmesh_server::ServerConfig::default()
        })
        .response_object(flash.object)
        .map_err(|error| format!("object.flash artifact: {error}"))?;
        eprintln!(
            "dmesh_cli_object_upload bearer=uart association=single artifact_root={}",
            artifact_root.display()
        );
        let mut session = DeviceSession::open(path.clone(), baud)?;
        let result = session.object_upload(
            &body,
            dmesh_server::verified_object::ObjectBodyStream::from_object(manifest, image),
        )?;
        eprintln!(
            "dmesh_cli_object_upload_complete bearer=uart records={} bytes={} tx_packets={} rx_packets={} retransmits={}",
            result.records, result.bytes, result.tx_packets, result.rx_packets, result.retransmits
        );
        println!(
            "dmesh_cli_stream_command target={} stream={} fin=true bytes={} {}",
            path,
            quic_lite::FIRST_SERVER_BIDI_STREAM_ID,
            result.response.len(),
            render_device_record(&FirmwareSchema::load(), &result.response)
        );
        return Ok(());
    }
    let mut serial = open_serial(path)?;
    configure_serial(&serial, baud)?;
    run_serial_service_request(&mut serial, path, &body).map(|_| ())
}

/// Preserve the catalog's physical-UART contract when a node name resolved to
/// a serial path. Explicit serial paths remain deliberately literal: callers
/// can supply `--baud` themselves, while a named CP210x device must not be
/// silently treated as packetized USB-JTAG.
fn append_catalog_uart_baud(arguments: &mut Vec<String>, profile: &DeviceProfile) {
    if profile.uart_baud.is_some() && !arguments.iter().any(|argument| argument == "--baud") {
        arguments.push("--baud".to_owned());
        arguments.push(profile.uart_baud.expect("checked above").to_string());
    }
}

fn run_serial_direct_discovery(path: &str, baud: Option<u32>) -> Result<(), String> {
    let started = Instant::now();
    let mut session = DeviceSession::open(path, baud)?;
    let announce = session.check(Duration::from_secs(3))?;
    println!(
        "dmesh_direct_check target={} device={} elapsed_us={}",
        path,
        announce.device_name().unwrap_or("unknown"),
        started.elapsed().as_micros(),
    );
    Ok(())
}

/// Send exactly one unmarked PPP record and render any direct records returned
/// during a short bounded receive interval. This is the host counterpart of
/// `IngressKind::UartRaw`: it deliberately bypasses QUIC-lite while retaining
/// normal PPP framing, serial ownership, and schema rendering.
fn run_serial_direct_record(arguments: &[String]) -> Result<(), String> {
    let path = arguments.first().ok_or("missing serial path")?;
    let mut index = 1;
    let mut timeout = Duration::from_secs(2);
    let mut baud = None;
    let record = match arguments.get(index).map(String::as_str) {
        Some("--direct-hex") => {
            index += 1;
            hex(arguments.get(index).ok_or("missing --direct-hex value")?)?
        }
        Some("--msg") => {
            index += 1;
            let end = arguments[index..]
                .iter()
                .position(|argument| matches!(argument.as_str(), "--timeout-secs" | "--baud"))
                .map(|offset| index + offset)
                .unwrap_or(arguments.len());
            let command = arguments[index..end].join(" ");
            if command.is_empty() {
                return Err("missing --msg value".into());
            }
            index = end.saturating_sub(1);
            encode_direct_command_with_id(&command, fresh_request_id())
                .map_err(|error| error.to_string())?
        }
        _ => usage(),
    };
    index += 1;
    while index < arguments.len() {
        match arguments[index].as_str() {
            "--timeout-secs" => {
                index += 1;
                timeout = Duration::from_secs(
                    arguments
                        .get(index)
                        .ok_or("missing --timeout-secs value")?
                        .parse::<u64>()
                        .map_err(|error| error.to_string())?,
                );
            }
            "--baud" => {
                index += 1;
                baud = Some(
                    arguments
                        .get(index)
                        .ok_or("missing --baud value")?
                        .parse::<u32>()
                        .map_err(|error| error.to_string())?,
                );
            }
            argument => return Err(format!("raw record does not support {argument}")),
        }
        index += 1;
    }
    if record.is_empty() || record.len() > quic_lite::DEFAULT_MAX_DATAGRAM_SIZE - 6 {
        return Err("raw record is empty or exceeds the UART MTU".into());
    }
    let mut serial = open_serial(path)?;
    // CP210x boards expose a physical 8N1 UART while C6 USB-JTAG uses its
    // packetized driver cadence. Keep the former opt-in exactly as stream
    // requests do; direct schema-backed diagnostics must work on both.
    configure_serial(&serial, baud)?;
    // USB-JTAG retains diagnostic records across short-lived CLI owners. Do
    // not mistake that old backlog for the reply to the record below.
    let mut stale = [0u8; 256];
    loop {
        match serial.read(&mut stale) {
            Ok(used) if used != 0 => {}
            Ok(_) => break,
            Err(ref error) if error.kind() == ErrorKind::WouldBlock => break,
            Err(error) => return Err(error.to_string()),
        }
    }
    let mut packet = [0u8; quic_lite::DEFAULT_MAX_DATAGRAM_SIZE];
    let used = dmesh_server::direct::ConnectionlessMessage::encode(&record, &mut packet)
        .ok_or_else(|| "UART connectionless record exceeds the MTU".to_owned())?;
    send_ppp(&mut serial, &packet[..used])?;
    println!("dmesh_cli_raw_sent target={path} bytes={}", record.len());

    let schema = FirmwareSchema::load();
    let mut decoder = Decoder::with_max(quic_lite::DEFAULT_MAX_DATAGRAM_SIZE + 1);
    let mut buffer = [0u8; quic_lite::DEFAULT_MAX_DATAGRAM_SIZE + 1];
    let deadline = Instant::now() + timeout;
    let mut replies = 0u32;
    // Raw schema commands share the ESP console with stream requests. Keep
    // the repeated NAN sniffer teardown line from burying a bounded direct
    // response just as the service path does.
    let mut text_filter = WatchTextFilter::default();
    while Instant::now() < deadline {
        match serial.read(&mut buffer) {
            Ok(used) if used != 0 => {
                for frame in decoder
                    .push(&buffer[..used])
                    .map_err(|error| error.to_string())?
                {
                    if let Ok(UartIngress::Unmarked(packet)) = classify_uart_payload(&frame)
                        && let Some(record) =
                            dmesh_server::direct::ConnectionlessMessage::decode(packet)
                    {
                        let rendered = render_device_record(&schema, record);
                        if text_filter.retain(&rendered) {
                            println!("dmesh_cli_raw_reply bytes={} {rendered}", record.len());
                        }
                        replies = replies.saturating_add(1);
                    }
                }
            }
            Ok(_) => {
                thread::sleep(Duration::from_millis(10));
            }
            Err(error) if error.kind() == ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(10));
            }
            Err(error) => return Err(error.to_string()),
        }
    }
    if replies == 0 {
        Err("raw record response timeout".into())
    } else {
        if text_filter.suppressed_disable_sniffer != 0 {
            println!(
                "dmesh_cli_raw_suppressed text=ic_disable_sniffer count={}",
                text_filter.suppressed_disable_sniffer
            );
        }
        Ok(())
    }
}

/// Issue one bearer-neutral service request using an already-owned UART.
/// Interactive watch mode calls this so a tmux pane has exactly one serial
/// owner while it both renders diagnostics and accepts stream commands.
fn run_serial_service_request(
    serial: &mut File,
    path: &str,
    body: &[u8],
) -> Result<Option<SerialProbeResult>, String> {
    // Service requests can overlap normal ESP-IDF radio diagnostics. Apply
    // the same bounded sniffer-teardown filter as `--watch`, otherwise a
    // useful service response is buried under the identical idle line.
    let mut text_filter = WatchTextFilter::default();
    let cid = fresh_connection_id()?;
    let limits = ConnectionLimits::default();
    // UART is frame I/O only. Keep bootstrap/CID/packet state in the same
    // quic-lite association used by UDP and NOW adapters.
    let uart_path = PathId::new(1).expect("static UART path ID is nonzero");
    let mut connection =
        ClientAssociation::<8, { quic_lite::DEFAULT_MAX_DATAGRAM_SIZE }>::with_limits(cid, limits);
    connection.select_path(uart_path);
    let mut open = [0u8; quic_lite::DEFAULT_MAX_DATAGRAM_SIZE];
    let (_, open_used) = connection
        .start(&mut open)
        .map_err(|error| format!("UART bootstrap OPEN: {error:?}"))?;
    send_uart_transport(serial, &open[..open_used])?;

    let mut decoder = Decoder::with_max(quic_lite::DEFAULT_MAX_DATAGRAM_SIZE + 1);
    let mut buffer = [0u8; quic_lite::DEFAULT_MAX_DATAGRAM_SIZE + 1];
    let bootstrap_deadline = Instant::now() + Duration::from_secs(3);
    'bootstrap: loop {
        if Instant::now() >= bootstrap_deadline {
            return Err("UART bootstrap timeout (no transport ACK)".into());
        }
        match serial.read(&mut buffer) {
            Ok(used) if used != 0 => {
                for record in decoder
                    .push(&buffer[..used])
                    .map_err(|error| error.to_string())?
                {
                    let packet = match classify_uart_payload(&record) {
                        Ok(UartIngress::Transport(packet)) => packet,
                        Ok(UartIngress::Unmarked(packet)) => {
                            if let Some(record) =
                                dmesh_server::direct::ConnectionlessMessage::decode(packet)
                            {
                                report_uart_direct_record(path, record, &mut text_filter);
                            }
                            continue;
                        }
                        Err(_) => continue,
                    };
                    // A stateless reset is intentionally not a valid short
                    // header. Recognize the issued token before filtering
                    // stale UART frames so a rebooted peer reports immediate
                    // association recovery instead of a bootstrap timeout.
                    if connection.is_peer_stateless_reset(packet) {
                        return Err("UART bootstrap: peer restarted".into());
                    }
                    if connection.receive_open_ack(uart_path, packet, 0).is_ok() {
                        break 'bootstrap;
                    }
                }
            }
            Ok(_) => thread::yield_now(),
            Err(error) if error.kind() == ErrorKind::WouldBlock => thread::yield_now(),
            Err(error) => return Err(error.to_string()),
        }
    }

    connection
        .continue_packet_numbers_from(1)
        .map_err(|error| format!("UART bootstrap packet numbers: {error:?}"))?;
    let stream_id = connection
        .allocate_client_bidi_stream()
        .map_err(|error| format!("UART service stream: {error:?}"))?;
    let mut packet = [0u8; quic_lite::DEFAULT_MAX_DATAGRAM_SIZE];
    let (_path, used) = connection
        .encode_stream_payload(stream_id, body, true, &mut packet)
        .map_err(|error| format!("UART service request: {error:?}"))?;
    send_uart_transport(serial, &packet[..used])?;

    let response_deadline = Instant::now() + Duration::from_secs(3);
    loop {
        if Instant::now() >= response_deadline {
            return Err("UART services timeout (no stream response)".into());
        }
        match serial.read(&mut buffer) {
            Ok(used) if used != 0 => {
                for record in decoder
                    .push(&buffer[..used])
                    .map_err(|error| error.to_string())?
                {
                    let packet = match classify_uart_payload(&record) {
                        Ok(UartIngress::Transport(packet)) => packet,
                        Ok(UartIngress::Unmarked(packet)) => {
                            if let Some(record) =
                                dmesh_server::direct::ConnectionlessMessage::decode(packet)
                            {
                                report_uart_direct_record(path, record, &mut text_filter);
                            }
                            continue;
                        }
                        Err(_) => continue,
                    };
                    let received = connection
                        .receive_stream_payload(uart_path, packet)
                        .map_err(|error| format!("UART response packet: {error:?}"))?;
                    let Some((stream_id, _offset, fin, data)) = received else {
                        continue;
                    };
                    connection
                        .stream_consumed(stream_id, data.len(), false)
                        .map_err(|error| format!("UART response accounting: {error:?}"))?;
                    let mut ack = [0u8; quic_lite::DEFAULT_MAX_DATAGRAM_SIZE];
                    if let Some((_path, ack_len)) = connection
                        .poll_transmit(&mut ack)
                        .map_err(|error| format!("UART response ACK: {error:?}"))?
                    {
                        send_uart_transport(serial, &ack[..ack_len])?;
                    }
                    if stream_id == quic_lite::FIRST_SERVER_BIDI_STREAM_ID {
                        // A one-shot CLI service request must retire its
                        // association before closing the UART FD.  Keeping
                        // the close inside QUIC-lite prevents a serial
                        // command from consuming the firmware's bounded
                        // multi-peer association table.
                        if let Some((_close_path, close_used)) = connection
                            .poll_close(&mut ack)
                            .map_err(|error| format!("UART service close: {error:?}"))?
                        {
                            send_uart_transport(serial, &ack[..close_used])?;
                        }
                        println!(
                            "dmesh_cli_stream_command target={} stream={} fin={} bytes={} {}",
                            path,
                            stream_id,
                            fin,
                            data.len(),
                            render_device_record(&FirmwareSchema::load(), &data)
                        );
                        return Ok(None);
                    }
                }
            }
            Ok(_) => thread::yield_now(),
            Err(error) if error.kind() == ErrorKind::WouldBlock => thread::yield_now(),
            Err(error) => return Err(error.to_string()),
        }
    }
}

/// Passively render direct UART records from boot/platform code. This does
/// not open a service stream and never substitutes for tagged `log-watch`:
/// firmware logs belong on that flow-controlled stream. Marked QUIC-lite
/// packets are reported only as transport observations, never decoded as
/// boot text or direct CBOR.
fn run_serial_watch(arguments: &[String]) -> Result<(), String> {
    let path = arguments.first().ok_or("missing serial path")?;
    if arguments
        .get(1)
        .is_none_or(|argument| argument != "--watch")
    {
        return Err("serial watch requires --watch immediately after the target".into());
    }
    let mut baud = None;
    let mut timeout = Duration::from_secs(90);
    let mut interactive = false;
    let mut reset_after_open = false;
    let mut index = 2;
    while index < arguments.len() {
        match arguments[index].as_str() {
            "--interactive" => interactive = true,
            // Keep the serial file open while resetting so the following
            // watch captures ROM, Stage2, and Main output. This is a
            // troubleshooting-only opt-in; a normal watch never toggles a
            // modem-control line.
            "--reset" => reset_after_open = true,
            "--baud" => {
                index += 1;
                baud = Some(
                    arguments
                        .get(index)
                        .ok_or("missing --baud value")?
                        .parse::<u32>()
                        .map_err(|error| error.to_string())?,
                );
            }
            "--timeout-secs" => {
                index += 1;
                timeout = Duration::from_secs(
                    arguments
                        .get(index)
                        .ok_or("missing --timeout-secs value")?
                        .parse::<u64>()
                        .map_err(|error| error.to_string())?,
                );
            }
            unknown => return Err(format!("unknown serial watch argument {unknown}")),
        }
        index += 1;
    }
    let mut serial = open_serial(path)?;
    configure_serial(&serial, baud)?;
    // Print the resolved physical contract before touching RTS.  A board name
    // has already been expanded to this exact `/dev/serial/by-id` path, and
    // an explicit baud makes a CP210x capture reproducible instead of relying
    // on whichever termios settings a prior owner left behind.  `None` is the
    // intentional packetized-native-USB case (for example C6 USB-JTAG).
    println!(
        "dmesh_uart_watch_open target={path} baud={}",
        baud.map_or("driver-default".to_owned(), |value| value.to_string())
    );
    if reset_after_open {
        pulse_serial_reset(&serial)?;
        println!("dmesh_uart_watch_reset target={path} line=RTS pulse_ms=120");
    }
    if interactive {
        unsafe {
            let flags = libc::fcntl(std::io::stdin().as_raw_fd(), libc::F_GETFL);
            if flags < 0
                || libc::fcntl(
                    std::io::stdin().as_raw_fd(),
                    libc::F_SETFL,
                    flags | libc::O_NONBLOCK,
                ) != 0
            {
                return Err(std::io::Error::last_os_error().to_string());
            }
        }
        eprintln!("dmesh_uart_interactive commands=SERVICE [field=value ...]|quit");
    }
    let schema = FirmwareSchema::load();
    let mut decoder = Decoder::with_max(quic_lite::DEFAULT_MAX_DATAGRAM_SIZE + 1);
    let mut raw_text = RawTextTap::default();
    let mut text_filter = WatchTextFilter::default();
    let mut buffer = [0u8; quic_lite::DEFAULT_MAX_DATAGRAM_SIZE + 1];
    let mut direct_records = 0u64;
    let mut transport_packets = 0u64;
    let mut received_bytes = 0u64;
    let mut stdin_buffer = String::new();
    let mut stdin_bytes = [0u8; 256];
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if interactive {
            match std::io::stdin().read(&mut stdin_bytes) {
                Ok(used) if used != 0 => {
                    stdin_buffer.push_str(&String::from_utf8_lossy(&stdin_bytes[..used]));
                    while let Some(newline) = stdin_buffer.find('\n') {
                        let line = stdin_buffer[..newline].trim().to_owned();
                        stdin_buffer.drain(..=newline);
                        if line.is_empty() {
                            continue;
                        }
                        if line == "quit" || line == "exit" {
                            println!("dmesh_uart_interactive exit");
                            return Ok(());
                        }
                        match parse_interactive_service_command(&line).and_then(|body| {
                            run_serial_service_request(&mut serial, path, &body).map(|_| ())
                        }) {
                            Ok(()) => {}
                            Err(error) => eprintln!("dmesh_uart_interactive error={error}"),
                        }
                    }
                }
                Ok(_) => {}
                Err(error) if error.kind() == ErrorKind::WouldBlock => {}
                Err(error) => return Err(error.to_string()),
            }
        }
        match serial.read(&mut buffer) {
            Ok(used) if used != 0 => {
                received_bytes = received_bytes.saturating_add(used as u64);
                for line in raw_text.push(&buffer[..used]) {
                    if text_filter.retain(&line) {
                        println!(
                            "dmesh_uart_watch_text {}",
                            serde_json::to_string(&line).unwrap()
                        );
                    }
                }
                for record in decoder
                    .push(&buffer[..used])
                    .map_err(|error| error.to_string())?
                {
                    match classify_uart_payload(&record) {
                        Ok(UartIngress::Unmarked(packet)) => {
                            if let Some(record) =
                                dmesh_server::direct::ConnectionlessMessage::decode(packet)
                            {
                                direct_records = direct_records.saturating_add(1);
                                println!(
                                    "dmesh_uart_watch_record bytes={} {}",
                                    record.len(),
                                    render_device_record(&schema, record)
                                );
                            }
                        }
                        Ok(UartIngress::Transport(packet)) => {
                            transport_packets = transport_packets.saturating_add(1);
                            // UART watch is a frame observer, not a second
                            // QUIC parser. CID/packet diagnostics come from
                            // the association owner through normal status.
                            println!("dmesh_uart_watch_transport bytes={}", packet.len());
                        }
                        Err(_) => {}
                    }
                }
            }
            Ok(_) => thread::sleep(Duration::from_millis(1)),
            Err(error) if error.kind() == ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(1))
            }
            Err(error) => return Err(error.to_string()),
        }
    }
    println!(
        "dmesh_uart_watch_timeout received_bytes={received_bytes} direct_records={direct_records} transport_packets={transport_packets}"
    );
    if text_filter.suppressed_disable_sniffer != 0 {
        println!(
            "dmesh_uart_watch_suppressed text=ic_disable_sniffer count={}",
            text_filter.suppressed_disable_sniffer
        );
    }
    // A passive watch may legitimately see nothing.  A watch that explicitly
    // performed the reset cannot: no byte at all means the ROM/Stage2/Main
    // serial path was not observed, so returning success would hide the exact
    // boot regression this diagnostic mode exists to expose.
    if reset_after_open && received_bytes == 0 {
        return Err(format!(
            "UART reset capture received no bytes target={path} baud={}; ROM, Stage2, or Main serial output was not observed",
            baud.map_or("driver-default".to_owned(), |value| value.to_string())
        ));
    }
    Ok(())
}

/// Line-oriented command vocabulary for a serial watch pane.  It intentionally
/// uses the same schema-driven tagged request as one-shot UART and UDP calls.
fn parse_interactive_service_command(line: &str) -> Result<Vec<u8>, String> {
    let command = line.split_whitespace().next().ok_or("empty command")?;
    if !FirmwareSchema::load().is_stream_command_name(command) {
        return Err(format!("unknown schema service {command}"));
    }
    let record = encode_stream_command_with_id(line, fresh_request_id())
        .map_err(|error| error.to_string())?;
    Ok(record)
}

/// Execute one service operation directly over the UDP QUIC-lite bearer.
/// This is intentionally the same `UdpClient` used by the host transport
/// tests: a command client has no raw UDP fallback or UART-specific schema.
/// Long-lived log subscription delivery is not enabled yet; `log-watch` is a
/// bounded record poll until the server-side framed subscription is added.
fn run_udp_service_client(arguments: &[String]) -> Result<(), String> {
    let (arguments, object_file) = split_object_file_argument(arguments)?;
    let peer = arguments
        .first()
        .and_then(|target| target.strip_prefix("udp://"))
        .ok_or("UDP target must use udp://HOST:PORT")?;
    let peer = parse_udp_peer(peer)?;
    let mut session_socket = None;
    let mut relay_forward_dcid = None;
    let mut relay_reverse_dcid = None;
    let mut relay_next_mac = None;
    let mut relay_allocation = 1u64;
    let tagged_command = arguments
        .get(1)
        .filter(|command| FirmwareSchema::load().is_stream_command_name(command))
        .map(|_| encode_stream_command_with_id(&arguments[1..].join(" "), fresh_request_id()))
        .transpose()
        .map_err(|error| error.to_string())?;
    let mut index = if tagged_command.is_some() {
        arguments.len()
    } else {
        1
    };
    while index < arguments.len() {
        match arguments[index].as_str() {
            "--socket" => {
                index += 1;
                session_socket = Some(
                    arguments
                        .get(index)
                        .ok_or("missing --socket value")?
                        .clone(),
                );
            }
            "--relay-forward-dcid" => {
                index += 1;
                relay_forward_dcid = Some(
                    arguments
                        .get(index)
                        .ok_or("missing --relay-forward-dcid value")?
                        .parse::<u64>()
                        .map_err(|error| error.to_string())?,
                );
            }
            "--relay-reverse-dcid" => {
                index += 1;
                relay_reverse_dcid = Some(
                    arguments
                        .get(index)
                        .ok_or("missing --relay-reverse-dcid value")?
                        .parse::<u64>()
                        .map_err(|error| error.to_string())?,
                );
            }
            "--relay-next-mac" => {
                index += 1;
                relay_next_mac = Some(
                    arguments
                        .get(index)
                        .ok_or("missing --relay-next-mac value")?
                        .clone(),
                );
            }
            "--relay-allocation" => {
                index += 1;
                relay_allocation = arguments
                    .get(index)
                    .ok_or("missing --relay-allocation value")?
                    .parse::<u64>()
                    .map_err(|error| error.to_string())?;
            }
            _ => return Err(format!("unknown UDP client argument {}", arguments[index])),
        }
        index += 1;
    }
    if let Some(socket_path) = session_socket {
        if tagged_command.is_some()
            || relay_forward_dcid.is_some()
            || relay_reverse_dcid.is_some()
            || relay_next_mac.is_some()
        {
            return Err("--socket cannot be combined with a one-shot or relay request".into());
        }
        return serve_udp_session_socket(peer, Path::new(&socket_path));
    }
    let request = tagged_command
        .ok_or("missing schema service; use dmesh-cli NODE SERVICE [field=value ...]")?;
    let tagged_probe = dmesh_server::tagged::decode(&request)
        .and_then(dmesh_server::probe::decode_probe_run_record)
        .map(|(_, request)| request);
    let probe_request = tagged_probe;
    // `object.flash` uses one client association with a command and an
    // ordered object-record stream. The CLI never starts a reverse UDP
    // server or a second association.
    let object_flash =
        dmesh_server::verified_object::decode_flash_handler_request(&request).is_some();
    // Firmware update is deliberately conservative by default: Recovery may
    // pause Wi-Fi while erasing flash, whereas the board's normal relay and
    // module traffic does not use this stream operation. The host can raise
    // this association-only profile explicitly for capability/stress tests.
    let requested_peer_receive_profile = if object_flash {
        requested_peer_receive_profile_from_env()?
    } else {
        None
    };
    let relay = match (relay_forward_dcid, relay_reverse_dcid, relay_next_mac) {
        (None, None, None) => None,
        (Some(forward), Some(reverse), Some(next_mac)) => Some((
            quic_lite::ConnectionId::new(forward).ok_or("invalid relay forward DCID")?,
            quic_lite::ConnectionId::new(reverse).ok_or("invalid relay reverse DCID")?,
            next_mac,
        )),
        _ => return Err("relay mode requires forward DCID, reverse DCID, and next MAC".into()),
    };
    if object_flash && relay.is_some() {
        return Err("object.flash cannot be combined with relay mode".into());
    }
    // This CID is owned by dmesh-cli and remains stable across relay alias
    // allocation. It is never a relay allocation.
    let cid = fresh_connection_id()?;
    let relay_pair = if let Some((forward, reverse, next_mac)) = relay.as_ref() {
        let revision = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|error| error.to_string())?
            .as_micros()
            .min(u128::from(u64::MAX - 1)) as u64;
        let reverse_allocation = relay_allocation
            .checked_add(1)
            .ok_or("relay reverse allocation overflow")?;
        let pair = format!(
            "relay.pair forward_allocation={relay_allocation} reverse_allocation={reverse_allocation} revision={revision} forward_dcid={} reverse_dcid={} client_dcid={} position=1 return_token={relay_allocation} next_mac={next_mac}",
            forward.value(),
            reverse.value(),
            cid.value(),
        );
        let request = encode_direct_command_with_id(&pair, fresh_request_id())
            .map_err(|error| error.to_string())?;
        let response = exchange_udp_stream_record(peer, &request)?;
        let response = dmesh_server::tagged::decode(&response)
            .ok_or("relay pair response is not tagged CBOR")?;
        if response.error.is_some() {
            return Err("relay pair returned an error".into());
        }
        let observed = dmesh_server::relay::decode_observed_pair(
            response.result.ok_or("relay pair response has no result")?,
        )
        .ok_or("relay pair response has invalid aliases")?;
        eprintln!(
            "dmesh_udp_relay_pair requested_forward={} requested_reverse={} forward_dcid={} reverse_dcid={} client_dcid={}",
            forward.value(),
            reverse.value(),
            observed.forward.local_dcid.unwrap().value(),
            observed.reverse.local_dcid.unwrap().value(),
            cid.value(),
        );
        Some((revision, observed))
    } else {
        None
    };
    let schema = FirmwareSchema::load();
    let runtime = tokio::runtime::Runtime::new().map_err(|error| error.to_string())?;
    runtime.block_on(async move {
        // `object.flash` is one QUIC-lite association with its command and
        // object streams. Do not first bootstrap UdpClient's legacy upload
        // loop: ObjectUploadClient is the shared stream owner used by UART
        // and UDP alike.
        if object_flash {
            let (_, flash) = dmesh_server::verified_object::decode_flash_handler_request(&request)
                .ok_or("invalid object.flash request")?;
            let (manifest, image, artifact) = flash_upload_object(flash.object, object_file.as_deref())?;
            eprintln!(
                "dmesh_cli_object_upload bearer=udp association=single artifact={}",
                artifact.display()
            );
            let result = udp_object_upload(
                peer,
                cid,
                &request,
                dmesh_server::verified_object::ObjectBodyStream::from_object(manifest, image),
                requested_peer_receive_profile,
            )
            .await?;
            eprintln!(
                "dmesh_cli_object_upload_complete bearer=udp records={} bytes={} elapsed_ms={} tx_packets={} rx_packets={} retransmits={}",
                result.records,
                result.bytes,
                result.elapsed_ms,
                result.tx_packets,
                result.rx_packets,
                result.retransmits
            );
            flash_upload_success(&result.response)?;
            println!(
                "dmesh_cli_stream_command target={peer} stream={} fin=true bytes={} {}",
                quic_lite::FIRST_SERVER_BIDI_STREAM_ID,
                result.response.len(),
                render_device_record(&schema, &result.response)
            );
            return Ok(());
        }
        let mut client = if let Some((_, observed)) = relay_pair {
            dmesh_server::udp::UdpClient::connect_with_quic_lite_wire_dcid(
                udp_bind_for_peer(peer),
                peer,
                cid,
                observed.forward.local_dcid.unwrap(),
            )
            .await
        } else {
            dmesh_server::udp::UdpClient::connect(udp_bind_for_peer(peer), peer, cid).await
        }
        .map_err(|error| error.to_string())?;
        if let Some((pair_revision, observed)) = relay_pair {
            let (_, _, next_mac) = relay.as_ref().expect("relay pair has relay options");
            let forward = observed.forward.local_dcid.unwrap();
            let reverse = observed.reverse.local_dcid.unwrap();
            let server_cid = client
                .peer_connection_id()
                .ok_or("relayed bootstrap did not install server CID")?;
            eprintln!(
                "dmesh_udp_relay_bootstrap forward_dcid={} reverse_dcid={} server_dcid={}",
                forward.value(),
                reverse.value(),
                server_cid.value()
            );
            let revision = pair_revision
                .checked_add(1)
                .ok_or("missing relay pair revision")?;
            let update = encode_direct_command_with_id(
                &format!(
                    "relay.apply allocation={relay_allocation} revision={revision} inbound_dcid={} outbound_dcid={} position=1 next_mac={next_mac}",
                    forward.value(),
                    server_cid.value()
                ),
                fresh_request_id(),
            )
            .map_err(|error| error.to_string())?;
            let mut update_control = dmesh_server::udp::UdpClient::connect(
                udp_bind_for_peer(peer),
                peer,
                fresh_connection_id()?,
            )
                .await
                .map_err(|error| error.to_string())?;
            let (_, update_response, update_fin) = update_control
                .request_stream(quic_lite::FIRST_CLIENT_BIDI_STREAM_ID, &update, true)
                .await
                .map_err(|error| error.to_string())?;
            if !update_fin {
                return Err("relay update stream did not finish".into());
            }
            let update_record = dmesh_server::tagged::decode(&update_response)
                .ok_or("relay update response is not tagged CBOR")?;
            if update_record.error.is_some() {
                return Err("relay update returned an error".into());
            }
            eprintln!(
                "dmesh_udp_relay_updated forward_dcid={} outbound_dcid={}",
                forward.value(),
                server_cid.value()
            );
        }
        if let Some(probe_request) = probe_request {
            client.set_deferred_receive_credit(true);
            let started = Instant::now();
            let mut frame = client
                .request_stream_frame(quic_lite::FIRST_CLIENT_BIDI_STREAM_ID, &request, true)
                .await
                .map_err(|error| error.to_string())?;
            // A priority scheduler may legitimately emit the high stream
            // before the first normal stream. The service stream map is
            // protocol-defined, so never infer its base from arrival order.
            let first_stream = quic_lite::FIRST_SERVER_BIDI_STREAM_ID;
            let plan = ProbeServicePlan::from_request(
                probe_request,
                quic_lite::DEFAULT_MAX_DATAGRAM_SIZE - 32,
            );
            let mut receiver = ProbeRun::<{ dmesh_server::probe::PROBE_MAX_NORMAL_STREAMS }>::new(
                2,
                plan.normal_streams,
                plan.high_priority_bytes != 0,
                plan.low_priority_bytes != 0,
            );
            loop {
                let stream = StreamFrame {
                    id: frame.id,
                    offset: frame.offset,
                    fin: frame.fin,
                    data: &frame.data,
                };
                let (complete, _) = receiver
                    .handle(first_stream, stream)
                    .map_err(|_| "UDP probe payload validation failed")?;
                if complete {
                    let elapsed = started.elapsed();
                    let bytes = receiver.bytes();
                    let transport = client.transport_stats();
                    let bps = if elapsed.is_zero() {
                        0
                    } else {
                        bytes.saturating_mul(8).saturating_mul(1_000_000)
                            / elapsed.as_micros().max(1) as u64
                    };
                    println!(
                        "dmesh_cli_probe_result bearer=udp target={peer} stream={first_stream} bytes={bytes} normal_bytes={} high_bytes={} low_bytes={} elapsed_us={} bps={bps} callback_errors={:?} received_datagrams={} duplicate_datagrams={} out_of_order_datagrams={} inferred_missing_packets={} retransmitted_datagrams={} loss_retransmits={} pto_retransmits={}",
                        receiver.normal_bytes(),
                        receiver.high_bytes(),
                        receiver.low_bytes(),
                        elapsed.as_micros(),
                        receiver.callback_errors(),
                        transport.received_datagrams,
                        transport.duplicate_datagrams,
                        transport.out_of_order_datagrams,
                        transport.inferred_missing_packets,
                        transport.retransmitted_datagrams,
                        transport.loss_retransmitted_datagrams,
                        transport.pto_retransmitted_datagrams,
                    );
                    // dmesh-cli owns this one-shot association.  Retire it
                    // explicitly before the process exits so an embedded
                    // peer with one active dispatcher can immediately admit
                    // lmesh's retained association on another path.
                    client.close(0).await.map_err(|error| error.to_string())?;
                    return Ok(());
                }
                frame = tokio::time::timeout(Duration::from_secs(30), client.recv_stream_frame())
                    .await
                    .map_err(|_| "UDP probe receive timeout")?
                    .map_err(|error| error.to_string())?;
            }
        }
        let flash_response = if object_flash {
            let (_, flash) = dmesh_server::verified_object::decode_flash_handler_request(&request)
                .ok_or("invalid object.flash request")?;
            let artifact_root = env::var_os("DMESH_OBJECT_ROOT")
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("target/flash"));
            let (manifest, image) = dmesh_server::ObjectServer::new(dmesh_server::ServerConfig {
                artifact_root: artifact_root.clone(),
                ..dmesh_server::ServerConfig::default()
            })
            .response_object(flash.object)
            .map_err(|error| format!("object.flash artifact: {error}"))?;
            let mut object = dmesh_server::verified_object::ObjectBodyStream::from_object(manifest, image);
            // The C6 raw-UDP6 adapter currently proves a 256-byte payload
            // envelope on this STA link.  This is only QUIC-lite stream
            // packet sizing; object record framing and recovery remain
            // bearer-neutral.
            let mut chunk = [0u8; 256];
            eprintln!(
                "dmesh_cli_object_upload association=single artifact_root={}",
                artifact_root.display()
            );

            let response = client
                .request_object_upload(
                    &request,
                    &mut object,
                    &mut chunk,
                    Duration::from_secs(300),
                )
                .await
                .map_err(|error| error.to_string())?;
            eprintln!(
                "dmesh_cli_object_upload_complete records={} bytes={}",
                object.record_index(),
                object.sent_bytes()
            );
            Ok((response.id, response.data, response.fin))
        } else {
            client
                .request_stream(quic_lite::FIRST_CLIENT_BIDI_STREAM_ID, &request, true)
                .await
        };
        let (stream, response, fin) = flash_response.map_err(|error| error.to_string())?;
        // A direct UDP CLI command is deliberately a one-shot client, unlike
        // lmesh's per-device association manager.  Send QUIC CLOSE while the
        // shared fixed-port socket is still alive; dropping it alone leaves a
        // firmware peer pinned to this transient CID until its idle timeout.
        client.close(0).await.map_err(|error| error.to_string())?;
        println!(
            "dmesh_cli_stream_command target={peer} stream={stream} fin={fin} bytes={} {}",
            response.len(),
            render_device_record(&schema, &response)
        );
        Ok(())
    })
}

/// Remove the CLI-only object source selector before schema encoding.  A
/// source path is host policy, not a firmware command field, so it must never
/// be sent to the device or become part of the signed object manifest.
fn split_object_file_argument(
    arguments: &[String],
) -> Result<(Vec<String>, Option<PathBuf>), String> {
    let mut retained = Vec::with_capacity(arguments.len());
    let mut object_file = None;
    let mut index = 0;
    while index < arguments.len() {
        if arguments[index] == "--file" {
            let value = arguments.get(index + 1).ok_or("missing --file path")?;
            if object_file.replace(PathBuf::from(value)).is_some() {
                return Err("object.flash accepts only one --file path".into());
            }
            index += 2;
        } else {
            retained.push(arguments[index].clone());
            index += 1;
        }
    }
    Ok((retained, object_file))
}

fn flash_upload_object(
    object: dmesh_server::verified_object::GetRequest<'_>,
    source: Option<&Path>,
) -> Result<(Vec<u8>, Vec<u8>, PathBuf), String> {
    let artifact_root = env::var_os("DMESH_OBJECT_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("target/flash"));
    let server = dmesh_server::ObjectServer::new(dmesh_server::ServerConfig {
        artifact_root,
        ..dmesh_server::ServerConfig::default()
    });
    if let Some(source) = source {
        let source = source.to_path_buf();
        let (manifest, image) = server
            .response_file(object, &source)
            .map_err(|error| format!("object.flash artifact: {error}"))?;
        Ok((manifest, image, source))
    } else {
        let (manifest, image) = server
            .response_object(object)
            .map_err(|error| format!("object.flash artifact: {error}"))?;
        Ok((manifest, image, server.config.artifact_root.clone()))
    }
}

fn flash_upload_success(response: &[u8]) -> Result<(), String> {
    let record = dmesh_server::tagged::decode(response)
        .ok_or("object.flash completed without a tagged terminal response")?;
    let result = record
        .result
        .ok_or("object.flash terminal response was not successful")?;
    let mut decoder = dmesh_server::cbor::Decoder::new(result);
    if decoder.text_ref() != Some(&b"flash complete"[..]) || !decoder.is_finished() {
        return Err("object.flash terminal response was not `flash complete`".into());
    }
    println!("SUCCESS object.flash complete");
    Ok(())
}

struct UdpObjectUploadResult {
    response: Vec<u8>,
    records: usize,
    bytes: usize,
    elapsed_ms: u64,
    tx_packets: u64,
    rx_packets: u64,
    retransmits: u64,
}

/// Move complete UDP datagrams for the bearer-neutral object client.  The
/// adapter has no stream, ACK, loss, or flow-control policy of its own.
async fn udp_object_upload(
    peer: SocketAddr,
    cid: quic_lite::ConnectionId,
    command: &[u8],
    records: dmesh_server::verified_object::ObjectBodyStream,
    requested_peer_receive_profile: Option<quic_lite::ReceiveWindowRequest>,
) -> Result<UdpObjectUploadResult, String> {
    // A token-verified peer restart means this association was discarded. It
    // is safe to repeat the idempotent object request only on a fresh CID;
    // never continue its packets or streams on the retired association.
    const PEER_RESTART_ATTEMPTS: usize = 3;
    let mut cid = cid;
    for attempt in 0..PEER_RESTART_ATTEMPTS {
        match udp_object_upload_once(
            peer,
            cid,
            command,
            records.clone(),
            requested_peer_receive_profile,
        )
        .await
        {
            Ok(result) => return Ok(result),
            Err(error)
                if error.contains("PeerRestarted") && attempt + 1 < PEER_RESTART_ATTEMPTS =>
            {
                let delay = Duration::from_millis(100_u64 << attempt);
                eprintln!(
                    "dmesh_cli_object_upload_peer_restarted attempt={} retry_in_ms={}",
                    attempt + 1,
                    delay.as_millis()
                );
                tokio::time::sleep(delay).await;
                cid = fresh_connection_id()?;
            }
            Err(error) => return Err(error),
        }
    }
    unreachable!("bounded retry loop returns on its final attempt")
}

async fn udp_object_upload_once(
    peer: SocketAddr,
    cid: quic_lite::ConnectionId,
    command: &[u8],
    records: dmesh_server::verified_object::ObjectBodyStream,
    requested_peer_receive_profile: Option<quic_lite::ReceiveWindowRequest>,
) -> Result<UdpObjectUploadResult, String> {
    let bind = udp_bind_for_peer(peer);
    let socket = match tokio::net::UdpSocket::bind(bind).await {
        Ok(socket) => socket,
        Err(error) if error.kind() == ErrorKind::AddrInUse => {
            // Keep 3338 as the reproducible default, but do not let an
            // unrelated direct diagnostic monopolize every independent
            // QUIC association. The selected UDP peer and the association
            // DCID remain unchanged when the OS assigns a source port.
            let ephemeral: SocketAddr = match peer {
                SocketAddr::V4(_) => "0.0.0.0:0".parse().expect("valid IPv4 wildcard"),
                SocketAddr::V6(_) => "[::]:0".parse().expect("valid IPv6 wildcard"),
            };
            tokio::net::UdpSocket::bind(ephemeral)
                .await
                .map_err(|fallback| {
                    format!("UDP bind {bind} busy ({error}); ephemeral fallback: {fallback}")
                })?
        }
        Err(error) => return Err(error.to_string()),
    };
    let mut client = dmesh_server::transport::ObjectUploadClient::<
        512,
        { quic_lite::DEFAULT_MAX_DATAGRAM_SIZE },
    >::new(cid, command, records)
    .map_err(|error| format!("object upload client: {error:?}"))?;
    if let Some(profile) = requested_peer_receive_profile {
        client
            .set_requested_peer_receive_profile(profile)
            .map_err(|error| format!("object upload peer receive profile: {error:?}"))?;
        eprintln!(
            "dmesh_cli_object_upload_requested_peer_receive max_data={} max_stream_data={}",
            profile.max_data, profile.max_stream_data
        );
    }
    let started = Instant::now();
    let deadline = started + object_upload_timeout();
    let mut driver = quic_lite::DatagramClientDriver::start(&mut client, 0)
        .map_err(|error| format!("object upload OPEN: {error:?}"))?;
    socket
        .send_to(
            driver.packet().expect("started object upload has OPEN"),
            peer,
        )
        .await
        .map_err(|error| error.to_string())?;
    driver.mark_sent(0);
    let mut input = [0u8; quic_lite::DEFAULT_MAX_DATAGRAM_SIZE];
    let mut unexpected_peer = None;
    // Adapter evidence only: QUIC-lite's rx_packets intentionally counts
    // packets admitted to this association. Keep the socket boundary visible
    // as well so a field failure can distinguish network loss from CID/parser
    // rejection without teaching the UDP adapter any transport policy.
    let mut socket_rx_packets = 0_u64;
    let mut quic_rejected_packets = 0_u64;
    while Instant::now() < deadline {
        let now_ms = started.elapsed().as_millis() as u64;
        if let Ok(Ok((used, source))) =
            tokio::time::timeout(Duration::from_millis(2), socket.recv_from(&mut input)).await
        {
            socket_rx_packets = socket_rx_packets.saturating_add(1);
            // Linux reports an inbound link-local source without the local
            // egress scope used to send to it.  The QUIC DCID authenticates
            // the association; UDP peer matching is remote IP plus port.
            if !same_udp_endpoint(source, peer) {
                unexpected_peer.get_or_insert(source);
                continue;
            }
            let admitted = driver.receive(&mut client, &input[..used], now_ms).map_err(|error| {
                format!(
                    "object upload receive: {error:?} records={} bytes={} blocked={:?} admission={:?} tx_packets={} socket_rx_packets={} quic_rx_packets={} quic_rejected_packets={} retransmits={} packet_hex={}",
                    client.record_index(), client.sent_bytes(), client.last_admission_block(), client.admission_state(), driver.tx_packets(), socket_rx_packets, driver.rx_packets(), quic_rejected_packets, driver.retransmit_packets(), hex_encode(&input[..used])
                )
            })?;
            if !admitted {
                quic_rejected_packets = quic_rejected_packets.saturating_add(1);
            } else if std::env::var_os("DMESH_OBJECT_UPLOAD_DEBUG_CREDIT").is_some() {
                eprintln!(
                    "dmesh_cli_object_upload_credit rx={} state={:?}",
                    socket_rx_packets,
                    client.admission_state()
                );
            }
            if admitted && let Some(packet) = driver.packet() {
                socket
                    .send_to(packet, peer)
                    .await
                    .map_err(|error| error.to_string())?;
                driver.mark_sent(now_ms);
            }
        }
        let now_ms = started.elapsed().as_millis() as u64;
        // Drain the complete currently-admissible QUIC-lite flight before
        // returning to the socket receive wait. A previous one-packet turn
        // inserted the adapter's 2 ms receive timeout between every fresh
        // stream packet, turning a normal window into stop-and-wait. The
        // driver remains the only source of packets, retransmissions, and
        // flow-control decisions; this loop only submits each ready packet.
        loop {
            driver
                .poll(&mut client, now_ms, 600, 400)
                .map_err(|error| format!("object upload poll: {error:?}"))?;
            let Some(packet) = driver.packet() else {
                break;
            };
            socket
                .send_to(packet, peer)
                .await
                .map_err(|error| error.to_string())?;
            driver.mark_sent(now_ms);
        }
        if client.is_complete() {
            // `receive` has already returned and sent the terminal response's
            // ACK. Send a separate QUIC CLOSE before this short-lived UDP
            // socket disappears, so the device does not retain a dead
            // association and retry its final MAX_* packet every control
            // cadence.
            let mut close_packet = [0u8; quic_lite::DEFAULT_MAX_DATAGRAM_SIZE];
            if let Some(close) = client
                .poll_close(&mut close_packet)
                .map_err(|error| format!("object upload close: {error:?}"))?
            {
                socket
                    .send_to(&close_packet[..close], peer)
                    .await
                    .map_err(|error| error.to_string())?;
                driver.mark_sent(now_ms);
            }
            if let Some(response) = client.rejected_response() {
                let reason = object_upload_rejection(response);
                return Err(format!(
                    "object upload rejected: {} records={} bytes={} blocked={:?} admission={:?}",
                    reason,
                    client.record_index(),
                    client.sent_bytes(),
                    client.last_admission_block(),
                    client.admission_state(),
                ));
            }
            return Ok(UdpObjectUploadResult {
                response: client.response().unwrap_or_default().to_vec(),
                records: client.record_index(),
                bytes: client.sent_bytes(),
                elapsed_ms: started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64,
                tx_packets: driver.tx_packets(),
                rx_packets: driver.rx_packets(),
                retransmits: driver.retransmit_packets(),
            });
        }
    }
    Err(format!(
        "object upload timeout records={} bytes={} blocked={:?} admission={:?} connection={:?} tx_packets={} socket_rx_packets={} quic_rx_packets={} quic_rejected_packets={} retransmits={} unexpected_peer={unexpected_peer:?}",
        client.record_index(),
        client.sent_bytes(),
        client.last_admission_block(),
        client.admission_state(),
        client.connection_debug_state(),
        driver.tx_packets(),
        socket_rx_packets,
        driver.rx_packets(),
        quic_rejected_packets,
        driver.retransmit_packets()
    ))
}

/// Bound the operator-side wait identically for UART and UDP. This is only a
/// diagnostic/client deadline; QUIC loss recovery and the firmware receiver's
/// idle timeout remain transport-owned and handler-owned respectively.
fn object_upload_timeout() -> Duration {
    Duration::from_secs(
        env::var("DMESH_OBJECT_UPLOAD_TIMEOUT_SECS")
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .filter(|value| *value != 0)
            .unwrap_or(60),
    )
}

fn requested_peer_receive_profile_from_env()
-> Result<Option<quic_lite::ReceiveWindowRequest>, String> {
    const DATA: &str = "DMESH_QUIC_REQUEST_PEER_MAX_DATA";
    const STREAM: &str = "DMESH_QUIC_REQUEST_PEER_MAX_STREAM_DATA";
    match (env::var(DATA).ok(), env::var(STREAM).ok()) {
        // The peer is authoritative for its normal memory profile. In
        // particular, a constrained ESP must not be inflated to a host-side
        // four-packet default before it can allocate its application sink.
        // Supplying both variables is deliberately an explicit stress or
        // capability experiment; OPEN_ACK remains the proof of acceptance.
        (None, None) => Ok(None),
        (Some(max_data), Some(max_stream_data)) => {
            let max_data = max_data
                .parse()
                .map_err(|error| format!("{DATA}: {error}"))?;
            let max_stream_data = max_stream_data
                .parse()
                .map_err(|error| format!("{STREAM}: {error}"))?;
            if max_data == 0 || max_stream_data == 0 {
                return Err("requested peer receive profile must be non-zero".into());
            }
            Ok(Some(quic_lite::ReceiveWindowRequest {
                max_data,
                max_stream_data,
            }))
        }
        _ => Err(format!("set both {DATA} and {STREAM}, or neither")),
    }
}

fn object_upload_rejection(response: &[u8]) -> String {
    dmesh_server::verified_object::decode_flash_handler_error(response)
        .map(String::from_utf8_lossy)
        .map(|reason| reason.into_owned())
        .unwrap_or_else(|| format!("invalid object.flash error ({})", hex_encode(response)))
}

fn same_udp_endpoint(received: SocketAddr, expected: SocketAddr) -> bool {
    match (received, expected) {
        (SocketAddr::V4(received), SocketAddr::V4(expected)) => {
            received.ip() == expected.ip() && received.port() == expected.port()
        }
        (SocketAddr::V6(received), SocketAddr::V6(expected)) => {
            received.ip() == expected.ip() && received.port() == expected.port()
        }
        _ => false,
    }
}

/// Select the wildcard address family from the peer. A raw IPv6 bearer must
/// not first fail in the host client by binding an IPv4 socket.
fn udp_bind_for_peer(peer: SocketAddr) -> SocketAddr {
    let port = env::var("DMESH_UDP_SOURCE_PORT")
        .ok()
        .and_then(|value| value.parse::<u16>().ok())
        .unwrap_or(3338);
    match peer {
        // Keep the operator/client socket distinct from both managed host
        // listeners (wlan0:3336, wlan1:3337) and firmware raw UDP6 (3339).
        // A fixed source port also makes link-local captures reproducible.
        // A concurrent operator can explicitly select `0` for an ephemeral
        // source without changing the peer or QUIC association identity.
        SocketAddr::V4(_) => SocketAddr::from(([0, 0, 0, 0], port)),
        SocketAddr::V6(_) => SocketAddr::from(([0; 16], port)),
    }
}

/// Parse a UDP peer, including the scoped IPv6 link-local form required by
/// raw UDP6 tests: `[fe80::1%wlan0]` (the firmware default port is used) or
/// `[fe80::1%wlan0]:3339`. `SocketAddr` itself deliberately
/// does not parse interface names, so resolve the Linux interface index here
/// at the host CLI boundary rather than teaching firmware about host scopes.
fn parse_udp_peer(value: &str) -> Result<SocketAddr, String> {
    if let Ok(peer) = value.parse::<SocketAddr>() {
        return Ok(peer);
    }
    let scoped = value
        .strip_prefix('[')
        .and_then(|value| {
            value
                .rsplit_once("]:")
                .map(|(address_scope, port)| (address_scope, Some(port)))
                .or_else(|| {
                    value
                        .strip_suffix(']')
                        .map(|address_scope| (address_scope, None))
                })
        })
        .ok_or_else(|| format!("invalid UDP peer {value:?}"))?;
    let (address_scope, port) = scoped;
    let (address, scope) = address_scope
        .rsplit_once('%')
        .ok_or_else(|| format!("IPv6 link-local peer needs %INTERFACE: {value:?}"))?;
    let address = address
        .parse::<Ipv6Addr>()
        .map_err(|error| error.to_string())?;
    let port = port
        .map(str::parse::<u16>)
        .transpose()
        .map_err(|error| error.to_string())?
        .unwrap_or(dmesh_server::udp::RAW_UDP6_PORT);
    let scope_id = scope
        .parse::<u32>()
        .ok()
        .or_else(|| {
            std::fs::read_to_string(format!("/sys/class/net/{scope}/ifindex"))
                .ok()
                .and_then(|index| index.trim().parse::<u32>().ok())
        })
        .ok_or_else(|| format!("unknown IPv6 scope interface {scope:?}"))?;
    Ok(SocketAddr::V6(SocketAddrV6::new(
        address, port, 0, scope_id,
    )))
}

/// Verify a selected UDP neighbor through the supported directed-discovery
/// request/reply. The reply remains a signed `announce.discovery` record;
/// this deliberately replaces the old unrelated bearer probe.
fn run_udp_direct_discovery(peer: SocketAddr) -> Result<(), String> {
    let id = fresh_request_id();
    let mut request = [0u8; 64];
    let used = announce::encode_discovery_request(id, &mut request)
        .ok_or("encode directed discovery request")?;
    let started = Instant::now();
    let response = exchange_udp_direct_record(peer, &request[..used])?;
    let payload = dmesh_server::direct::ConnectionlessMessage::decode(&response)
        .ok_or_else(|| "direct discovery received a non-direct response".to_owned())?;
    let record = dmesh_server::tagged::decode(payload)
        .ok_or("direct discovery response is not tagged CBOR")?;
    if record.id != Some(id) {
        return Err("direct discovery response has the wrong request ID".into());
    }
    let announce = announce::decode_record(record)
        .filter(|announce| announce.kind == announce::ANNOUNCE_DISCOVERY)
        .ok_or("direct discovery response is not an announce.discovery record")?;
    println!(
        "dmesh_direct_check target={peer} request_id={id} device={} elapsed_us={}",
        announce.device_name().unwrap_or("unknown"),
        started.elapsed().as_micros()
    );
    Ok(())
}

/// Check every direct ESP endpoint in the checked-in hosts inventory without
/// consulting the host radio service.  Each candidate gets its own directed
/// discovery record followed by a normal QUIC telemetry request: a multicast
/// sighting, a local TX completion, or one peer's failure cannot make another
/// candidate appear reachable.
fn run_hosts_check() -> Result<(), String> {
    let path = env::var_os("DMESH_HOSTS_FILE")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("hosts"));
    let contents = std::fs::read_to_string(&path)
        .map_err(|error| format!("read hosts inventory {}: {error}", path.display()))?;
    let mut candidates = Vec::<(String, SocketAddr)>::new();
    for line in contents.lines() {
        let line = line.split('#').next().unwrap_or_default();
        let mut fields = line.split_whitespace();
        let Some(address) = fields.next() else {
            continue;
        };
        let Ok(address) = address.parse::<std::net::IpAddr>() else {
            continue;
        };
        for name in fields {
            candidates.push((
                name.to_owned(),
                SocketAddr::new(address, dmesh_server::udp::RAW_UDP6_PORT),
            ));
        }
    }
    if candidates.is_empty() {
        return Err(format!(
            "hosts inventory {} has no IP/name entries",
            path.display()
        ));
    }

    let mut reachable = 0usize;
    for (name, peer) in candidates {
        let discovery = run_udp_direct_discovery(peer);
        if let Err(error) = discovery {
            println!(
                "dmesh_hosts_check name={name} peer={peer} reachable=false stage=discovery error={error}"
            );
            continue;
        }
        let request = encode_stream_command_with_id("telemetry.nan_status", fresh_request_id())
            .map_err(|error| format!("encode telemetry.nan_status: {error}"))?;
        match exchange_udp_stream_record(peer, &request) {
            Ok(response) => {
                let schema = FirmwareSchema::load();
                println!(
                    "dmesh_hosts_check name={name} peer={peer} reachable=true {}",
                    render_device_record(&schema, &response)
                );
                reachable = reachable.saturating_add(1);
            }
            Err(error) => println!(
                "dmesh_hosts_check name={name} peer={peer} reachable=false stage=quic error={error}"
            ),
        }
    }
    if reachable == 0 {
        return Err("no hosts-inventory peer completed direct discovery and QUIC telemetry".into());
    }
    Ok(())
}

/// Ask every directly reachable inventory node for a fresh discovery reply,
/// wait one DW8 interval plus margin, then collect each observer's local
/// `discovery.nodes` cache.  Every line describes one node; direct replies
/// are self reports without `visible_from`, observer cache rows carry the
/// single `visible_from` nodeID, and receiver-side facts keep one row per
/// (node, observer) pair because they differ per observer.
fn run_hosts_discovery() -> Result<(), String> {
    let reachable = multicast_discover_peers()?;
    if reachable.is_empty() {
        return Err("no peer answered UDP6 multicast discovery".into());
    }
    // Each observer owns different local media. Ask every reachable one to
    // run its common active pass (UDP, NAN, NOW where available), then allow
    // the sleepy-device DW and Android's temporary Aware Subscribe to report
    // before reading any observer cache.
    for discovered in &reachable {
        if !discovered.passive_ready {
            continue;
        }
        let request = encode_stream_command_with_id("discovery.active", fresh_request_id())
            .map_err(|error| format!("encode discovery.active: {error}"))?;
        let _ = exchange_udp_stream_record(discovered.peer, &request);
    }
    std::thread::sleep(Duration::from_secs(5));
    let mut rows = Vec::<(String, String, String)>::new();
    for discovered in &reachable {
        let peer = discovered.peer;
        let observer = discovered.node.clone();
        let request = encode_stream_command_with_id("discovery.nodes", fresh_request_id())
            .map_err(|error| format!("encode discovery.nodes: {error}"))?;
        match exchange_udp_stream_record(peer, &request) {
            Ok(response) => match observed_nodes(&response) {
                Some(nodes) => {
                    for entry in nodes {
                        rows.push((entry.node, observer.clone(), entry.fields));
                    }
                }
                None => println!("observer={observer} result=invalid_discovery_nodes"),
            },
            Err(error) => println!("observer={observer} error={error}"),
        }
    }
    rows.sort();
    for (node, observer, fields) in rows {
        let node_field = if node.is_empty() {
            String::new()
        } else {
            format!("node={node} ")
        };
        println!("{node_field}{fields} visible_from={observer}");
    }
    Ok(())
}

/// Flash one Main image without requiring an operator to stitch together the
/// discovery, NAN wake, Recovery handoff, and verified-object steps.  The
/// target is either its signed announce node ID/device name (when awake) or
/// the NAN MAC recorded by an observer's `discovery.nodes` cache.  A legacy
/// generic ESP announce is deliberately refused for writes: it cannot select
/// a safe CPU artifact.
fn run_automated_flash(arguments: &[String]) -> Result<(), String> {
    let (target, source) = match arguments {
        [target] => (target.as_str(), None),
        [target, flag, path] if flag == "--file" => (target.as_str(), Some(path.as_str())),
        _ => return Err("usage: dmesh-cli flash TARGET [--file MAIN_IMAGE]".into()),
    };
    let target_mac = parse_mac(target);
    let mut observed_node_id = None::<String>;
    let mut peers = multicast_discover_peers()?;
    let mut target_peer = peers.iter().find(|peer| flash_target_matches(peer, target));
    let mut selected = target_peer.map(|peer| (peer.peer, peer.announce));
    println!("dmesh_flash_gate target_found={}", selected.is_some());

    // A DW-only target is absent from UDP multicast. Ask every reachable
    // observer to refresh all of its media, then use the observation cache to
    // locate the observer which actually saw the requested radio MAC/node.
    if selected.is_none() {
        for peer in &peers {
            if peer.passive_ready {
                let request = encode_stream_command_with_id("discovery.active", fresh_request_id())
                    .map_err(|error| error.to_string())?;
                let _ = exchange_udp_stream_record(peer.peer, &request);
            }
        }
        std::thread::sleep(Duration::from_secs(5));
        let mut wake = None;
        for peer in &peers {
            let request = encode_stream_command_with_id("discovery.nodes", fresh_request_id())
                .map_err(|error| error.to_string())?;
            let Ok(response) = exchange_udp_stream_record(peer.peer, &request) else { continue };
            let Some(nodes) = observed_nodes(&response) else { continue };
            for node in nodes {
                let matches = target_mac.is_some_and(|mac| node.peer_mac == Some(mac))
                    || (!target.contains(':') && node.node.eq_ignore_ascii_case(target));
                if matches {
                    if let Some(mac) = node.peer_mac {
                        if !node.node.is_empty() {
                            observed_node_id = Some(node.node);
                        }
                        wake = Some((peer.peer, mac));
                        break;
                    }
                }
            }
            if wake.is_some() { break; }
        }
        let (observer, mac) = wake.ok_or_else(|| {
            format!("target_not_visible target={target}; no synced observer cache has its NAN peer")
        })?;
        let request = encode_stream_command_with_id(
            &format!("nan.wakeup to={}", mac_encode(&mac)),
            fresh_request_id(),
        )
        .map_err(|error| error.to_string())?;
        ensure_stream_success(exchange_udp_stream_record(observer, &request)?, "nan.wakeup")?;
        println!("dmesh_flash_gate nan_wake_accepted=true observer={observer} target_mac={}", mac_encode(&mac));

        let deadline = Instant::now() + Duration::from_secs(45);
        while Instant::now() < deadline {
            peers = multicast_discover_peers()?;
            if let Some(peer) = peers.iter().find(|peer| {
                observed_node_id
                    .as_deref()
                    .is_some_and(|node| peer.node.eq_ignore_ascii_case(node))
                    || flash_target_matches(peer, target)
            }) {
                selected = Some((peer.peer, peer.announce));
                break;
            }
        }
        target_peer = peers.iter().find(|peer| flash_target_matches(peer, target));
    }
    let (peer, announce) = selected.or_else(|| target_peer.map(|peer| (peer.peer, peer.announce)))
        .ok_or_else(|| format!("target_wake_timeout target={target}"))?;
    let cpu = announce::flash_cpu_for_device_class(announce.device_class).ok_or_else(|| {
        format!("target_cpu_unknown device_class={}; flash a concrete-family Main over a controlled path first", announce.device_class)
    })?;
    run_udp_direct_discovery(peer)?;
    let main_identity = firmware_identity(peer)?;
    println!("dmesh_flash_gate target_udp_ready=true peer={peer} cpu={cpu}");

    let recovery = encode_stream_command_with_id("boot.recovery", fresh_request_id())
        .map_err(|error| error.to_string())?;
    ensure_stream_success(exchange_udp_stream_record(peer, &recovery)?, "boot.recovery")?;
    println!("dmesh_flash_gate recovery_requested=true peer={peer}");

    // Recovery reuses the target identity and endpoint. Prefer its fresh
    // multicast announce, but a bridged WLAN can suppress link-local
    // multicast even when Recovery has submitted it. In that case a direct
    // `firmware.identity` response different from the pre-handoff Main image
    // is stronger evidence: it proves this exact endpoint ran another image,
    // not merely that a multicast packet was queued by the sender.
    let deadline = Instant::now() + Duration::from_secs(75);
    let recovery_peer = loop {
        if Instant::now() >= deadline {
            return Err("recovery_seen=false timeout waiting for fresh Recovery identity or multicast".into());
        }
        let candidates = multicast_discover_peers()?;
        if let Some(candidate) = candidates.into_iter().find(|candidate| {
            candidate.node == hex_encode(announce.device_id())
                && candidate.announce.device_class == announce.device_class
        }) {
            if firmware_identity(candidate.peer).is_ok_and(|identity| identity != main_identity) {
                println!("dmesh_flash_recovery_evidence source=multicast_identity");
                break candidate.peer;
            }
        }
        if firmware_identity(peer).is_ok_and(|identity| identity != main_identity) {
            println!("dmesh_flash_recovery_evidence source=direct_identity");
            break peer;
        }
    };
    println!("dmesh_flash_gate recovery_seen=true peer={recovery_peer}");
    let mut upload = vec![
        format!("udp://{recovery_peer}"),
        "object.flash".to_owned(),
        format!("cpu={cpu}"),
        "target=6".to_owned(),
    ];
    if let Some(source) = source {
        upload.push("--file".to_owned());
        upload.push(source.to_owned());
    }
    run_udp_service_client(&upload)?;
    println!("dmesh_flash_gate object_committed=true peer={recovery_peer}");

    let deadline = Instant::now() + Duration::from_secs(75);
    loop {
        if Instant::now() >= deadline {
            return Err("main_healthy=false timeout waiting for Main status".into());
        }
        let candidates = multicast_discover_peers()?;
        if let Some(candidate) = candidates.into_iter().find(|candidate| {
            candidate.node == hex_encode(announce.device_id())
                && candidate.announce.device_class == announce.device_class
        }) {
            let status = encode_stream_command_with_id("status", fresh_request_id())
                .map_err(|error| error.to_string())?;
            if ensure_stream_success(exchange_udp_stream_record(candidate.peer, &status)?, "Main status").is_ok() {
                println!("dmesh_flash_gate main_healthy=true peer={}", candidate.peer);
                return Ok(());
            }
        }
    }
}

fn flash_target_matches(peer: &DiscoveredPeer, target: &str) -> bool {
    peer.node.eq_ignore_ascii_case(target) || peer.announce.device_name() == Some(target)
}

fn parse_mac(value: &str) -> Option<[u8; 6]> {
    let mut mac = [0u8; 6];
    let mut parts = value.split(':');
    for byte in &mut mac {
        *byte = u8::from_str_radix(parts.next()?, 16).ok()?;
    }
    parts.next().is_none().then_some(mac)
}

fn ensure_stream_success(response: Vec<u8>, action: &str) -> Result<(), String> {
    let record = dmesh_server::tagged::decode(&response)
        .ok_or_else(|| format!("{action} response is not tagged CBOR"))?;
    if record.error.is_some() || record.result.is_none() {
        return Err(format!("{action} rejected by peer"));
    }
    Ok(())
}

/// Return the exact running-image identity published by the common firmware
/// handler.  It is compared only for one endpoint across a requested reboot;
/// it is never used as a device identity or a substitute for the signed
/// announce identity.
fn firmware_identity(peer: SocketAddr) -> Result<String, String> {
    let request = encode_stream_command_with_id("firmware.identity", fresh_request_id())
        .map_err(|error| error.to_string())?;
    let response = exchange_udp_stream_record(peer, &request)?;
    let record = dmesh_server::tagged::decode(&response)
        .ok_or("firmware.identity response is not tagged CBOR")?;
    if record.error.is_some() {
        return Err("firmware.identity rejected by peer".into());
    }
    let mut result = dmesh_server::cbor::Decoder::new(
        record.result.ok_or("firmware.identity response has no result")?,
    );
    let identity = result
        .text_ref()
        .and_then(|value| core::str::from_utf8(value).ok())
        .ok_or("firmware.identity response is not a UTF-8 image hash")?;
    result.is_finished().then(|| identity.to_owned()).ok_or_else(|| {
        "firmware.identity response has trailing fields".to_owned()
    })
}

/// Send the common discovery request directly to every local IPv6 multicast
/// scope and return only peers that supplied the matching signed response.
struct DiscoveredPeer {
    peer: SocketAddr,
    /// Lowercase hex of the announce `device_id`, the stable nodeID for
    /// output; the peer address when the announce carries no device identity.
    node: String,
    /// The signed announce matched to this UDP6 endpoint.  The orchestrator
    /// uses its immutable device identity/class rather than inferring either
    /// from an address or a configured board nickname.
    announce: announce::Announce,
    /// A target relay must have receiver-side NAN evidence. A UDP multicast
    /// reply alone says nothing about whether it can see a sleepy device.
    passive_ready: bool,
}

/// Render the announce CBOR fields that are present, using the schema field
/// names. The virtual IPv6 identity replaces the raw public key/signature.
fn announce_log_fields(announce: &announce::Announce) -> Vec<String> {
    let mut fields = Vec::new();
    if announce.has_identity() {
        if let Some(vip) = announce::virtual_ip6(announce.public_key()) {
            fields.push(format!("vip6={}", Ipv6Addr::from(vip)));
        }
    }
    fields.push(format!("kind={}", announce.kind));
    fields.push(format!("uptime_secs={}", announce.uptime_secs));
    if announce.device_class != announce::DEVICE_CLASS_UNKNOWN {
        fields.push(format!("device_class={}", announce.device_class));
        fields.push(format!(
            "device_family={}",
            announce::device_class_name(announce.device_class)
        ));
        if let Some(cpu) = announce::flash_cpu_for_device_class(announce.device_class) {
            fields.push(format!("flash_cpu={cpu}"));
        }
    }
    if announce.probe_capabilities != 0 {
        fields.push(format!("probe_capabilities={}", announce.probe_capabilities));
    }
    if let Some(name) = announce.device_name() {
        fields.push(format!("device_name={name}"));
    }
    if let Some(domain) = announce.device_domain() {
        fields.push(format!("device_domain={domain}"));
    }
    if let Some(name) = announce.network_name() {
        fields.push(format!("network_name={name}"));
    }
    if announce.wifi_channel != 0 {
        fields.push(format!("wifi_channel={}", announce.wifi_channel));
    }
    if let Some(addr) = announce.sta_link_local_v6() {
        fields.push(format!("sta_link_local_v6={}", Ipv6Addr::from(addr)));
    }
    if announce.udp_port != 0 {
        fields.push(format!("udp_port={}", announce.udp_port));
    }
    if let Some(addr) = announce.udp_link_local_v6() {
        fields.push(format!("udp_link_local_v6={}", Ipv6Addr::from(addr)));
    }
    fields
}

fn multicast_discover_peers() -> Result<Vec<DiscoveredPeer>, String> {
    const PORT: u16 = 5227;
    let request_id = fresh_request_id();
    let mut record = [0u8; 96];
    let record_len = announce::encode_discovery_request(request_id, &mut record)
        .ok_or("encode UDP6 multicast discovery request")?;
    let mut wire = [0u8; 128];
    let wire_len =
        dmesh_server::direct::ConnectionlessMessage::encode(&record[..record_len], &mut wire)
            .ok_or("wrap UDP6 multicast discovery request")?;
    let socket = UdpSocket::bind(SocketAddr::V6(SocketAddrV6::new(
        Ipv6Addr::UNSPECIFIED,
        0,
        0,
        0,
    )))
    .map_err(|error| format!("bind UDP6 multicast discovery: {error}"))?;
    socket
        .set_read_timeout(Some(Duration::from_millis(250)))
        .map_err(|error| error.to_string())?;
    let group = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0x5227);
    let mut submitted = 0usize;
    for entry in std::fs::read_dir("/sys/class/net").map_err(|error| error.to_string())? {
        let entry = entry.map_err(|error| error.to_string())?;
        let name = entry.file_name();
        if name == "lo" {
            continue;
        }
        let index = std::fs::read_to_string(entry.path().join("ifindex"))
            .ok()
            .and_then(|value| value.trim().parse::<u32>().ok());
        let Some(index) = index else { continue };
        let destination = SocketAddr::V6(SocketAddrV6::new(group, PORT, 0, index));
        if socket.send_to(&wire[..wire_len], destination).is_ok() {
            submitted = submitted.saturating_add(1);
        }
    }
    if submitted == 0 {
        return Err("UDP6 multicast discovery was not submitted on any interface".into());
    }
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut peers = Vec::<DiscoveredPeer>::new();
    let mut input = [0u8; quic_lite::DEFAULT_MAX_DATAGRAM_SIZE];
    while Instant::now() < deadline {
        let Ok((used, peer)) = socket.recv_from(&mut input) else {
            continue;
        };
        let Some(payload) = dmesh_server::direct::ConnectionlessMessage::decode(&input[..used])
        else {
            continue;
        };
        let Some(record) = dmesh_server::tagged::decode(payload) else {
            continue;
        };
        let facts = (record.id == Some(request_id))
            .then(|| announce::discovery_facts(record))
            .flatten();
        let Some(announce) = (record.id == Some(request_id))
            .then(|| announce::decode_record(record))
            .flatten()
        else {
            continue;
        };
        let peer = match peer {
            SocketAddr::V6(value) if announce.udp_port != 0 => SocketAddr::V6(SocketAddrV6::new(
                *value.ip(),
                announce.udp_port,
                value.flowinfo(),
                value.scope_id(),
            )),
            peer => peer,
        };
        if !peers.iter().any(|known| known.peer == peer) {
            let passive_ready = facts.is_some_and(|facts| {
                facts.nan_service_observations != 0 || facts.nan_visible_nodes != 0
            });
            let node_id = hex_encode(announce.device_id());
            let node = if node_id.is_empty() {
                peer.to_string()
            } else {
                node_id.clone()
            };
            let mut line = vec![format!("peer={peer}")];
            if !node_id.is_empty() {
                line.insert(0, format!("node={node_id}"));
            }
            line.extend(announce_log_fields(&announce));
            if let Some(facts) = facts {
                if let Some(suffix) = facts.nan_cluster_suffix {
                    line.push(format!("nan_cluster_suffix={}", hex_encode(&suffix)));
                }
                line.push(format!(
                    "nan_service_observations={}",
                    facts.nan_service_observations
                ));
                line.push(format!("nan_visible_nodes={}", facts.nan_visible_nodes));
            }
            if !passive_ready {
                line.push("passive_ready=false".to_owned());
            }
            println!("{}", line.join(" "));
            peers.push(DiscoveredPeer {
                peer,
                node,
                announce,
                passive_ready,
            });
        }
    }
    Ok(peers)
}

/// One decoded `discovery.nodes` observation. `node` is the hex of the
/// announce `device_id` (the truncated key used for the VIP6), empty for
/// provisional peers whose identity was never decoded; those rows are keyed
/// by the `peer` radio MAC inside `fields` instead. `fields` renders every
/// remaining observation fact with its CBOR schema name, in wire order.
struct ObservedNode {
    node: String,
    peer_mac: Option<[u8; 6]>,
    fields: String,
}

/// Decode the full bounded observation cache. The caller retains observer
/// provenance rather than pretending that a controller-local observation is
/// global mesh truth; receiver-side facts differ per observer and must not
/// be averaged together.
fn observed_nodes(response: &[u8]) -> Option<Vec<ObservedNode>> {
    let record = dmesh_server::tagged::decode(response)?;
    let mut result = dmesh_server::cbor::Decoder::new(record.result?);
    let (major, count) = result.head()?;
    if major != 5 {
        return None;
    }
    let mut nodes = Vec::new();
    for _ in 0..count {
        let key = result.uint()?;
        if key != 1 {
            result.skip()?;
            continue;
        }
        let (major, entries) = result.head()?;
        if major != 4 {
            return None;
        }
        for _ in 0..entries {
            let (major, field_count) = result.head()?;
            if major != 5 {
                return None;
            }
            let mut device_id = String::new();
            let mut peer_mac = None;
            let mut fields = Vec::<String>::new();
            for _ in 0..field_count {
                match result.uint()? {
                    1 => device_id = result.bytes_ref().map(hex_encode)?,
                    // Android reports its opaque PeerHandle as a zero MAC; a
                    // zero peer is a placeholder, not a radio observation.
                    2 => {
                        let bytes: [u8; 6] = result.bytes_ref()?.try_into().ok()?;
                        if bytes != [0; 6] {
                            peer_mac = Some(bytes);
                            fields.push(format!("peer={}", mac_encode(&bytes)));
                        }
                    }
                    3 => fields.push(format!("bssid={}", mac_encode(result.bytes_ref()?))),
                    4 => fields.push(format!("available_fields={}", result.uint()?)),
                    // 0 (no observation) and u32::MAX (Android wall clock does
                    // not fit the 32-bit field) are sentinels, not times.
                    5 => {
                        let value = result.uint()?;
                        if value != 0 && value != u32::MAX as u64 {
                            fields.push(format!("first_seen_ms={value}"));
                        }
                    }
                    6 => {
                        let value = result.uint()?;
                        if value != 0 && value != u32::MAX as u64 {
                            fields.push(format!("last_seen_ms={value}"));
                        }
                    }
                    7 => fields.push(format!("packets={}", result.uint()?)),
                    8 => fields.push(format!("active_publish_rx={}", result.uint()?)),
                    9 => fields.push(format!("active_subscribe_rx={}", result.uint()?)),
                    10 => fields.push(format!("followup_rx={}", result.uint()?)),
                    11 => fields.push(format!("last_kind={}", result.uint()?)),
                    12 => fields.push(format!("last_payload_len={}", result.uint()?)),
                    // 13 last_payload_hash is decoded but not rendered.
                    14 => fields.push(format!("unavailable_fields={}", result.uint()?)),
                    15 => fields.push(format!("channel={}", result.uint()?)),
                    _ => result.skip()?,
                }
            }
            nodes.push(ObservedNode {
                node: device_id,
                peer_mac,
                fields: fields.join(" "),
            });
        }
    }
    result.is_finished().then_some(nodes)
}

/// Send one schema-backed private direct control record to an explicit UDP
/// companion.  This is deliberately separate from a QUIC-lite service stream:
/// it is used to request radio actions such as active discovery before a
/// relay/DCID route exists.
fn run_udp_direct_record(arguments: &[String]) -> Result<(), String> {
    let target = arguments.first().ok_or("missing UDP target")?;
    let peer = target
        .strip_prefix("udp://")
        .ok_or("UDP target must use udp://HOST:PORT")?;
    let peer = parse_udp_peer(peer)?;
    let mut index = 1;
    let record = match arguments.get(index).map(String::as_str) {
        Some("--direct-hex") => {
            index += 1;
            hex(arguments.get(index).ok_or("missing --direct-hex value")?)?
        }
        Some("--msg") => {
            index += 1;
            let end = arguments[index..]
                .iter()
                .position(|argument| matches!(argument.as_str(), "--timeout-secs" | "--baud"))
                .map(|offset| index + offset)
                .unwrap_or(arguments.len());
            let command = arguments[index..end].join(" ");
            if command.is_empty() {
                return Err("missing --msg value".into());
            }
            index = end.saturating_sub(1);
            encode_direct_command_with_id(&command, fresh_request_id())
                .map_err(|error| error.to_string())?
        }
        _ => usage(),
    };
    index += 1;
    let mut timeout = Duration::from_secs(2);
    while index < arguments.len() {
        match arguments[index].as_str() {
            "--timeout-secs" => {
                index += 1;
                timeout = Duration::from_secs(
                    arguments
                        .get(index)
                        .ok_or("missing --timeout-secs value")?
                        .parse::<u64>()
                        .map_err(|error| error.to_string())?,
                );
            }
            argument => return Err(format!("UDP direct record does not support {argument}")),
        }
        index += 1;
    }
    let response = exchange_udp_direct_record_with_timeout(peer, &record, timeout)?;
    let response_record = dmesh_server::direct::ConnectionlessMessage::decode(&response)
        .ok_or_else(|| "UDP direct record received a non-direct response".to_owned())?;
    let schema = FirmwareSchema::load();
    println!(
        "dmesh_udp_direct_reply target={peer} {}",
        render_device_record(&schema, response_record)
    );
    Ok(())
}

/// Exchange one direct record from the fixed dmesh-cli UDP source port.
/// Keeping this tuple stable is deliberate: relay.pair binds its reverse path
/// to it, while independent dmesh-cli invocations can reuse that binding.
fn exchange_udp_direct_record(peer: SocketAddr, record: &[u8]) -> Result<Vec<u8>, String> {
    exchange_udp_direct_record_with_timeout(peer, record, Duration::from_secs(2))
}

/// Execute a relay administration record on a normal QUIC stream. Relay
/// setup is never part of the direct-message allowlist.
fn exchange_udp_stream_record(peer: SocketAddr, record: &[u8]) -> Result<Vec<u8>, String> {
    let runtime = tokio::runtime::Runtime::new().map_err(|error| error.to_string())?;
    runtime.block_on(async move {
        for attempt in 0..2 {
            let mut client = dmesh_server::udp::UdpClient::connect(
                udp_bind_for_peer(peer),
                peer,
                fresh_connection_id()?,
            )
            .await
            .map_err(|error| error.to_string())?;
            match client
                .request_stream(quic_lite::FIRST_CLIENT_BIDI_STREAM_ID, record, true)
                .await
            {
                Ok((_, response, true)) => return Ok(response),
                Ok((_, _, false)) => {
                    return Err("UDP application stream did not finish".to_owned());
                }
                Err(error)
                    if attempt == 0
                        && dmesh_server::transport::is_fresh_association_retry_error(&error) =>
                {
                    // The old association has already been discarded. A
                    // fresh CID repeats the application request once; no ACK,
                    // packet number, or stream ID is selected by the CLI.
                }
                Err(error) => return Err(error.to_string()),
            }
        }
        unreachable!("bounded retry loop returns on its final attempt")
    })
}

fn exchange_udp_direct_record_with_timeout(
    peer: SocketAddr,
    record: &[u8],
    timeout: Duration,
) -> Result<Vec<u8>, String> {
    let mut packet = [0u8; quic_lite::DEFAULT_MAX_DATAGRAM_SIZE];
    let used = dmesh_server::direct::ConnectionlessMessage::encode(record, &mut packet)
        .ok_or_else(|| "encode UDP connectionless packet exceeds the MTU".to_owned())?;
    let socket = UdpSocket::bind(udp_bind_for_peer(peer)).map_err(|error| error.to_string())?;
    socket.connect(peer).map_err(|error| error.to_string())?;
    socket
        .set_read_timeout(Some(timeout))
        .map_err(|error| error.to_string())?;
    socket
        .send(&packet[..used])
        .map_err(|error| error.to_string())?;
    let mut response = [0u8; quic_lite::DEFAULT_MAX_DATAGRAM_SIZE];
    let response_len = socket.recv(&mut response).map_err(|error| {
        if matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) {
            "UDP direct record timeout (no reply)".to_owned()
        } else {
            error.to_string()
        }
    })?;
    Ok(response[..response_len].to_vec())
}

#[derive(Deserialize)]
struct LocalSessionRequest {
    /// Schema service name, identical to `dmesh-cli NODE SERVICE`.
    service: String,
    /// Service fields use the same JSON types as the HTTP request body.
    #[serde(flatten)]
    fields: serde_json::Map<String, serde_json::Value>,
}

/// Own a single UDP QUIC-lite connection and expose a deliberately small
/// local text socket. This replaces the retired byte-forwarding listener: a
/// local client supplies a schema-backed JSON line such as
/// `{"service":"log-watch","records":4}` and receives one JSON result.
/// Requests use distinct QUIC stream IDs on this owned connection.
///
/// This is a session/shell helper, not a bearer proxy. It has no TCP path and
/// it never accepts arbitrary raw UART data. Long-lived log delivery will use
/// the same endpoint once the service handler publishes framed log records.
pub fn serve_udp_session_socket(peer: SocketAddr, socket_path: &Path) -> Result<(), String> {
    if socket_path.exists() {
        let metadata = std::fs::symlink_metadata(socket_path).map_err(|error| error.to_string())?;
        if !metadata.file_type().is_socket() {
            return Err(format!(
                "refusing to replace non-socket {}",
                socket_path.display()
            ));
        }
        std::fs::remove_file(socket_path).map_err(|error| error.to_string())?;
    }
    let listener = UnixListener::bind(socket_path).map_err(|error| error.to_string())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(socket_path, std::fs::Permissions::from_mode(0o600))
            .map_err(|error| error.to_string())?;
    }
    listener
        .set_nonblocking(true)
        .map_err(|error| error.to_string())?;
    let cid = fresh_connection_id()?;
    let runtime = tokio::runtime::Runtime::new().map_err(|error| error.to_string())?;
    let mut client = runtime
        .block_on(dmesh_server::udp::UdpClient::connect(
            "0.0.0.0:0".parse().expect("valid UDP bind"),
            peer,
            cid,
        ))
        .map_err(|error| error.to_string())?;
    let schema = FirmwareSchema::load();
    let mut next_stream = quic_lite::FIRST_CLIENT_BIDI_STREAM_ID;
    eprintln!(
        "dmesh_device_session target={peer} socket={}",
        socket_path.display()
    );
    loop {
        match listener.accept() {
            Ok((mut stream, _)) => {
                let mut line = String::new();
                BufReader::new(stream.try_clone().map_err(|error| error.to_string())?)
                    .read_line(&mut line)
                    .map_err(|error| error.to_string())?;
                let response = match serde_json::from_str::<LocalSessionRequest>(&line) {
                    Ok(request) => match encode_stream_fields_with_id(
                        &request.service,
                        &request.fields,
                        fresh_request_id(),
                    ) {
                        Ok(packet) => {
                            let stream_id = next_stream;
                            next_stream = next_stream.saturating_add(4);
                            match runtime.block_on(client.request_stream(stream_id, &packet, true))
                            {
                                Ok((stream_id, record, fin)) => serde_json::json!({
                                    "response": {
                                        "stream": stream_id, "fin": fin,
                                        "record": render_device_record(&schema, &record),
                                        "record_hex": hex_encode(&record),
                                    }
                                }),
                                Err(error) => serde_json::json!({"error": error.to_string()}),
                            }
                        }
                        Err(error) => serde_json::json!({"error": error.to_string()}),
                    },
                    Err(error) => {
                        serde_json::json!({"error": format!("invalid JSON request: {error}")})
                    }
                };
                writeln!(stream, "{response}").map_err(|error| error.to_string())?;
            }
            Err(error) if error.kind() == ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(10))
            }
            Err(error) => return Err(error.to_string()),
        }
    }
}

/// Fresh caller identity for correlation across independent CLI invocations.
///
/// Never derive this from process ID or a newly-created `Instant`: both made
/// consecutive dmesh-cli runs reuse the same connection ID and let a delayed
/// datagram be misattributed to the next request.
fn fresh_request_id() -> u64 {
    loop {
        let value = rand::random::<u64>();
        if value != 0 {
            return value;
        }
    }
}

fn fresh_connection_id() -> Result<quic_lite::ConnectionId, String> {
    let value = (fresh_request_id() & quic_lite::ConnectionId::MAX_VALUE).max(1);
    quic_lite::ConnectionId::new(value).ok_or("could not allocate random client CID".to_owned())
}

#[cfg(test)]
mod tests {
    use super::{
        ClientPathPolicy, RawTextTap, WatchTextFilter, is_fatal_diagnostic,
        object_upload_rejection, observed_nodes, parse_udp_peer, proxy_request,
        proxy_socket_target, same_udp_endpoint,
    };
    use dmesh_server::relay::{
        DesiredRule, PairRequest, RelayRoute, RelayState, Request, decode_pair_request,
        decode_request, encode_observed_pair, encode_observed_rule, encode_pair_request,
        encode_request, now_next_hop_handle, udp6_next_hop_handle,
    };
    use dmesh_server::udp::{
        RelayDatagramHandler, RelayDatagramOutcome, TaggedStreamContext, TaggedStreamHandler,
        UdpClient, UdpConfig,
    };
    use quic_lite::{ConnectionId, DcidDatagram, dispatch_datagram};
    use std::net::SocketAddr;
    use std::pin::Pin;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use tokio::net::UdpSocket;

    #[derive(Clone)]
    struct RelayHarness {
        state: Arc<Mutex<RelayState<SocketAddr, 2>>>,
        server_addr: SocketAddr,
        forward_count: Arc<AtomicUsize>,
        reverse_count: Arc<AtomicUsize>,
    }

    #[derive(Debug)]
    struct DirectRelayAdminSentinel(AtomicUsize);

    impl TaggedStreamHandler for DirectRelayAdminSentinel {
        fn handle<'a>(
            &'a self,
            _context: TaggedStreamContext,
            payload: Vec<u8>,
        ) -> Pin<Box<dyn std::future::Future<Output = Option<Vec<u8>>> + Send + 'a>> {
            Box::pin(async move {
                if decode_pair_request(&payload).is_some() || decode_request(&payload).is_some() {
                    self.0.fetch_add(1, Ordering::Relaxed);
                }
                None
            })
        }
    }

    impl TaggedStreamHandler for RelayHarness {
        fn handle<'a>(
            &'a self,
            context: TaggedStreamContext,
            request: Vec<u8>,
        ) -> Pin<Box<dyn std::future::Future<Output = Option<Vec<u8>>> + Send + 'a>> {
            Box::pin(async move {
                let record = dmesh_server::tagged::decode(&request)?;
                let id = record.id?;
                let mut response = [0u8; quic_lite::DEFAULT_MAX_DATAGRAM_SIZE];
                let used = if let Some(pair) = decode_pair_request(&request) {
                    let (forward, reverse) = self
                        .state
                        .lock()
                        .ok()?
                        .reconcile_pair(pair, |handle| {
                            if now_next_hop_handle([2, 0, 0, 0, 0, 1]) == Some(handle) {
                                Some(self.server_addr)
                            } else if udp6_next_hop_handle(1) == Some(handle) {
                                Some(context.peer)
                            } else {
                                None
                            }
                        })
                        .ok()?;
                    let mut fields = [0u8; 64];
                    let fields_len = encode_observed_pair(forward, reverse, &mut fields)?;
                    dmesh_server::tagged::encode_numeric_response(
                        dmesh_server::relay::RELAY_COMPONENT,
                        dmesh_server::relay::RELAY_APPLY_PAIR,
                        id,
                        &fields[..fields_len],
                        &mut response,
                    )?
                } else if let Some(request) = decode_request(&request) {
                    let observed = self
                        .state
                        .lock()
                        .ok()?
                        .reconcile(request, |handle| {
                            (now_next_hop_handle([2, 0, 0, 0, 0, 1]) == Some(handle))
                                .then_some(self.server_addr)
                        })
                        .ok()?;
                    let mut fields = [0u8; 64];
                    let fields_len = encode_observed_rule(observed, &mut fields)?;
                    dmesh_server::tagged::encode_numeric_response(
                        dmesh_server::relay::RELAY_COMPONENT,
                        dmesh_server::relay::RELAY_APPLY,
                        id,
                        &fields[..fields_len],
                        &mut response,
                    )?
                } else if record.component == Some(dmesh_server::tagged::Name::Tag(6))
                    && record.method == Some(dmesh_server::tagged::Name::Tag(9))
                {
                    // `curl -sS -X POST http://127.0.0.1:18981/_m/mesh \
                    //   -H 'content-type: application/json' \
                    //   --data '{"id":31,"method":"discovery.nodes"}'`
                    // exercises the same catalog method through HTTP.
                    dmesh_server::tagged::encode_numeric_response(
                        6,
                        9,
                        id,
                        &[0x81, 0x65, b'r', b'e', b'l', b'a', b'y'],
                        &mut response,
                    )?
                } else {
                    return None;
                };
                Some(response[..used].to_vec())
            })
        }
    }

    impl RelayDatagramHandler for RelayHarness {
        fn handle(
            &self,
            ingress: SocketAddr,
            packet: &[u8],
            out: &mut [u8],
        ) -> RelayDatagramOutcome {
            let Ok(state) = self.state.lock() else {
                return RelayDatagramOutcome::Drop;
            };
            let Ok(datagram) = dispatch_datagram(state.registry(), packet, out) else {
                return RelayDatagramOutcome::NotHandled;
            };
            let DcidDatagram::Forward {
                received_dcid,
                rule,
                used,
            } = datagram
            else {
                return RelayDatagramOutcome::NotHandled;
            };
            if ingress == self.server_addr {
                self.reverse_count.fetch_add(1, Ordering::Relaxed);
            } else {
                self.forward_count.fetch_add(1, Ordering::Relaxed);
            }
            let used = if matches!(rule.destination, quic_lite::ForwardDestination::Bootstrap)
                && ingress != self.server_addr
            {
                let Some(reverse) = state.relay_open_return_dcid(received_dcid) else {
                    return RelayDatagramOutcome::Drop;
                };
                let Ok(used) = quic_lite::rewrite_relay_open(packet, None, reverse, out) else {
                    return RelayDatagramOutcome::Drop;
                };
                used
            } else {
                used
            };
            RelayDatagramOutcome::Forward {
                peer: rule.next_hop,
                used,
            }
        }
    }

    /// CLIENT, RELAY, and SERVER share actual UDP listeners. Relay
    /// administration is sent on normal QUIC streams; only the current
    /// QUIC-lite relay-open bootstrap uses the custom-version Initial header.
    #[tokio::test]
    async fn udp_relay_pair_rewrites_bootstrap_and_status_both_directions() {
        let root = std::env::temp_dir().join(format!(
            "dmesh-cli-relay-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let server_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server_socket.local_addr().unwrap();
        drop(server_socket);
        let server_task = tokio::spawn(dmesh_server::udp::run(UdpConfig {
            bind: server_addr,
            artifact_root: root.clone(),
            ..UdpConfig::default()
        }));

        let relay_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let relay_addr = relay_socket.local_addr().unwrap();
        drop(relay_socket);
        let client_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let forward_count = Arc::new(AtomicUsize::new(0));
        let reverse_count = Arc::new(AtomicUsize::new(0));
        let relay = Arc::new(RelayHarness {
            state: Arc::new(Mutex::new(RelayState::new())),
            server_addr,
            forward_count: forward_count.clone(),
            reverse_count: reverse_count.clone(),
        });
        let direct_relay_admin = Arc::new(DirectRelayAdminSentinel(AtomicUsize::new(0)));
        let relay_task = tokio::spawn(dmesh_server::udp::run(UdpConfig {
            bind: relay_addr,
            artifact_root: root.clone(),
            tagged_handler: Some(relay.clone()),
            relay_handler: Some(relay),
            direct_handler: Some(direct_relay_admin.clone()),
            ..UdpConfig::default()
        }));

        // The first control connection uses the same stable client UDP tuple
        // that Step 2 will reuse for relay-open. `relay.pair` itself travels
        // on a normal tagged QUIC stream, never through the direct handler.
        let mut control = UdpClient::connect_with_socket(
            client_socket,
            relay_addr,
            ConnectionId::new(71).unwrap(),
        )
        .await
        .unwrap();
        let mut discovery = [0u8; 32];
        // HTTP-equivalent discovery request used by the dashboard before it
        // offers a relay-local neighbor:
        // curl -sS -X POST http://127.0.0.1:18982/_m/mesh/services/lmesh/call/discovery.nodes \
        //   -H 'content-type: application/json' --data '{"id":31}'
        let discovery_len =
            dmesh_server::tagged::encode_numeric_empty_request(6, 9, 31, &mut discovery).unwrap();
        let (_, discovery_response, discovery_fin) = control
            .request_stream(
                quic_lite::FIRST_CLIENT_BIDI_STREAM_ID,
                &discovery[..discovery_len],
                true,
            )
            .await
            .unwrap();
        assert!(discovery_fin);
        let discovery_response = dmesh_server::tagged::decode(&discovery_response).unwrap();
        assert_eq!(discovery_response.id, Some(31));
        assert_eq!(
            discovery_response.result,
            Some(&[0x81, 0x65, b'r', b'e', b'l', b'a', b'y'][..])
        );

        let pair = PairRequest {
            forward: Request {
                allocation: 1,
                revision: 1,
                rule: Some(DesiredRule {
                    proposed_dcid: Some(ConnectionId::new(8).unwrap()),
                    route: RelayRoute {
                        next_hop: now_next_hop_handle([2, 0, 0, 0, 0, 1]).unwrap(),
                        destination: quic_lite::ForwardDestination::Bootstrap,
                    },
                    position: 1,
                }),
            },
            reverse: Request {
                allocation: 2,
                revision: 1,
                rule: Some(DesiredRule {
                    proposed_dcid: Some(ConnectionId::new(12).unwrap()),
                    route: RelayRoute {
                        next_hop: udp6_next_hop_handle(1).unwrap(),
                        destination: quic_lite::ForwardDestination::Connection(
                            ConnectionId::new(77).unwrap(),
                        ),
                    },
                    position: 1,
                }),
            },
        };
        // Step-1 HTTP driver:
        // curl -sS -X POST http://127.0.0.1:18981/_m/mesh/services/lmesh/call/relay.connect \
        //   -H 'content-type: application/json' \
        //   --data '{"id":41,"relay_endpoint":"udp://[fe80::226e:f1ff:fe13:b170]:3339","next_hop_mac":"10:bd:a3:ac:5a:20"}'
        // performs this stream-side discovery + relay.pair sequence. Android
        // uses the same JSON at `/services/android/call/relay.connect`.
        let mut record = [0u8; 192];
        let record_len = encode_pair_request(pair, Some(41), &mut record).unwrap();
        let (_, response, response_fin) = control
            .request_stream(
                quic_lite::FIRST_CLIENT_BIDI_STREAM_ID + 4,
                &record[..record_len],
                true,
            )
            .await
            .unwrap();
        assert!(response_fin);
        let response_record = dmesh_server::tagged::decode(&response).unwrap();
        assert_eq!(
            response_record.method,
            Some(dmesh_server::tagged::Name::Tag(
                dmesh_server::relay::RELAY_APPLY_PAIR
            ))
        );
        assert!(response_record.error.is_none());
        let observed =
            dmesh_server::relay::decode_observed_pair(response_record.result.unwrap()).unwrap();
        assert_eq!(observed.forward.local_dcid.unwrap().value(), 8);
        assert_eq!(observed.reverse.local_dcid.unwrap().value(), 12);
        assert_eq!(
            direct_relay_admin.0.load(Ordering::Relaxed),
            0,
            "relay.pair must be administered through a normal QUIC stream"
        );
        let client_socket = control.into_socket().unwrap();

        let mut client = UdpClient::connect_with_socket_and_quic_lite_wire_dcid(
            client_socket,
            relay_addr,
            ConnectionId::new(77).unwrap(),
            ConnectionId::new(8).unwrap(),
        )
        .await
        .unwrap();
        let server_cid = client.peer_connection_id().unwrap();
        assert_ne!(server_cid.value(), 0);
        let update = Request {
            allocation: 1,
            revision: 2,
            rule: Some(DesiredRule {
                proposed_dcid: Some(ConnectionId::new(8).unwrap()),
                route: RelayRoute {
                    next_hop: now_next_hop_handle([2, 0, 0, 0, 0, 1]).unwrap(),
                    destination: quic_lite::ForwardDestination::Connection(server_cid),
                },
                position: 1,
            }),
        };
        let mut update_record = [0u8; 128];
        let update_record_len = encode_request(update, Some(42), &mut update_record).unwrap();
        // The current one-connection UDP helper gives its socket to the
        // relayed endpoint above. A later shared client-session mux will keep
        // this original control connection alive. Until then, verify that the
        // reconciliation is still a normal QUIC stream, not a direct packet.
        let mut update_control = UdpClient::connect(
            "127.0.0.1:0".parse().unwrap(),
            relay_addr,
            ConnectionId::new(72).unwrap(),
        )
        .await
        .unwrap();
        // `relay.apply` is an internal Step-2 reconciliation record, not a
        // public HTTP method. The future HTTP driver remains `relay.connect`;
        // it owns the retained session and performs this update after OPEN_ACK.
        let (_, update_response, update_fin) = update_control
            .request_stream(
                quic_lite::FIRST_CLIENT_BIDI_STREAM_ID,
                &update_record[..update_record_len],
                true,
            )
            .await
            .unwrap();
        assert!(update_fin);
        assert!(
            dmesh_server::tagged::decode(&update_response)
                .unwrap()
                .error
                .is_none()
        );

        let mut status_request = [0u8; 32];
        let status_request_len = dmesh_server::tagged::encode_numeric_empty_request(
            dmesh_server::services::DIAGNOSTIC_COMPONENT,
            dmesh_server::services::DIAGNOSTIC_STATUS_METHOD,
            43,
            &mut status_request,
        )
        .unwrap();
        let (_, status, fin) = client
            .request_stream(
                quic_lite::FIRST_CLIENT_BIDI_STREAM_ID,
                &status_request[..status_request_len],
                true,
            )
            .await
            .unwrap();
        let status_record = dmesh_server::tagged::decode(&status).unwrap();
        let mut status_result = dmesh_server::cbor::Decoder::new(status_record.result.unwrap());
        let status = String::from_utf8(status_result.text_ref().unwrap().to_vec()).unwrap();
        assert!(fin);
        assert!(
            status.contains("connection_dcid="),
            "status handler response: {status}"
        );
        assert!(
            forward_count.load(Ordering::Relaxed) >= 2,
            "bootstrap plus status must traverse forward route"
        );
        assert!(
            reverse_count.load(Ordering::Relaxed) >= 2,
            "bootstrap ACK plus status must traverse reverse route"
        );
        assert_eq!(
            direct_relay_admin.0.load(Ordering::Relaxed),
            0,
            "relay.apply must be administered through a normal QUIC stream"
        );
        eprintln!(
            "dmesh-cli relay-e2e server_dcid={} forward_packets={} reverse_packets={}",
            server_cid.value(),
            forward_count.load(Ordering::Relaxed),
            reverse_count.load(Ordering::Relaxed)
        );
        relay_task.abort();
        server_task.abort();
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn path_policy_aliases_and_firmware_values_are_stable() {
        assert_eq!(
            ClientPathPolicy::parse("aggregate"),
            Some(ClientPathPolicy::Aggregate)
        );
        assert_eq!(
            ClientPathPolicy::parse("fastest"),
            Some(ClientPathPolicy::HighestMeasuredSpeed)
        );
        assert_eq!(ClientPathPolicy::parse("udp").unwrap().wire(), 1);
        assert_eq!(ClientPathPolicy::parse("uart").unwrap().wire(), 2);
        assert_eq!(ClientPathPolicy::parse("spill").unwrap().wire(), 3);
        assert_eq!(ClientPathPolicy::parse("aggregate").unwrap().wire(), 4);
        assert_eq!(ClientPathPolicy::parse("ESP-NOW"), None);
    }

    #[test]
    fn raw_text_tap_reports_complete_lines_and_ignores_ppp() {
        let mut tap = RawTextTap::default();
        assert!(tap.push(b"boot step=").is_empty());
        assert_eq!(tap.push(b"uart\r\n"), vec!["boot step=uart"]);
        assert!(tap.push(&[0x7e, b'a', 0, b'\n', 0x7e]).is_empty());
        assert_eq!(tap.push(b"panic=none\n"), vec!["panic=none"]);
    }

    #[test]
    fn proxy_targets_and_requests_use_existing_jsonl_contract() {
        assert_eq!(
            proxy_socket_target("lmesh://lmesh-wifi"),
            Some("/run/mesh/lmesh-wifi/mesh.sock")
        );
        assert_eq!(
            proxy_socket_target("uds:///tmp/lmesh.sock"),
            Some("/tmp/lmesh.sock")
        );
        let request = proxy_request(
            "telemetry.nan_metrics",
            serde_json::json!({"destination":"14:c1:9f:e4:5d:48"}),
            Some("14c19fe45d48".to_owned()),
        )
        .unwrap();
        assert_eq!(request["method"], "telemetry.nan_metrics");
        assert_eq!(request["destination"], "14:c1:9f:e4:5d:48");
        assert_eq!(request["to"], "14c19fe45d48");
        assert!(request["id"].as_str().unwrap().starts_with("dmesh-cli-"));
        assert!(proxy_request("telemetry.nan_metrics", serde_json::json!([]), None).is_err());
    }

    #[test]
    fn watch_filter_keeps_first_sniffer_diagnostic() {
        let mut filter = WatchTextFilter::default();
        assert!(filter.retain("I (1) wifi:ic_disable_sniffer"));
        assert!(!filter.retain("I (2) wifi:ic_disable_sniffer"));
        assert!(filter.retain("DMESH main: radio ready"));
        assert_eq!(filter.suppressed_disable_sniffer, 1);
    }

    #[test]
    fn session_fatal_diagnostics_cover_panic_and_mid_suite_reset() {
        assert!(is_fatal_diagnostic("Guru Meditation Error"));
        assert!(is_fatal_diagnostic("rst:0x1 (POWERON_RESET)"));
        assert!(!is_fatal_diagnostic("transport status=ready"));
    }

    #[test]
    fn scoped_link_local_udp_peer_keeps_interface_index() {
        let peer = parse_udp_peer("[fe80::16c1:9fff:fee5:9800%9]:3339").unwrap();
        assert_eq!(peer.to_string(), "[fe80::16c1:9fff:fee5:9800%9]:3339");
    }

    #[test]
    fn scoped_link_local_udp_peer_uses_the_raw_firmware_default_port() {
        let peer = parse_udp_peer("[fe80::16c1:9fff:fee5:9800%9]").unwrap();
        assert_eq!(peer.to_string(), "[fe80::16c1:9fff:fee5:9800%9]:3339");
    }

    #[test]
    fn udp_endpoint_match_ignores_local_link_local_scope() {
        let configured: SocketAddr = "[fe80::12bd:a3ff:feac:5a20%5]:3339".parse().unwrap();
        let received: SocketAddr = "[fe80::12bd:a3ff:feac:5a20]:3339".parse().unwrap();
        assert!(same_udp_endpoint(received, configured));
        let wrong_port: SocketAddr = "[fe80::12bd:a3ff:feac:5a20]:3338".parse().unwrap();
        assert!(!same_udp_endpoint(wrong_port, configured));
    }

    #[test]
    fn object_upload_busy_response_is_reported_as_application_error() {
        let mut response = [0_u8; 96];
        let used = dmesh_server::tagged::encode_numeric_error(
            dmesh_server::verified_object::OBJECT_COMPONENT,
            dmesh_server::verified_object::OBJECT_FLASH_METHOD,
            7,
            dmesh_server::verified_object::FLASH_BUSY_ERROR,
            &mut response,
        )
        .unwrap();
        assert_eq!(
            object_upload_rejection(&response[..used]),
            "flash already in progress"
        );
    }

    #[test]
    fn observed_nodes_render_the_full_observation_facts() {
        let entries = [
            dmesh_server::announce::ObservedDevice {
                device_id: b"peer-a",
                peer: [1, 2, 3, 4, 5, 6],
                bssid: Some([0x50, 0x6f, 0x9a, 1, 2, 3]),
                channel: Some(6),
                available_fields: dmesh_server::discovery::OBSERVATION_ALL_FIELDS,
                first_seen_ms: 1,
                last_seen_ms: 2,
                packets: 3,
                active_publish_rx: 4,
                active_subscribe_rx: 5,
                followup_rx: 6,
                last_kind: 1,
                last_payload_len: 7,
                last_payload_hash: 8,
            },
            dmesh_server::announce::ObservedDevice {
                device_id: b"",
                peer: [7, 8, 9, 10, 11, 12],
                bssid: None,
                channel: None,
                available_fields: dmesh_server::discovery::OBSERVATION_PEER,
                first_seen_ms: 9,
                last_seen_ms: 10,
                packets: 11,
                active_publish_rx: 0,
                active_subscribe_rx: 0,
                followup_rx: 0,
                last_kind: 0,
                last_payload_len: 0,
                last_payload_hash: 0,
            },
            // Android-style row: a decoded identity but an opaque PeerHandle
            // (zero MAC) and wall-clock timestamps that degrade to u32::MAX.
            dmesh_server::announce::ObservedDevice {
                device_id: b"\x6c\x57\xff\x07\x63\x7d\x3b\x61\x7c\xab\x85\x77\x0b\x9c\xeb\xc4",
                peer: [0; 6],
                bssid: None,
                channel: None,
                available_fields: dmesh_server::discovery::OBSERVATION_PEER
                    | dmesh_server::discovery::OBSERVATION_PAYLOAD_FINGERPRINT,
                first_seen_ms: u32::MAX,
                last_seen_ms: u32::MAX,
                packets: 33,
                active_publish_rx: 33,
                active_subscribe_rx: 0,
                followup_rx: 0,
                last_kind: 0,
                last_payload_len: 96,
                last_payload_hash: 0,
            },
        ];
        let mut result = [0u8; 768];
        let result_len =
            dmesh_server::announce::encode_devices_observed_response(&entries, &mut result)
                .expect("encode discovery inventory");
        let fields = dmesh_server::tagged::decode(&result[..result_len])
            .and_then(|record| record.fields)
            .expect("extract discovery inventory fields");
        let mut response = [0u8; 960];
        let response_len =
            dmesh_server::tagged::encode_numeric_response(6, 9, 1, fields, &mut response)
                .expect("wrap discovery inventory");
        let nodes = observed_nodes(&response[..response_len]).expect("decode observations");
        assert_eq!(nodes.len(), 3);
        assert_eq!(nodes[0].node, "706565722d61");
        assert_eq!(
            nodes[0].fields,
            "peer=01:02:03:04:05:06 bssid=50:6f:9a:01:02:03 channel=6 \
              available_fields=31 first_seen_ms=1 last_seen_ms=2 packets=3 \
              active_publish_rx=4 active_subscribe_rx=5 followup_rx=6 \
              last_kind=1 last_payload_len=7 unavailable_fields=0"
        );
        // A provisional radio peer without a decoded identity has no nodeID;
        // its row is keyed by the peer MAC inside the facts.
        assert_eq!(nodes[1].node, "");
        assert_eq!(
            nodes[1].fields,
            "peer=07:08:09:0a:0b:0c available_fields=1 first_seen_ms=9 \
              last_seen_ms=10 packets=11 active_publish_rx=0 active_subscribe_rx=0 \
              followup_rx=0 last_kind=0 last_payload_len=0 unavailable_fields=30"
        );
    }
}
