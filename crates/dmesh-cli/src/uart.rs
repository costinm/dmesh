//! Physical UART bearer adapter.
//!
//! This module owns serial frame I/O and observation of the
//! out-of-band boot log.

use crate::client::{
    RawTextTap, configure_serial, is_fatal_diagnostic, open_serial, send_ppp, send_uart_transport,
};
use dmesh_server::uart::{UartIngress, classify_uart_payload};
use quic_lite::DatagramClient;
use std::{
    collections::VecDeque,
    fs::File,
    io::{ErrorKind, Read},
    thread,
    time::{Duration, Instant},
};
use uart_codec::codec::Decoder;

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
pub(crate) struct DatagramRunStats {
    pub elapsed_us: u64,
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

    /// Drive any shared QUIC datagram client over this physical UART.
    pub(crate) fn drive_client<C, const PACKET: usize>(
        &mut self,
        client: &mut C,
        timeout: Duration,
        operation: &str,
    ) -> Result<DatagramRunStats, String>
    where
        C: DatagramClient<PACKET>,
    {
        self.assert_healthy()?;
        let started = Instant::now();
        let deadline = started + timeout;
        let mut driver = quic_lite::DatagramClientDriver::start(client, 0)
            .map_err(|error| format!("{operation} OPEN: {error:?}"))?;
        send_uart_transport(
            &mut self.serial,
            driver.packet().ok_or("QUIC client produced no OPEN")?,
        )?;
        driver.mark_sent(0);
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
                        .map_err(|e| e.to_string())?
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
                            Ok(UartIngress::Transport(packet)) => {
                                self.push_event(DeviceSessionEvent::TransportPacket(
                                    packet.to_vec(),
                                ));
                                let now_ms = started.elapsed().as_millis() as u64;
                                if driver
                                    .receive(client, packet, now_ms)
                                    .map_err(|error| format!("{operation} receive: {error:?}"))?
                                    && let Some(output) = driver.packet()
                                {
                                    send_uart_transport(&mut self.serial, output)?;
                                    driver.mark_sent(now_ms);
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
            let now_ms = started.elapsed().as_millis() as u64;
            driver
                .poll(client, now_ms, 600, 400)
                .map_err(|error| format!("{operation} poll: {error:?}"))?;
            if let Some(output) = driver.packet() {
                send_uart_transport(&mut self.serial, output)?;
                driver.mark_sent(now_ms);
            }
            if client.is_complete() {
                self.assert_healthy()?;
                return Ok(DatagramRunStats {
                    elapsed_us: started.elapsed().as_micros().max(1) as u64,
                    tx_packets: driver.tx_packets(),
                    rx_packets: driver.rx_packets(),
                    retransmits: driver.retransmit_packets(),
                });
            }
            thread::sleep(Duration::from_millis(2));
        }
        self.assert_healthy()?;
        Err(format!("{operation} timed out on {}", self.path))
    }

    pub(crate) fn send_quic_packet(&mut self, packet: &[u8]) -> Result<(), String> {
        self.assert_healthy()?;
        send_uart_transport(&mut self.serial, packet)
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
