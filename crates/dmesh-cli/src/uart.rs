//! Application session policy over the shared `uart-codec` physical bearer.

use crate::client::is_fatal_diagnostic;
use std::{
    collections::VecDeque,
    time::{Duration, Instant},
};
use uart_codec::host::{UartPort, UartRecord};

/// A bounded observation made by a persistent physical-UART device session.
///
/// The serial bearer is shared by command/reply traffic, normal QUIC-lite
/// packets, and the small out-of-band boot/crash diagnostic channel.  Keeping
/// these observations together lets a hardware test retain the last useful
/// context when a later operation fails, without treating text as protocol.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DeviceSessionEvent {
    /// Application message delivered by quic-lite's common stream callback.
    Message(Vec<u8>),
    /// Opaque QUIC datagram retained only for transport-test observation.
    Datagram(Vec<u8>),
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
    port: UartPort,
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
        let mut port = UartPort::open(&path, baud).map_err(|error| error.to_string())?;
        port.discard_input_blocking(Duration::ZERO)
            .map_err(|error| error.to_string())?;
        Ok(Self {
            path,
            port,
            history: VecDeque::with_capacity(Self::DEFAULT_HISTORY_LIMIT),
            history_limit: Self::DEFAULT_HISTORY_LIMIT,
            fatal_diagnostic: None,
        })
    }

    pub fn path(&self) -> &str {
        &self.path
    }

    /// Explicit troubleshooting reset. Normal sessions never change modem
    /// lines; the physical operation remains owned by `uart-codec`.
    pub fn reset(&self) -> Result<(), String> {
        self.port
            .reset_blocking()
            .map_err(|error| error.to_string())
    }

    /// Send the transport-neutral UART wake record without initiating a
    /// QUIC-lite exchange.
    pub fn send_wake(&mut self) -> Result<(), String> {
        self.port
            .send_wake_blocking()
            .map_err(|error| error.to_string())
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
        self.port
            .discard_input_blocking(settle)
            .map_err(|error| error.to_string())?;
        // A reset can split a PPP delimiter across the drain boundary.  Start
        // the actual test with no partial binary frame, diagnostic line, or
        // stale fatal marker from the preceding serial owner.
        self.history.clear();
        self.fatal_diagnostic = None;
        Ok(())
    }

    pub fn recent_events(&self) -> impl ExactSizeIterator<Item = &DeviceSessionEvent> {
        self.history.iter()
    }

    /// Remove and return observations accumulated since the previous drain.
    pub fn drain_events(&mut self) -> impl Iterator<Item = DeviceSessionEvent> + '_ {
        self.history.drain(..)
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
        let mut records = 0;
        while Instant::now() < deadline {
            for record in self
                .port
                .receive_blocking(Duration::from_millis(2))
                .map_err(|error| error.to_string())?
            {
                match record {
                    UartRecord::Log(line) => {
                        if is_fatal_diagnostic(&line) {
                            self.fatal_diagnostic.get_or_insert_with(|| line.clone());
                        }
                        let event = DeviceSessionEvent::Diagnostic(line);
                        let is_match = matched(&event);
                        self.push_event(event);
                        if is_match {
                            self.assert_healthy()?;
                            return Ok((true, records));
                        }
                    }
                    UartRecord::Datagram(packet) => {
                        records += 1;
                        let event = DeviceSessionEvent::Datagram(packet);
                        let is_match = matched(&event);
                        self.push_event(event);
                        if is_match {
                            self.assert_healthy()?;
                            return Ok((true, records));
                        }
                    }
                }
            }
        }
        self.assert_healthy()?;
        Ok((false, records))
    }

    fn push_event(&mut self, event: DeviceSessionEvent) {
        if self.history.len() == self.history_limit {
            self.history.pop_front();
        }
        self.history.push_back(event);
    }
}
