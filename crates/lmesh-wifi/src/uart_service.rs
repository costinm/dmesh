//! Opt-in Linux UART companion adapter. Presence checks never retain a port.

use crate::RadioService;
use anyhow::{Context, Result, anyhow, bail};
use serde_json::{Value, json};
use std::{
    collections::HashMap,
    net::Ipv6Addr,
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use uart_codec::host::{PortInfo, UartPort, UartRecord};

const PACKET: usize = quic_lite::DEFAULT_MAX_DATAGRAM_SIZE;

struct Paired {
    path: PathBuf,
    vip6: Ipv6Addr,
    baud: Option<u32>,
    port: UartPort,
}

#[derive(Clone)]
pub struct UartController {
    radio: RadioService,
    paired: Arc<Mutex<Option<Paired>>>,
    observed: Arc<Mutex<HashMap<PathBuf, Ipv6Addr>>>,
    generation: Arc<AtomicU64>,
}

impl UartController {
    pub fn new(radio: RadioService) -> Self {
        Self {
            radio,
            paired: Arc::new(Mutex::new(None)),
            observed: Arc::new(Mutex::new(HashMap::new())),
            generation: Arc::new(AtomicU64::new(0)),
        }
    }

    pub fn devices(&self) -> Result<Value> {
        let ports = uart_codec::host::list_ports()?;
        let paired = self
            .paired
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let observed = self
            .observed
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        Ok(json!({"devices": ports.iter().map(|port| json!({
            "path": port.path,
            "device": port.device,
            "vip6": observed.get(&port.path).map(ToString::to_string),
            "paired": paired.as_ref().is_some_and(|paired| paired.path == port.path),
        })).collect::<Vec<_>>()}))
    }

    pub fn status(&self) -> Result<Value> {
        let paired = self
            .paired
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        Ok(json!({"paired": paired.as_ref().map(|paired| json!({
            "path": paired.path, "vip6": paired.vip6, "baud": paired.baud,
            "lines": paired.port.lines().ok().map(|lines| json!({
                "dtr": lines.dtr, "rts": lines.rts, "cts": lines.cts,
            })),
        })), "visible": uart_codec::host::list_ports()?.len()}))
    }

    /// Send a connectionless signed check to one or all listed ports, then close it.
    pub fn discover(
        &self,
        path: Option<PathBuf>,
        baud: Option<u32>,
        timeout: Duration,
    ) -> Result<Value> {
        let listed = uart_codec::host::list_ports()?;
        let candidates = if let Some(path) = path {
            vec![
                listed
                    .into_iter()
                    .find(|port| port.path == path || port.device == path)
                    .ok_or_else(|| {
                        anyhow!(
                            "UART path is not a listed USB serial device: {}",
                            path.display()
                        )
                    })?,
            ]
        } else {
            listed
        };
        let results = candidates
            .into_iter()
            .map(|port| match self.check_one(&port, baud, timeout) {
                Ok(value) => value,
                Err(error) => json!({"path": port.path, "ok": false, "error": error.to_string()}),
            })
            .collect::<Vec<_>>();
        Ok(json!({"devices": results}))
    }

    fn check_one(&self, info: &PortInfo, baud: Option<u32>, timeout: Duration) -> Result<Value> {
        {
            let paired = self
                .paired
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if paired
                .as_ref()
                .is_some_and(|paired| paired.path == info.path)
            {
                return Ok(
                    json!({"path": info.path, "ok": true, "vip6": paired.as_ref().map(|paired| paired.vip6), "paired": true}),
                );
            }
        }
        let mut port = UartPort::open(&info.path, baud).with_context(|| {
            format!(
                "temporarily open UART {} for discovery",
                info.path.display()
            )
        })?;
        let id = SystemTime::now().duration_since(UNIX_EPOCH)?.as_micros() as u64;
        let mut request = [0u8; 96];
        let used = dmesh_server::announce::encode_discovery_request(id, &mut request)
            .context("encode UART discovery check")?;
        let mut packet = [0u8; 128];
        let used =
            dmesh_server::direct::ConnectionlessMessage::encode(&request[..used], &mut packet)
                .context("encode UART discovery long packet")?;
        port.send_message(&packet[..used])?;
        let deadline = Instant::now() + timeout;
        while let Some(remaining) = deadline.checked_duration_since(Instant::now()) {
            if remaining.is_zero() {
                break;
            }
            for record in port.receive(remaining.min(Duration::from_millis(100)))? {
                let UartRecord::Message(packet) = record else {
                    continue;
                };
                let Some(response) = dmesh_server::direct::ConnectionlessMessage::decode(&packet)
                else {
                    continue;
                };
                if dmesh_server::tagged::decode(response).and_then(|record| record.id) != Some(id) {
                    continue;
                }
                let Some(announce) = dmesh_server::announce::decode_announce(response) else {
                    continue;
                };
                if !self.radio.observe_discovered_announce(
                    "uart",
                    info.path.display().to_string(),
                    None,
                    announce,
                ) {
                    bail!("UART discovery reply has invalid signed identity");
                }
                let vip6 = dmesh_server::announce::virtual_ip6(announce.public_key())
                    .map(Ipv6Addr::from)
                    .context("signed announce has no VIP6")?;
                self.observed
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .insert(info.path.clone(), vip6);
                return Ok(
                    json!({"path": info.path, "ok": true, "vip6": vip6, "device_name": announce.device_name(), "paired": false}),
                );
            }
        }
        bail!("UART discovery check timed out")
    }

    /// Ownership is explicit and requires a previously signed observation.
    pub fn pair(&self, path: &Path, vip6: Ipv6Addr, baud: Option<u32>) -> Result<Value> {
        let listed = uart_codec::host::list_ports()?;
        let info = listed
            .iter()
            .find(|port| port.path == path || port.device == path)
            .ok_or_else(|| anyhow!("UART port is no longer present"))?;
        let path = &info.path;
        let seen = self
            .observed
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if seen.get(path) != Some(&vip6) {
            bail!("UART path and VIP6 require a matching signed discovery result");
        }
        drop(seen);
        // The path may have been reused after discovery. Verify the device
        // again before retaining the port under its original signed VIP.
        let fresh = self.check_one(info, baud, Duration::from_secs(1))?;
        let expected_vip6 = vip6.to_string();
        if fresh.get("vip6").and_then(Value::as_str) != Some(expected_vip6.as_str()) {
            bail!("UART device identity changed since discovery");
        }
        self.radio.require_owned_companion(&expected_vip6, Some(vip6))?;
        let mut paired = self
            .paired
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if paired.is_some() {
            bail!("a UART companion is already paired; unpair it first");
        }
        let port = UartPort::open(path, baud)?;
        *paired = Some(Paired {
            path: path.to_path_buf(),
            vip6,
            baud,
            port,
        });
        let generation = self.generation.fetch_add(1, Ordering::AcqRel) + 1;
        drop(paired);
        let controller = self.clone();
        std::thread::spawn(move || controller.read_idle(generation));
        Ok(json!({"paired": true, "path": path, "vip6": vip6}))
    }

    pub fn unpair(&self) -> Value {
        let mut paired = self
            .paired
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let previous = paired.take().map(|paired| paired.path);
        self.generation.fetch_add(1, Ordering::AcqRel);
        json!({"paired": false, "released": previous})
    }

    pub fn unpair_matching(&self, id: &Path) -> Result<Value> {
        let mut paired = self.paired.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let current = paired.as_ref().context("no paired UART companion")?;
        let same_device = current.path == id || match (current.path.canonicalize(), id.canonicalize()) {
            (Ok(current), Ok(requested)) => current == requested,
            _ => false,
        };
        if !same_device {
            bail!("UART companion ID does not match the paired port");
        }
        let released = paired.take().map(|paired| paired.path);
        self.generation.fetch_add(1, Ordering::AcqRel);
        Ok(json!({"paired": false, "released": released}))
    }

    pub fn set_baud(&self, baud: u32) -> Result<Value> {
        let mut paired = self
            .paired
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let paired = paired.as_mut().context("no paired UART companion")?;
        paired.port.set_baud(baud)?;
        paired.baud = Some(baud);
        Ok(json!({"baud": baud, "path": paired.path}))
    }

    pub fn reset(&self) -> Result<Value> {
        let paired = self
            .paired
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let paired = paired.as_ref().context("no paired UART companion")?;
        paired.port.reset()?;
        Ok(json!({"reset": true, "path": paired.path}))
    }

    pub fn paired_with(&self, destination: &str) -> bool {
        self.paired
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .as_ref()
            .is_some_and(|paired| paired.vip6.to_string() == destination)
    }

    /// One normal QUIC stream over the explicitly paired physical frame path.
    pub fn forward(&self, record: &[u8]) -> Result<Vec<u8>> {
        let mut paired = self
            .paired
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let paired = paired.as_mut().context("no paired UART companion")?;
        let cid = quic_lite::ConnectionId::new(
            SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos() as u64 | 1,
        )
        .context("allocate UART client CID")?;
        let mut client = dmesh_server::transport::TaggedClient::<8, PACKET>::new(cid, record)
            .map_err(|error| anyhow!("UART tagged client: {error:?}"))?;
        let started = Instant::now();
        let mut driver = quic_lite::DatagramClientDriver::start(&mut client, 0)
            .map_err(|error| anyhow!("UART QUIC start: {error:?}"))?;
        let deadline = started + Duration::from_secs(5);
        loop {
            if let Some(packet) = driver.packet() {
                paired.port.send_frame(packet)?;
                driver.mark_sent(started.elapsed().as_millis() as u64);
            }
            if client.response().is_some() {
                break;
            }
            if Instant::now() >= deadline {
                bail!("paired UART QUIC response timed out");
            }
            for inbound in paired.port.receive(Duration::from_millis(20))? {
                match inbound {
                    UartRecord::Frame(frame) => {
                        driver
                            .receive(&mut client, &frame, started.elapsed().as_millis() as u64)
                            .map_err(|error| anyhow!("UART QUIC receive: {error:?}"))?;
                    }
                    UartRecord::Message(packet) => self
                        .radio
                        .record_uart_message(&paired.path.display().to_string(), &packet),
                    UartRecord::Log(line) => self
                        .radio
                        .record_uart_log(&paired.path.display().to_string(), &line),
                }
            }
            if driver.packet().is_none() {
                driver
                    .poll(&mut client, started.elapsed().as_millis() as u64, 600, 400)
                    .map_err(|error| anyhow!("UART QUIC poll: {error:?}"))?;
            }
        }
        Ok(client
            .response()
            .context("UART tagged response missing")?
            .to_vec())
    }

    /// Hotplug never claims a new port. Remove ownership only when it vanished.
    pub fn reconcile_presence(&self) -> Result<bool> {
        let paths = uart_codec::host::list_ports()?
            .into_iter()
            .map(|port| port.path)
            .collect::<Vec<_>>();
        let mut paired = self
            .paired
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if paired
            .as_ref()
            .is_some_and(|paired| !paths.contains(&paired.path))
        {
            *paired = None;
            self.generation.fetch_add(1, Ordering::AcqRel);
            return Ok(true);
        }
        Ok(false)
    }

    fn read_idle(&self, generation: u64) {
        while self.generation.load(Ordering::Acquire) == generation {
            let records = {
                let mut paired = self
                    .paired
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                match paired.as_mut() {
                    Some(paired) => paired
                        .port
                        .receive(Duration::from_millis(100))
                        .map(|records| (paired.path.clone(), records)),
                    None => break,
                }
            };
            match records {
                Ok((path, records)) => {
                    for record in records {
                        match record {
                            UartRecord::Log(line) => self
                                .radio
                                .record_uart_log(&path.display().to_string(), &line),
                            UartRecord::Message(packet) => self
                                .radio
                                .record_uart_message(&path.display().to_string(), &packet),
                            UartRecord::Frame(_) => {}
                        }
                    }
                }
                Err(error) => {
                    tracing::warn!(%error, "paired UART receive failed");
                    self.unpair();
                    break;
                }
            }
        }
    }
}
