//! Explicit Linux BLE CoC companion ownership over the shared QUIC-lite frames.

use crate::RadioService;
use anyhow::{Context, Result, anyhow, bail};
use lmesh_ble_hci::{CocChannel, DEFAULT_COC_PSM};
use serde_json::{Value, json};
use std::{net::Ipv6Addr, sync::{Arc, Mutex}, time::{Duration, Instant, SystemTime, UNIX_EPOCH}};

const PACKET: usize = quic_lite::DEFAULT_MAX_DATAGRAM_SIZE;

struct Paired {
    address: String,
    vip6: Ipv6Addr,
    channel: CocChannel,
}

#[derive(Clone)]
pub struct BleCompanion {
    radio: RadioService,
    paired: Arc<Mutex<Option<Paired>>>,
}

impl BleCompanion {
    pub fn new(radio: RadioService) -> Self {
        Self { radio, paired: Arc::new(Mutex::new(None)) }
    }

    pub fn pair(&self, address: &str, expected_vip6: Option<Ipv6Addr>, psm: Option<u16>) -> Result<Value> {
        if self.paired.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).is_some() {
            bail!("a BLE companion is already paired; unpair it first");
        }
        let channel = CocChannel::connect(address, psm.unwrap_or(DEFAULT_COC_PSM))?;
        let id = SystemTime::now().duration_since(UNIX_EPOCH)?.as_micros() as u64;
        let mut request = [0u8; 96];
        let used = dmesh_server::announce::encode_discovery_request(id, &mut request)
            .context("encode BLE signed discovery check")?;
        let response = run_tagged(&channel, &request[..used])?;
        let announce = dmesh_server::announce::decode_announce(&response)
            .context("BLE peer did not return a signed discovery announce")?;
        if !self.radio.observe_discovered_announce("ble", address.to_owned(), None, announce) {
            bail!("BLE discovery reply has invalid signed identity");
        }
        let vip6 = dmesh_server::announce::virtual_ip6(announce.public_key())
            .map(Ipv6Addr::from).context("signed BLE announce has no VIP6")?;
        if expected_vip6.is_some_and(|expected| expected != vip6) {
            bail!("BLE signed VIP differs from the selected discovery result");
        }
        self.radio.require_owned_companion(address, Some(vip6))?;
        let mut paired = self.paired.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        if paired.is_some() { bail!("a BLE companion was paired concurrently"); }
        *paired = Some(Paired { address: address.to_ascii_uppercase(), vip6, channel });
        Ok(json!({"paired": true, "kind": "ble", "id": address, "vip6": vip6, "psm": psm.unwrap_or(DEFAULT_COC_PSM)}))
    }

    pub fn unpair(&self, id: &str) -> Result<Value> {
        let mut paired = self.paired.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let current = paired.as_ref().context("no paired BLE companion")?;
        if !current.address.eq_ignore_ascii_case(id) { bail!("BLE companion ID does not match the paired address"); }
        let released = paired.take().map(|paired| paired.address);
        Ok(json!({"paired": false, "kind": "ble", "released": released}))
    }

    pub fn paired_with(&self, destination: &str) -> bool {
        self.paired.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
            .as_ref().is_some_and(|paired| paired.vip6.to_string() == destination)
    }

    pub fn forward(&self, record: &[u8]) -> Result<Vec<u8>> {
        let paired = self.paired.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let paired = paired.as_ref().context("no paired BLE companion")?;
        run_tagged(&paired.channel, record)
    }
}

fn run_tagged(channel: &CocChannel, record: &[u8]) -> Result<Vec<u8>> {
    let cid = quic_lite::ConnectionId::new(SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos() as u64 | 1)
        .context("allocate BLE client CID")?;
    let mut client = dmesh_server::transport::TaggedClient::<8, PACKET>::new(cid, record)
        .map_err(|error| anyhow!("BLE tagged client: {error:?}"))?;
    let started = Instant::now();
    let mut driver = quic_lite::DatagramClientDriver::start(&mut client, 0)
        .map_err(|error| anyhow!("BLE QUIC start: {error:?}"))?;
    let deadline = started + Duration::from_secs(5);
    loop {
        if let Some(packet) = driver.packet() {
            channel.send_frame(packet)?;
            driver.mark_sent(started.elapsed().as_millis() as u64);
        }
        if let Some(response) = client.response() { return Ok(response.to_vec()); }
        if Instant::now() >= deadline { bail!("BLE QUIC response timed out"); }
        if let Some(packet) = channel.receive_frame(Duration::from_millis(20))? {
            driver.receive(&mut client, &packet, started.elapsed().as_millis() as u64)
                .map_err(|error| anyhow!("BLE QUIC receive: {error:?}"))?;
        }
        if driver.packet().is_none() {
            driver.poll(&mut client, started.elapsed().as_millis() as u64, 600, 400)
                .map_err(|error| anyhow!("BLE QUIC poll: {error:?}"))?;
        }
    }
}
