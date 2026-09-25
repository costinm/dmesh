//! Experimental Linux BLE HCI service.

use crate::HciDevice;
use crate::{Advertisement, DMESH_BLE_SERVICE_UUID16};
use anyhow::{Context, Result, bail};
use serde_json::{Value, json};
use std::time::Duration;

const DEFAULT_HCI_DEV: u16 = 0;
const OCF_LE_SET_ADV_PARAMETERS: u16 = 0x0006;
const OCF_LE_SET_ADV_DATA: u16 = 0x0008;
const OCF_LE_SET_ADV_ENABLE: u16 = 0x000a;
const OCF_LE_SET_SCAN_PARAMETERS: u16 = 0x000b;
const OCF_LE_SET_SCAN_ENABLE: u16 = 0x000c;
const AF_BLUETOOTH: libc::c_int = 31;
const BTPROTO_HCI: libc::c_int = 1;
const HCIDEVUP: libc::c_int = 0x400448c9_u32 as libc::c_int;

pub struct BleService;

impl BleService {
    pub fn scan(
        &self,
        dev_id: Option<u16>,
        reason: Option<String>,
        scan_ms: Option<u64>,
    ) -> Result<Value> {
        let dev_id = dev_id.unwrap_or(DEFAULT_HCI_DEV);
        let scan_ms = scan_ms.unwrap_or(1_500).clamp(100, 30_000);
        let hci_up = hci_dev_up(dev_id).map_err(|error| format!("{error:#}"));
        let socket = HciSocket::open(dev_id)?;
        socket.send_le_command(
            OCF_LE_SET_SCAN_PARAMETERS,
            &[0x00, 0x10, 0x00, 0x10, 0x00, 0x00, 0x00],
        )?;
        socket.send_le_command(OCF_LE_SET_SCAN_ENABLE, &[0x01, 0x00])?;
        let deadline = std::time::Instant::now() + Duration::from_millis(scan_ms);
        let mut reports = Vec::new();
        let mut dmesh = Vec::new();
        while let Some(remaining) = deadline.checked_duration_since(std::time::Instant::now()) {
            if remaining.is_zero() {
                break;
            }
            let Some(packet) = socket.recv_timeout(remaining.min(Duration::from_millis(250)))?
            else {
                continue;
            };
            for report in parse_hci_le_adv_reports(&packet) {
                if let Some(Ok(parsed)) = parse_dmesh_ble_report(&report) {
                    dmesh.push(parsed);
                }
                reports.push(report);
            }
        }
        let disable_sent = socket
            .send_le_command(OCF_LE_SET_SCAN_ENABLE, &[0x00, 0x00])
            .is_ok();
        Ok(
            json!({"ok": true, "backend": "linux_hci_raw", "dev_id": dev_id,
            "hci_up": result_string_json(hci_up), "scan_ms": scan_ms,
            "service_uuid16": format!("0x{DMESH_BLE_SERVICE_UUID16:04x}"),
            "reason": reason.unwrap_or_else(|| "jsonl".to_owned()), "disable_sent": disable_sent,
            "report_count": reports.len(), "dmesh_count": dmesh.len(), "reports": reports, "dmesh": dmesh}),
        )
    }

    pub fn adv(
        &self,
        dev_id: Option<u16>,
        on: Option<bool>,
        payload: Option<String>,
    ) -> Result<Value> {
        let dev_id = dev_id.unwrap_or(DEFAULT_HCI_DEV);
        let on = on.unwrap_or(true);
        let socket = HciSocket::open(dev_id)?;
        if on {
            let _ = payload;
            let data = Advertisement::new(local_vip6()?).encode_service_data_ad();
            socket.send_le_command(
                OCF_LE_SET_ADV_PARAMETERS,
                &[0xa0, 0, 0xa0, 0, 3, 0, 0, 0, 0, 0, 0, 7, 0, 0, 0],
            )?;
            socket.send_le_command(OCF_LE_SET_ADV_DATA, &adv_data(&data)?)?;
            socket.send_le_command(OCF_LE_SET_ADV_ENABLE, &[1])?;
        } else {
            socket.send_le_command(OCF_LE_SET_ADV_ENABLE, &[0])?;
        }
        Ok(json!({"ok": true, "backend": "linux_hci_raw", "dev_id": dev_id, "on": on}))
    }
}

struct HciSocket {
    inner: HciDevice,
}
impl HciSocket {
    fn open(dev_id: u16) -> Result<Self> {
        Ok(Self {
            inner: HciDevice::open(dev_id)?,
        })
    }
    fn send_le_command(&self, ocf: u16, params: &[u8]) -> Result<()> {
        self.inner.send_le_command(ocf, params).map(|_| ())
    }
    fn recv_timeout(&self, timeout: Duration) -> Result<Option<Vec<u8>>> {
        self.inner.recv_timeout(timeout)
    }
}

fn parse_hci_le_adv_reports(packet: &[u8]) -> Vec<Value> {
    if packet.len() < 4 || packet[0] != 0x04 || packet[1] != 0x3e || packet[3] != 0x02 {
        return Vec::new();
    }
    let mut offset = 5;
    let mut reports = Vec::new();
    let count = packet.get(4).copied().unwrap_or(0) as usize;
    for _ in 0..count {
        if offset + 9 > packet.len() {
            break;
        }
        let event_type = packet[offset];
        let addr_type = packet[offset + 1];
        let address = mac_string_reversed(&packet[offset + 2..offset + 8]);
        let data_len = packet[offset + 8] as usize;
        offset += 9;
        if offset + data_len + 1 > packet.len() {
            break;
        }
        let data = packet[offset..offset + data_len].to_vec();
        offset += data_len;
        let rssi = packet[offset] as i8;
        offset += 1;
        reports.push(json!({
            "event_type": event_type,
            "addr_type": addr_type,
            "address": address,
            "scan_rssi": rssi,
            "data": hex_bytes(&data),
            "fields": ble_ad_fields_json(&data),
        }));
    }
    reports
}

fn parse_dmesh_ble_report(report: &Value) -> Option<Result<Value>> {
    let address = report.get("address")?.as_str()?;
    let scan_rssi = report.get("scan_rssi")?.as_i64()? as i32;
    let data_hex = report.get("data")?.as_str()?;
    let data = parse_hex_bytes(data_hex).ok()?;
    let mut offset = 0;
    while offset < data.len() {
        let field_len = data[offset] as usize;
        offset += 1;
        if field_len == 0 {
            break;
        }
        if offset + field_len > data.len() {
            break;
        }
        let field_type = data[offset];
        let field_data = &data[offset + 1..offset + field_len];
        if field_type == 0x16
            && field_data.len() >= 2
            && u16::from_le_bytes([field_data[0], field_data[1]]) == DMESH_BLE_SERVICE_UUID16
        {
            let parsed = Advertisement::decode_value(&field_data[2..]).map(|advertisement| {
                json!({
                    "protocol": "dmesh_ble",
                    "version": 1,
                    "address": address,
                    "scan_rssi": scan_rssi,
                    "vip6": std::net::Ipv6Addr::from(advertisement.vip6).to_string(),
                    "configured": advertisement.configured,
                })
            });
            return Some(parsed);
        }
        offset += field_len;
    }
    None
}

fn ble_ad_fields_json(data: &[u8]) -> Vec<Value> {
    let mut offset = 0;
    let mut fields = Vec::new();
    while offset < data.len() {
        let field_len = data[offset] as usize;
        offset += 1;
        if field_len == 0 {
            break;
        }
        if offset + field_len > data.len() {
            break;
        }
        let field_type = data[offset];
        let field_data = &data[offset + 1..offset + field_len];
        fields.push(json!({
            "type": format!("0x{field_type:02x}"),
            "data": hex_bytes(field_data),
        }));
        offset += field_len;
    }
    fields
}

fn adv_data(adv: &[u8]) -> Result<Vec<u8>> {
    if adv.len() > 0x1f {
        bail!("BLE advertisement data too large: {}", adv.len());
    }
    let mut out = Vec::with_capacity(32);
    out.push(adv.len() as u8);
    out.extend_from_slice(adv);
    out.resize(32, 0);
    Ok(out)
}

fn hci_dev_up(dev_id: u16) -> Result<String> {
    let fd = unsafe {
        libc::socket(
            AF_BLUETOOTH,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC,
            BTPROTO_HCI,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error()).context("failed to open HCI control socket");
    }
    let rc = unsafe { libc::ioctl(fd, HCIDEVUP as libc::Ioctl, dev_id as libc::c_int) };
    let result = if rc < 0 {
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::EALREADY) {
            Ok("already_up".to_string())
        } else {
            Err(error).with_context(|| format!("failed to bring hci{dev_id} up"))
        }
    } else {
        Ok("brought_up".to_string())
    };
    unsafe {
        libc::close(fd);
    }
    result
}

fn result_string_json(output: std::result::Result<String, String>) -> Value {
    match output {
        Ok(value) => json!({"ok": true, "value": value}),
        Err(error) => json!({"ok": false, "error": error}),
    }
}

fn local_vip6() -> Result<[u8; 16]> {
    let Some(value) = std::env::var_os("LMESH_VIP6") else {
        return Ok([0; 16]);
    };
    let address: std::net::Ipv6Addr = value
        .to_string_lossy()
        .parse()
        .context("LMESH_VIP6 must be an IPv6 address")?;
    Ok(address.octets())
}

fn hex_bytes(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn parse_hex_bytes(value: &str) -> Result<Vec<u8>> {
    let value = value.trim();
    if value.len() % 2 != 0 {
        bail!("hex byte string must have even length");
    }
    (0..value.len())
        .step_by(2)
        .map(|idx| {
            u8::from_str_radix(&value[idx..idx + 2], 16)
                .with_context(|| format!("invalid hex byte at offset {idx}"))
        })
        .collect()
}

fn mac_string_reversed(bytes: &[u8]) -> String {
    bytes
        .iter()
        .rev()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}
