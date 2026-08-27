use anyhow::Result;
use lmesh_wifi::{
    InterfaceSet, WifiService,
    dispatch::{
        handle_request, handle_reviewed_request, normalize_json_rpc_request, subscription_config,
    },
    reviewed::ReviewedWifiRequest,
};
use serde_json::json;
use std::{
    sync::{Arc, LazyLock},
    time::Duration,
};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};

static CONTROL_CATALOG: LazyLock<mesh::tagged::TaggedCatalog> = LazyLock::new(|| {
    mesh::tagged::TaggedCatalog::from_tools_json(
        &serde_json::from_str(include_str!("../resources/tools.json"))
            .expect("lmesh-wifi tools.json must be valid JSON"),
    )
    .expect("lmesh-wifi tools.json must be a valid tagged catalog")
});

struct WifiCborHandler {
    netd: Arc<lmesh_wifi::WifiNetd>,
    radio: Arc<lmesh_wifi::RadioService>,
}

#[async_trait::async_trait]
impl mesh::wire::TaggedRecordHandler for WifiCborHandler {
    async fn handle_record(
        &self,
        record: mesh::tagged::TaggedRecord,
    ) -> anyhow::Result<Option<mesh::tagged::TaggedRecord>> {
        let id = record
            .id
            .clone()
            .ok_or_else(|| anyhow::anyhow!("tagged-CBOR request missing id"))?;
        let request = match decode_wifi_tagged_request(&record) {
            Ok(request) => request,
            Err(error) => {
                return Ok(Some(mesh::wire::response_error(
                    id,
                    json!({"error": error.to_string()}),
                )));
            }
        };
        let response = handle_reviewed_request(&self.netd, &self.radio, request);
        Ok(Some(mesh::wire::response_ok(id, response)))
    }
}

fn decode_wifi_tagged_request(
    record: &mesh::tagged::TaggedRecord,
) -> anyhow::Result<ReviewedWifiRequest> {
    let Some(method) = CONTROL_CATALOG.method_name(record) else {
        anyhow::bail!("tagged-CBOR method is outside the reviewed wifi catalog");
    };
    let value = CONTROL_CATALOG.to_jsonl(record);
    match method {
        "wifi.ap.status" => serde_json::from_value(value).map(ReviewedWifiRequest::ApStatus),
        "wifi.sta.status" => serde_json::from_value(value).map(ReviewedWifiRequest::StaStatus),
        "wifi.rawnan.status" => {
            serde_json::from_value(value).map(ReviewedWifiRequest::RawNanStatus)
        }
        "wifi.probe.plan" => serde_json::from_value(value).map(ReviewedWifiRequest::ProbePlan),
        "wifi.interface.status" => {
            serde_json::from_value(value).map(ReviewedWifiRequest::InterfaceStatus)
        }
        "wifi.ap.stations" => serde_json::from_value(value).map(ReviewedWifiRequest::ApStations),
        "wifi.raw.metrics" => serde_json::from_value(value).map(ReviewedWifiRequest::RawMetrics),
        "wifi.raw.stop" => serde_json::from_value(value).map(ReviewedWifiRequest::RawStop),
        "wifi.raw.listen" => serde_json::from_value(value).map(ReviewedWifiRequest::RawListen),
        "wifi.raw.check" => serde_json::from_value(value).map(ReviewedWifiRequest::RawCheck),
        "wifi.raw.iperf" => serde_json::from_value(value).map(ReviewedWifiRequest::RawIperf),
        "wifi.raw.send" => serde_json::from_value(value).map(ReviewedWifiRequest::RawSend),
        "wifi.rawnan.ping" => serde_json::from_value(value).map(ReviewedWifiRequest::RawNanPing),
        "wifi.rawnan.listen" => {
            serde_json::from_value(value).map(ReviewedWifiRequest::RawNanListen)
        }
        _ => unreachable!("the reviewed wifi catalog contains only typed read-only methods"),
    }
    .map_err(Into::into)
}

#[tokio::main]
async fn main() -> Result<()> {
    let service = Arc::new(WifiService::from_environment());
    let netd = Arc::new(service.netd().clone());
    let radio = Arc::new(service.radio().clone());
    let (trace, _guard) = mesh::local_trace::init("lmesh-wifi");
    mesh::local_trace::serve("lmesh-wifi", trace.clone());
    // wlan0 is the stable infrastructure fixture: start its AP at service
    // launch. lmesh owns the independent AP-off NAN+NOW/STA+NOW radio.
    for result in service.start_stable() {
        let phase = if result.get("ssid").is_some() {
            "ap_start"
        } else if result.get("monitor_iface").is_some() {
            "raw_monitor"
        } else if result.get("profile").is_some() {
            "rate_profile"
        } else {
            "startup"
        };
        tracing::info!(
            phase,
            ok = result
                .get("ok")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false),
            iface = result
                .get("iface")
                .and_then(serde_json::Value::as_str)
                .unwrap_or(""),
            profile = result
                .get("profile")
                .and_then(serde_json::Value::as_str)
                .unwrap_or(""),
            error = result
                .get("error")
                .and_then(serde_json::Value::as_str)
                .unwrap_or(""),
            result = ?result,
            "wifi_startup_result"
        );
    }

    // A USB/radio reset can leave the supervised process alive while its AP
    // netdev disappears. Watch rtnetlink events only for this service's
    // configured interfaces; STA/NAN events from lmesh/wlan1 must never
    // trigger lmesh-wifi/wlan0 recovery.
    let owned_interfaces = netd.owned_interfaces().clone();
    let (link_events, mut link_event_rx) = tokio::sync::mpsc::unbounded_channel();
    std::thread::spawn(move || watch_rtnetlink_link_events(owned_interfaces, link_events));
    let stable_health = service.clone();
    tokio::spawn(async move {
        while let Some(event) = link_event_rx.recv().await {
            // A burst accompanies USB reprobe. Let rtnetlink finish naming
            // and registering the device before asking nl80211 to rebuild it.
            tokio::time::sleep(Duration::from_millis(250)).await;
            let result = stable_health.reconcile_stable_health();
            if result.get("state").and_then(serde_json::Value::as_str) != Some("healthy") {
                tracing::warn!(?event, ?result, "wifi_stable_link_reconcile");
            }
        }
    });

    if netd.owned_interfaces().names().is_empty() {
        tracing::warn!("LMESH_INTERFACES is empty; Wi-Fi AP was not started");
    }

    // The Recovery Wi-Fi flashing path is part of the service's normal
    // bearer set. Keep it alive with lmesh-wifi so flash-device.py only has
    // to configure the device; an explicit wifi.object.udp.start request is
    // retained as an idempotent diagnostic/control surface.
    let object_udp = radio.object_udp_start(None, None, None);
    tracing::info!(
        ok = object_udp
            .get("ok")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false),
        port = object_udp
            .get("port")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(3336),
        error = object_udp
            .get("error")
            .and_then(serde_json::Value::as_str)
            .unwrap_or(""),
        "object_udp_startup",
    );
    let path = std::env::var("LMESH_CONTROL_SOCKET")
        .unwrap_or_else(|_| "/run/mesh/lmesh-wifi/mesh.sock".to_string());
    let mut listener = mesh::server::MeshListener::new("lmesh-wifi", Some(&path))
        .map_err(|error| anyhow::anyhow!(error.to_string()))?;
    while let Some(stream) = listener
        .accept()
        .await
        .map_err(|error| anyhow::anyhow!(error.to_string()))?
    {
        let netd = netd.clone();
        let radio = radio.clone();
        let trace = trace.clone();
        tokio::spawn(async move {
            let mut stream = stream;
            let mut first = [0_u8; 1];
            let Ok(bytes_read) = stream.read(&mut first).await else {
                return;
            };
            if bytes_read == 0 {
                return;
            }
            let mut stream = mesh::wire::PrefixedStream::new(first[0], stream);
            if first[0] == 0 {
                let _ =
                    mesh::wire::serve_cbor_session(&mut stream, &WifiCborHandler { netd, radio })
                        .await;
                return;
            }
            let (reader, mut writer) = tokio::io::split(stream);
            let mut reader = BufReader::new(reader);
            let mut line = String::new();
            loop {
                line.clear();
                if reader
                    .read_line(&mut line)
                    .await
                    .ok()
                    .filter(|n| *n > 0)
                    .is_none()
                {
                    break;
                }
                let request = normalize_json_rpc_request(
                    serde_json::from_str(line.trim()).unwrap_or_else(|_| json!({})),
                );
                if let Some(config) = subscription_config(&request) {
                    let rawnan_subscription = radio.rawnan_subscription_start(&config);
                    let ack = json!({
                        "success": true,
                        "data": {"subscribed": true, "service": "lmesh-wifi", "targets": config.targets.clone()}
                    });
                    if writer.write_all(ack.to_string().as_bytes()).await.is_err()
                        || writer.write_all(b"\n").await.is_err()
                        || writer.flush().await.is_err()
                    {
                        if let Some(iface) = rawnan_subscription {
                            radio.rawnan_subscription_stop(&iface);
                        }
                        break;
                    }
                    for entry in trace.get_all() {
                        if config.matches(&entry) {
                            if writer
                                .write_all(
                                    serde_json::to_string(&entry).unwrap_or_default().as_bytes(),
                                )
                                .await
                                .is_err()
                                || writer.write_all(b"\n").await.is_err()
                            {
                                break;
                            }
                        }
                    }
                    let mut events = trace.subscribe();
                    while let Ok(entry) = events.recv().await {
                        if config.matches(&entry)
                            && (writer
                                .write_all(
                                    serde_json::to_string(&entry).unwrap_or_default().as_bytes(),
                                )
                                .await
                                .is_err()
                                || writer.write_all(b"\n").await.is_err()
                                || writer.flush().await.is_err())
                        {
                            break;
                        }
                    }
                    if let Some(iface) = rawnan_subscription {
                        radio.rawnan_subscription_stop(&iface);
                    }
                    break;
                }
                let response = handle_request(&netd, &radio, request);
                if writer
                    .write_all(response.to_string().as_bytes())
                    .await
                    .is_err()
                {
                    break;
                }
                if writer.write_all(b"\n").await.is_err() {
                    break;
                }
                let _ = writer.flush().await;
            }
        });
    }
    Ok(())
}

#[derive(Debug)]
struct LinkEvent {
    kind: u16,
    ifindex: i32,
    iface: Option<String>,
    mac: Option<String>,
}

const RTMGRP_LINK: u32 = 1;
const IFLA_ADDRESS: u16 = 1;
const IFLA_IFNAME: u16 = 3;
const NLMSG_ALIGNTO: usize = 4;

fn parse_mac(value: &str) -> Option<[u8; 6]> {
    let bytes = value
        .trim()
        .split(':')
        .map(|part| u8::from_str_radix(part, 16).ok())
        .collect::<Option<Vec<_>>>()?;
    bytes.try_into().ok()
}

fn watch_rtnetlink_link_events(
    owned_interfaces: InterfaceSet,
    sender: tokio::sync::mpsc::UnboundedSender<LinkEvent>,
) {
    let fd = unsafe {
        libc::socket(
            libc::AF_NETLINK,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC,
            libc::NETLINK_ROUTE,
        )
    };
    if fd < 0 {
        tracing::error!(error = %std::io::Error::last_os_error(), "rtnetlink link watcher unavailable");
        return;
    }
    let mut address: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
    address.nl_family = libc::AF_NETLINK as libc::sa_family_t;
    address.nl_pid = 0;
    address.nl_groups = RTMGRP_LINK;
    let bound = unsafe {
        libc::bind(
            fd,
            &address as *const libc::sockaddr_nl as *const libc::sockaddr,
            std::mem::size_of_val(&address) as libc::socklen_t,
        )
    };
    if bound != 0 {
        tracing::error!(error = %std::io::Error::last_os_error(), "rtnetlink link watcher bind failed");
        unsafe {
            libc::close(fd);
        }
        return;
    }
    let mut buffer = [0_u8; 8192];
    loop {
        let read = unsafe { libc::recv(fd, buffer.as_mut_ptr().cast(), buffer.len(), 0) };
        if read < 0 {
            if std::io::Error::last_os_error().kind() != std::io::ErrorKind::Interrupted {
                tracing::warn!(error = %std::io::Error::last_os_error(), "rtnetlink link watcher read failed");
            }
            continue;
        }
        for event in parse_link_events(&buffer[..read as usize]) {
            // Link deletion can be represented without an interface name on
            // some kernels. Ignore such ambiguous events rather than
            // treating an unrelated device as a reason to disturb the AP.
            let Some(iface) = event.iface.as_deref() else {
                continue;
            };
            if owned_interfaces.contains(iface) && sender.send(event).is_err() {
                unsafe {
                    libc::close(fd);
                }
                return;
            }
        }
    }
}

fn parse_link_events(mut bytes: &[u8]) -> Vec<LinkEvent> {
    const NLMSG_HDR_LEN: usize = 16;
    const IFINFO_LEN: usize = 16;
    let mut events = Vec::new();
    while bytes.len() >= NLMSG_HDR_LEN {
        let length = u32::from_ne_bytes(bytes[..4].try_into().expect("header length")) as usize;
        let kind = u16::from_ne_bytes(bytes[4..6].try_into().expect("header type"));
        if length < NLMSG_HDR_LEN || length > bytes.len() {
            break;
        }
        if matches!(kind, libc::RTM_NEWLINK | libc::RTM_DELLINK)
            && length >= NLMSG_HDR_LEN + IFINFO_LEN
        {
            let info = &bytes[NLMSG_HDR_LEN..NLMSG_HDR_LEN + IFINFO_LEN];
            let ifindex = i32::from_ne_bytes(info[4..8].try_into().expect("ifindex"));
            let mut iface = None;
            let mut mac = None;
            let mut attrs = &bytes[NLMSG_HDR_LEN + IFINFO_LEN..length];
            while attrs.len() >= 4 {
                let attr_len =
                    u16::from_ne_bytes(attrs[..2].try_into().expect("attribute length")) as usize;
                let attr_type = u16::from_ne_bytes(attrs[2..4].try_into().expect("attribute type"));
                if attr_len < 4 || attr_len > attrs.len() {
                    break;
                }
                let value = &attrs[4..attr_len];
                match attr_type {
                    IFLA_IFNAME => {
                        iface = std::ffi::CStr::from_bytes_until_nul(value)
                            .ok()
                            .and_then(|name| name.to_str().ok())
                            .map(str::to_owned)
                    }
                    IFLA_ADDRESS if value.len() == 6 => {
                        mac = Some(
                            value
                                .iter()
                                .map(|byte| format!("{byte:02x}"))
                                .collect::<Vec<_>>()
                                .join(":"),
                        )
                    }
                    _ => {}
                }
                let aligned = (attr_len + (NLMSG_ALIGNTO - 1)) & !(NLMSG_ALIGNTO - 1);
                if aligned > attrs.len() {
                    break;
                }
                attrs = &attrs[aligned..];
            }
            events.push(LinkEvent {
                kind,
                ifindex,
                iface,
                mac,
            });
        }
        let aligned = (length + (NLMSG_ALIGNTO - 1)) & !(NLMSG_ALIGNTO - 1);
        if aligned > bytes.len() {
            break;
        }
        bytes = &bytes[aligned..];
    }
    events
}

#[cfg(test)]
mod link_event_tests {
    use super::*;

    #[test]
    fn parses_mac_and_link_attributes() {
        let mut message = vec![0_u8; 16 + 16];
        message[4..6].copy_from_slice(&(libc::RTM_NEWLINK as u16).to_ne_bytes());
        message[20..24].copy_from_slice(&42_i32.to_ne_bytes());
        message.extend_from_slice(&[
            10,
            0,
            IFLA_IFNAME as u8,
            0,
            b'w',
            b'l',
            b'a',
            b'n',
            b'0',
            0,
            0,
            0,
        ]);
        message.extend_from_slice(&[
            10,
            0,
            IFLA_ADDRESS as u8,
            0,
            0x9c,
            0xef,
            0xd5,
            0xf6,
            0x36,
            0x47,
        ]);
        let length = message.len() as u32;
        message[..4].copy_from_slice(&length.to_ne_bytes());
        let events = parse_link_events(&message);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].ifindex, 42);
        assert_eq!(events[0].iface.as_deref(), Some("wlan0"));
        assert_eq!(events[0].mac.as_deref(), Some("9c:ef:d5:f6:36:47"));
        assert_eq!(
            parse_mac("9C:EF:D5:F6:36:47"),
            Some([0x9c, 0xef, 0xd5, 0xf6, 0x36, 0x47])
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reviewed_wifi_status_decodes_numeric_tags() {
        let request = decode_wifi_tagged_request(&mesh::tagged::TaggedRecord {
            component: mesh::tagged::NameOrTag::Tag(5),
            method: mesh::tagged::NameOrTag::Tag(1),
            id: Some(json!(11)),
            env: [(mesh::tagged::NameOrTag::Tag(1), json!("wlan0"))]
                .into_iter()
                .collect(),
            ..Default::default()
        })
        .unwrap();
        assert!(
            matches!(request, ReviewedWifiRequest::ApStatus(request) if request.iface.as_deref() == Some("wlan0"))
        );
    }

    #[test]
    fn reviewed_wifi_metrics_decode_numeric_tags() {
        let request = decode_wifi_tagged_request(&mesh::tagged::TaggedRecord {
            component: mesh::tagged::NameOrTag::Tag(5),
            method: mesh::tagged::NameOrTag::Tag(6),
            id: Some(json!(12)),
            env: [(mesh::tagged::NameOrTag::Tag(1), json!("wlan0"))]
                .into_iter()
                .collect(),
            ..Default::default()
        })
        .unwrap();
        assert!(
            matches!(request, ReviewedWifiRequest::RawMetrics(request) if request.iface.as_deref() == Some("wlan0"))
        );
    }

    #[test]
    fn reviewed_pair_probe_plan_decodes_numeric_tags() {
        let request = decode_wifi_tagged_request(&mesh::tagged::TaggedRecord {
            component: mesh::tagged::NameOrTag::Tag(5),
            method: mesh::tagged::NameOrTag::Tag(16),
            id: Some(json!(13)),
            env: [
                (mesh::tagged::NameOrTag::Tag(1), json!("wlan0")),
                (mesh::tagged::NameOrTag::Tag(2), json!("111111111111")),
                (mesh::tagged::NameOrTag::Tag(3), json!("222222222222")),
            ]
            .into_iter()
            .collect(),
            ..Default::default()
        })
        .unwrap();
        assert!(matches!(
            request,
            ReviewedWifiRequest::ProbePlan(request)
                if request.iface.as_deref() == Some("wlan0")
                    && request.source_id == "111111111111"
                    && request.target_id == "222222222222"
        ));
    }

    #[test]
    fn unreviewed_wifi_method_is_not_named_cbor() {
        assert!(
            decode_wifi_tagged_request(&mesh::tagged::TaggedRecord {
                component: mesh::tagged::NameOrTag::Name("wifi".to_owned()),
                method: mesh::tagged::NameOrTag::Name("ap.stop".to_owned()),
                id: Some(json!(11)),
                ..Default::default()
            })
            .is_err()
        );
    }
}
