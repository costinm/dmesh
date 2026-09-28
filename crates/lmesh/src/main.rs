use anyhow::Result;

type HostPacketPool =
    quic_lite::packet_pool::PacketPool<32, { quic_lite::DEFAULT_PACKET_POOL_SLOT_SIZE }>;
static HOST_PACKET_POOL: HostPacketPool = HostPacketPool::new();

/// Linux mesh daemon with radio and BLE adapters.
#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    tokio::task::LocalSet::new().run_until(run()).await
}

async fn run() -> Result<()> {
    let defaults = lmesh_wifi::mesh_runtime::LMESH_DEFAULTS;
    let bind = std::net::SocketAddr::from((std::net::Ipv6Addr::UNSPECIFIED, defaults.udp_port));
    let bearer = quic_lite::bearer_udp::TokioUdpBearer::<64>::bind(bind).await?;
    let wifi_iface = std::env::var("LMESH_WIFI_IFACE").unwrap_or_else(|_| "wlan1".to_owned());
    let (espnow, espnow_ingress) =
        lmesh_wifi::espnow_bearer::EspNowBearer::<HostPacketPool>::new(wifi_iface);
    let mut node = lmesh_wifi::mesh_runtime::HostQuicNode::new(None, &HOST_PACKET_POOL);
    node.add_bearer(bearer)
        .map_err(|error| anyhow::anyhow!("attach lmesh UDP bearer: {error:?}"))?;
    node.add_bearer(espnow)
        .map_err(|error| anyhow::anyhow!("attach lmesh ESP-NOW bearer: {error:?}"))?;
    if let Ok(address) = std::env::var("LMESH_BLE_COC") {
        let psm = std::env::var("LMESH_BLE_COC_PSM")
            .ok()
            .map(|value| {
                u16::from_str_radix(value.trim_start_matches("0x"), 16)
                    .or_else(|_| value.parse::<u16>())
            })
            .transpose()?
            .unwrap_or(lmesh_ble_hci::DEFAULT_COC_PSM);
        let channel = lmesh_ble_hci::CocChannel::connect(&address, psm)?;
        node.add_bearer(lmesh_ble_hci::CocBearer::new(channel))
            .map_err(|error| anyhow::anyhow!("attach lmesh BLE CoC bearer: {error:?}"))?;
    }
    if let Some(path) = std::env::var_os("LMESH_UART") {
        let baud = std::env::var("LMESH_UART_BAUD")
            .ok()
            .map(|value| value.parse::<u32>())
            .transpose()?;
        let port = uart_codec::host::UartPort::open(&path, baud)?;
        let mut uart = port.into_tokio::<32, { quic_lite::DEFAULT_PACKET_POOL_SLOT_SIZE }>(
            quic_lite::BearerName::new("uart")
                .ok_or_else(|| anyhow::anyhow!("invalid UART bearer name"))?,
        )?;
        uart.set_sideband_handler(|received| {
            for line in received.logs {
                tracing::info!(target: "uart", %line);
            }
        });
        node.add_bearer(uart)
            .map_err(|error| anyhow::anyhow!("attach lmesh UART bearer: {error:?}"))?;
    }
    lmesh_wifi::mesh_runtime::run_mesh_service(defaults, node, espnow_ingress).await
}
