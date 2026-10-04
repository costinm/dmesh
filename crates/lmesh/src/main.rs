use anyhow::Result;

mod companion;
mod radio;

/// Slots in the node's packet pool, which companion bearers also use.
pub(crate) const HOST_POOL_SLOTS: usize = 32;
type HostPacketPool =
    quic_lite::packet_pool::PacketPool<HOST_POOL_SLOTS, { quic_lite::DEFAULT_PACKET_POOL_SLOT_SIZE }>;
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
    // The raw Wi-Fi bearer (open AP + monitor, NOW and NAN) is `rawnan`'s; it is
    // started from the configured WLAN once the service runs.
    let (espnow, radio, observer, wlan_configured) = radio::create::<HostPacketPool>();
    let mut node = lmesh_wifi::mesh_runtime::HostQuicNode::new(&HOST_PACKET_POOL);
    node.add_bearer(bearer)
        .map_err(|error| anyhow::anyhow!("attach lmesh UDP bearer: {error:?}"))?;
    let now_bearer = node
        .add_bearer(espnow)
        .map_err(|error| anyhow::anyhow!("attach lmesh ESP-NOW bearer: {error:?}"))?;
    // A BLE companion connected at startup; `companion.pair kind=ble` attaches
    // more while running.
    if let Ok(address) = std::env::var("LMESH_BLE_COC") {
        let psm = std::env::var("LMESH_BLE_COC_PSM")
            .ok()
            .map(|value| {
                u16::from_str_radix(value.trim_start_matches("0x"), 16)
                    .or_else(|_| value.parse::<u16>())
            })
            .transpose()?;
        node.add_bearer(lmesh_ble_hci::CocBearer::connect(&address, psm)?)
            .map_err(|error| anyhow::anyhow!("attach lmesh BLE CoC bearer: {error:?}"))?;
    }
    // A serial port attached at startup; a pairing on that path reuses it.
    let mut startup_uart = None;
    if let Some(path) = std::env::var_os("LMESH_UART") {
        let baud = std::env::var("LMESH_UART_BAUD")
            .ok()
            .map(|value| value.parse::<u32>())
            .transpose()?;
        let port = uart_codec::host::UartPort::open(&path, baud)?;
        let mut uart = port.into_tokio::<HOST_POOL_SLOTS, { quic_lite::DEFAULT_PACKET_POOL_SLOT_SIZE }>(
            quic_lite::BearerName::new("uart")
                .ok_or_else(|| anyhow::anyhow!("invalid UART bearer name"))?,
        )?;
        uart.set_sideband_handler(|received| {
            for line in received.logs {
                tracing::info!(target: "uart", %line);
            }
        });
        let bearer = node
            .add_bearer(uart)
            .map_err(|error| anyhow::anyhow!("attach lmesh UART bearer: {error:?}"))?;
        startup_uart = Some((path.to_string_lossy().into_owned(), bearer));
    }
    lmesh_wifi::mesh_runtime::run_mesh_service(
        defaults,
        node,
        now_bearer,
        lmesh_wifi::mesh_runtime::RadioOwner::External,
        Box::new(move |registry, node, own_key, discovery| {
            companion::register(registry, node, own_key, startup_uart);
            radio::register(registry, radio, &observer, discovery, wlan_configured);
        }),
    )
    .await
}
