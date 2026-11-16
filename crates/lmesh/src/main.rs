use anyhow::Result;
use mesh_api::link::{LinkName, PeerL2Address};
use mesh_api::pool::{DEFAULT_HEADROOM, DEFAULT_MAX_PAYLOAD};
use quic_base::XipLazyPool;
use quic_link::{AssocConfig, ConnectionId, LinkId, LinkProfile, TokioAssocDriver};
use quic_mux::{TokioMux, TokioMuxConfig};

mod companion;
mod radio;

/// Linux mesh daemon with radio and BLE adapters.
#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    tokio::task::LocalSet::new().run_until(run()).await
}

async fn run() -> Result<()> {
    let defaults = lmesh_wifi::mesh_runtime::LMESH_DEFAULTS;
    let mut mux_acceptors = Vec::new();
    let mut driver_tasks = Vec::new();
    let peer_cid = ConnectionId::new(1).expect("non-zero CID");

    // The raw Wi-Fi bearer (open AP + monitor, NOW and NAN) is `rawnan`'s; it is
    // started from the configured WLAN once the service runs.
    let (mut espnow, radio, observer, wlan_configured) = radio::create::<XipLazyPool>();
    let mut now_driver = TokioAssocDriver::new(AssocConfig::default(), 64);
    let now_profile = LinkProfile::radio_short_messages(2, 232, peer_cid, 8, 2_000, 50_000);
    now_driver
        .add_link_with(
            LinkId(1),
            PeerL2Address::new(1).expect("non-zero peer"),
            now_profile,
            |pool, ingress| {
                espnow.attach(pool, ingress);
                Ok::<_, std::convert::Infallible>(espnow)
            },
        )
        .expect("infallible ESP-NOW attach");
    let (now_tx, now_rx, now_task) = now_driver.spawn();
    driver_tasks.push(now_task);
    let (now_mux, now_acceptor) = TokioMux::spawn(false, TokioMuxConfig::default());
    now_mux.add_packet_link(now_tx, now_rx, DEFAULT_MAX_PAYLOAD, 10);
    mux_acceptors.push(now_acceptor);

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
        let mut coc = lmesh_ble_hci::CocBearer::connect(&address, psm)?;
        let mut ble_driver = TokioAssocDriver::new(AssocConfig::default(), 64);
        let ble_profile = LinkProfile::stream_link(1, DEFAULT_MAX_PAYLOAD, 64 * 1024);
        ble_driver
            .add_link_with(
                LinkId(1),
                PeerL2Address::new(1).expect("non-zero peer"),
                ble_profile,
                |pool, ingress| {
                    coc.attach(pool, ingress);
                    Ok::<_, std::convert::Infallible>(coc)
                },
            )
            .expect("infallible BLE CoC attach");
        let (tx, rx, task) = ble_driver.spawn();
        driver_tasks.push(task);
        let (mux, acceptor) = TokioMux::spawn(false, TokioMuxConfig::default());
        mux.add_packet_link(tx, rx, DEFAULT_MAX_PAYLOAD, 10);
        mux_acceptors.push(acceptor);
    }
    // A serial port attached at startup; a pairing on that path reuses it.
    if let Some(path) = std::env::var_os("LMESH_UART") {
        let baud = std::env::var("LMESH_UART_BAUD")
            .ok()
            .map(|value| value.parse::<u32>())
            .transpose()?;
        let port = uart_codec::host::UartPort::open(&path, baud)?;
        let mut uart = port.into_tokio(
            LinkName::new("uart")
                .ok_or_else(|| anyhow::anyhow!("invalid UART bearer name"))?,
        )?;
        uart.set_sideband_handler(|received| {
            for line in received.logs {
                tracing::info!(target: "uart", %line);
            }
        });
        let mut uart_driver = TokioAssocDriver::new(AssocConfig::default(), 64);
        let uart_profile = LinkProfile::udp_datagram(1, DEFAULT_MAX_PAYLOAD, peer_cid);
        uart_driver.add_link_with(
            LinkId(1),
            PeerL2Address::new(1).expect("non-zero peer"),
            uart_profile,
            |pool, ingress| {
                uart.attach(pool, DEFAULT_HEADROOM, ingress)?;
                Ok::<_, std::io::Error>(uart)
            },
        )?;
        let (tx, rx, task) = uart_driver.spawn();
        driver_tasks.push(task);
        let (mux, acceptor) = TokioMux::spawn(false, TokioMuxConfig::default());
        mux.add_packet_link(tx, rx, DEFAULT_MAX_PAYLOAD, 10);
        mux_acceptors.push(acceptor);
    }
    let result = lmesh_wifi::mesh_runtime::run_mesh_service(
        defaults,
        Some(now_mux),
        mux_acceptors,
        lmesh_wifi::mesh_runtime::RadioOwner::External,
        Box::new(move |registry, own_key, discovery| {
            companion::register(registry, own_key);
            radio::register(registry, radio, &observer, discovery, wlan_configured);
        }),
    )
    .await;
    for task in driver_tasks {
        task.abort();
    }
    result
}
