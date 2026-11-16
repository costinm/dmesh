//! Linux companion pairing over a physical UART: `companion.pair kind=uart`
//! and `companion.unpair kind=uart`.
//!
//! The UART is wired and trusted: the device lets a host on it set or replace
//! the shared secret, and unpair erases it along with the device's BLE bonds.
//! The bearer itself adds no cryptography; the secret is what QUIC-lite later
//! uses to authenticate and encrypt. This file only owns the port. Pairing
//! attaches the UART as an ordinary bearer of the caller's running QUIC node
//! and leaves it attached and in use: a port that is already attached (at
//! startup, or by an earlier pairing) is reused. The exchange itself is the
//! bearer-independent one in `dmesh_discovery::controller`.

use std::boxed::Box;
use std::{
    collections::HashMap,
    format,
    net::Ipv6Addr,
    string::{String, ToString},
    sync::Mutex,
    time::Duration,
};

use dmesh_discovery::controller::{self, ControllerLink, PairRequest, Paired};
use dmesh_discovery::device_record::DeviceStore;
use mesh_api::link::{LinkName, PeerL2Address};
use mesh_api::pool::{DEFAULT_HEADROOM, DEFAULT_MAX_PAYLOAD};
use quic_link::{AssocConfig, ConnectionId, LinkId, LinkProfile, TokioAssocDriver};
use quic_mux::{TokioMux, TokioMuxConfig};

use crate::host::UartPort;

/// Association setup limit; the exchange itself has its own.
const SETUP_TIMEOUT: Duration = Duration::from_secs(20);

/// What to pair.
pub struct Pairing<'a> {
    /// Serial device path.
    pub path: &'a str,
    /// Line rate; `None` for the UART default.
    pub baud: Option<u32>,
    /// The signed device identity the caller expects at this port; when absent,
    /// the device on the port is paired under its own identity.
    pub vip6: Option<Ipv6Addr>,
    /// Name to store on the device; the device's own name when absent.
    pub name: Option<&'a str>,
    /// Compressed P-256 control-plane root to install (33 bytes).
    pub root_public_key: [u8; 33],
    /// Where the device's record is saved.
    pub store: &'a DeviceStore,
}

struct ConnectedUart {
    mux: TokioMux,
    driver_task: tokio::task::JoinHandle<()>,
}

impl Drop for ConnectedUart {
    fn drop(&mut self) {
        self.driver_task.abort();
    }
}

/// The serial ports attached for `companion.pair kind=uart`.
#[derive(Default)]
pub struct UartCompanion {
    attached: Mutex<HashMap<String, ConnectedUart>>,
}

impl UartCompanion {
    pub fn new() -> Self {
        Self::default()
    }

    /// Pair the device on a serial port. The port stays attached afterwards.
    pub async fn pair(&self, request: Pairing<'_>) -> Result<Paired, String> {
        self.with_mux(request.path, request.baud, |mux| async move {
            controller::pair_mux(
                &mux,
                &controller::Pairing {
                    vip6: request.vip6,
                    name: request.name,
                    root_public_key: request.root_public_key,
                    store: request.store,
                    endpoint: ("uart", request.path),
                },
            )
            .await
        })
        .await
    }

    /// Reset the device on `path` to unpaired (it forgets the secret and its BLE
    /// bonds), clear credentials/ownership and keep its discovery/configuration
    /// record. The port stays attached.
    pub async fn unpair(
        &self,
        path: &str,
        baud: Option<u32>,
        store: &DeviceStore,
    ) -> Result<Ipv6Addr, String> {
        self.with_mux(path, baud, |mux| async move {
            controller::unpair_mux(&mux, store).await
        })
        .await
    }

    async fn with_mux<T, F>(
        &self,
        path: &str,
        baud: Option<u32>,
        operation: impl FnOnce(TokioMux) -> F,
    ) -> Result<T, String>
    where
        F: std::future::Future<Output = Result<T, String>>,
    {
        let existing = self.lock().get(path).map(|conn| conn.mux.clone());
        let mux = match existing {
            Some(mux) => mux,
            None => self.attach(path, baud)?,
        };
        let outcome = tokio::time::timeout(SETUP_TIMEOUT, operation(mux))
            .await
            .unwrap_or_else(|_| Err(format!("UART {path}: timed out after {SETUP_TIMEOUT:?}")));
        if outcome.is_err() {
            self.lock().remove(path);
        }
        outcome
    }

    fn attach(&self, path: &str, baud: Option<u32>) -> Result<TokioMux, String> {
        let port = UartPort::open(path, baud).map_err(|error| format!("open {path}: {error}"))?;
        let mut bearer = port
            .into_tokio(LinkName::new("uart").ok_or("link name")?)
            .map_err(|error| format!("start UART bearer: {error}"))?;
        let peer_cid = ConnectionId::new(1).unwrap();
        let mut driver = TokioAssocDriver::new(AssocConfig::default(), 64);
        let profile = LinkProfile::udp_datagram(1, DEFAULT_MAX_PAYLOAD, peer_cid);
        driver
            .add_link_with(
                LinkId(1),
                PeerL2Address::new(1).unwrap(),
                profile,
                |pool, ingress| {
                    bearer.attach(pool, DEFAULT_HEADROOM, ingress)?;
                    Ok::<_, std::io::Error>(bearer)
                },
            )
            .map_err(|error| format!("attach UART {path}: {error}"))?;
        let (tx, rx, driver_task) = driver.spawn();
        let (mux, _acceptor) = TokioMux::spawn(true, TokioMuxConfig::default());
        mux.add_packet_link(tx, rx, DEFAULT_MAX_PAYLOAD, 10);
        self.lock().insert(
            path.to_string(),
            ConnectedUart {
                mux: mux.clone(),
                driver_task,
            },
        );
        Ok(mux)
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, ConnectedUart>> {
        self.attached
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

#[async_trait::async_trait]
impl ControllerLink for UartCompanion {
    async fn pair(&self, request: PairRequest<'_>) -> Result<(), String> {
        UartCompanion::pair(
            self,
            Pairing {
                path: request.id,
                baud: request.baud,
                vip6: request.vip6,
                name: request.name,
                root_public_key: request
                    .root_public_key
                    .ok_or("this controller has no control-plane root key; name one in root_public_key_b64")?,
                store: request.store,
            },
        )
        .await
        .map(|_| ())
    }

    async fn unpair(&self, id: &str, store: &DeviceStore) -> Result<(), String> {
        UartCompanion::unpair(self, id, None, store).await.map(|_| ())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dmesh_discovery::announce::{self, Announce};
    use dmesh_discovery::device_record::DeviceRecord;
    use dmesh_discovery::provision;
    use mesh_api::envelope as tagged;
    use std::{boxed::Box, vec, vec::Vec, string::ToString, borrow::ToOwned, format, future::Future};

    use dmesh_discovery::{Engine, NoFacts, P256Identity};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use std::os::fd::{AsRawFd, FromRawFd};
    use std::sync::{Arc, Mutex, atomic::{AtomicBool, Ordering}};

    /// A fake unpaired device: signed discovery plus `provision.install`.
    struct FakeDevice {
        announce: Announce,
        installed: Arc<Mutex<Vec<(String, Vec<u8>, Vec<u8>)>>>,
        accept: bool,
    }

    impl FakeDevice {
        fn handle(&self, request: &[u8]) -> Vec<u8> {
            let record = tagged::decode(request).unwrap();
            let id = record.id.unwrap();
            let mut out = [0u8; 512];
            let used = if let Some(install) = provision::decode_install(record) {
                if self.accept {
                    self.installed.lock().unwrap().push((
                        install.name.to_owned(),
                        install.root_public_key.to_vec(),
                        install.secret.to_vec(),
                    ));
                }
                tagged::encode_numeric_response(
                    provision::COMPONENT,
                    provision::INSTALL,
                    id,
                    if self.accept { &[0xf5] } else { &[0xf4] },
                    &mut out,
                )
            } else if provision::is_unpair(record) {
                self.installed.lock().unwrap().clear();
                tagged::encode_numeric_response(
                    provision::COMPONENT,
                    provision::UNPAIR,
                    id,
                    &[0xf5],
                    &mut out,
                )
            } else {
                announce::encode_discovery_response(self.announce, id, &mut out)
            };
            out[..used.unwrap()].to_vec()
        }
    }

    fn pty() -> (std::fs::File, std::path::PathBuf, std::fs::File) {
        let (mut master, mut slave) = (0, 0);
        assert_eq!(
            unsafe {
                libc::openpty(&mut master, &mut slave, std::ptr::null_mut(), std::ptr::null(), std::ptr::null())
            },
            0
        );
        let flags = unsafe { libc::fcntl(master, libc::F_GETFL) };
        unsafe { libc::fcntl(master, libc::F_SETFL, flags | libc::O_NONBLOCK) };
        let slave = unsafe { std::fs::File::from_raw_fd(slave) };
        let path = std::fs::read_link(format!("/proc/self/fd/{}", slave.as_raw_fd())).unwrap();
        (unsafe { std::fs::File::from_raw_fd(master) }, path, slave)
    }

    /// Two ptys with their masters cross-connected: a cable between the host
    /// side (returned path) and the device side.
    struct Cable {
        host_path: std::path::PathBuf,
        device_path: std::path::PathBuf,
        stop: Arc<AtomicBool>,
    }

    impl Cable {
        fn new() -> Self {
            use std::io::{Read, Write};
            // The slave descriptors are dropped at once: an exclusive-mode tty
            // stays exclusive until its last descriptor closes, which would make
            // a second open fail here although a real device reopens fine.
            let (mut host_master, host_path, _) = pty();
            let (mut device_master, device_path, _) = pty();
            let stop = Arc::new(AtomicBool::new(false));
            let flag = stop.clone();
            std::thread::spawn(move || {
                let mut buffer = [0u8; 2048];
                while !flag.load(Ordering::Relaxed) {
                    let mut idle = true;
                    if let Ok(count) = host_master.read(&mut buffer)
                        && count > 0
                    {
                        idle = false;
                        let _ = device_master.write_all(&buffer[..count]);
                    }
                    if let Ok(count) = device_master.read(&mut buffer)
                        && count > 0
                    {
                        idle = false;
                        let _ = host_master.write_all(&buffer[..count]);
                    }
                    if idle {
                        std::thread::sleep(Duration::from_millis(1));
                    }
                }
            });
            Self {
                host_path,
                device_path,
                stop,
            }
        }
    }

    impl Drop for Cable {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::Relaxed);
        }
    }

    fn start_device(
        cable: &Cable,
        device: FakeDevice,
    ) {
        let path = cable.device_path.clone();
        std::thread::spawn(move || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(async move {
                    let port = UartPort::open(&path, None).unwrap();
                    let mut bearer = port.into_tokio(LinkName::new("uart").unwrap()).unwrap();
                    let peer_cid = ConnectionId::new(1).unwrap();
                    let mut driver = TokioAssocDriver::new(AssocConfig::default(), 64);
                    let profile = LinkProfile::udp_datagram(1, DEFAULT_MAX_PAYLOAD, peer_cid);
                    driver
                        .add_link_with(
                            LinkId(1),
                            PeerL2Address::new(1).unwrap(),
                            profile,
                            |pool, ingress| {
                                bearer.attach(pool, DEFAULT_HEADROOM, ingress)?;
                                Ok::<_, std::io::Error>(bearer)
                            },
                        )
                        .unwrap();
                    let (tx, rx, driver_task) = driver.spawn();
                    let (_mux, mut acceptor) = TokioMux::spawn(false, TokioMuxConfig::default());
                    _mux.add_packet_link(tx, rx, DEFAULT_MAX_PAYLOAD, 10);
                    tokio::select! {
                        _ = driver_task => {}
                        _ = async {
                            while let Some(mut stream) = acceptor.accept().await {
                                let mut request = Vec::new();
                                if stream.read_to_end(&mut request).await.is_ok() && !request.is_empty() {
                                    let response = device.handle(&request);
                                    let _ = stream.write_all(&response).await;
                                    let _ = stream.shutdown().await;
                                }
                            }
                        } => {}
                    }
                });
        });
    }

    fn signed_device_announce() -> (Announce, Ipv6Addr) {
        let identity = Arc::new(P256Identity::generate());
        let announce = Engine::new(identity, Arc::new(NoFacts)).local_announce().unwrap();
        let vip6 = Ipv6Addr::from(announce::virtual_ip6(announce.public_key()).unwrap());
        (announce, vip6)
    }

    fn companion() -> UartCompanion {
        UartCompanion::new()
    }

    fn request<'a>(cable: &'a Cable, vip6: Ipv6Addr, store: &'a DeviceStore) -> Pairing<'a> {
        Pairing {
            path: cable.host_path.to_str().unwrap(),
            baud: None,
            vip6: Some(vip6),
            name: Some("sensor1"),
            root_public_key: [2u8; 33],
            store,
        }
    }

    fn open_descriptors_of(path: &std::path::Path) -> usize {
        std::fs::read_dir("/proc/self/fd")
            .unwrap()
            .flatten()
            .filter(|entry| std::fs::read_link(entry.path()).is_ok_and(|target| target == path))
            .count()
    }

    fn local<F: Future>(future: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(tokio::task::LocalSet::new().run_until(future))
    }

    #[test]
    fn a_missing_port_is_reported_and_leaves_no_record() {
        local(async {
            let directory = tempfile::tempdir().unwrap();
            let store = DeviceStore::new(directory.path());
            let error = companion().pair(Pairing {
                    path: "/dev/does-not-exist-uart",
                    baud: None,
                    vip6: Some("fc00::1".parse().unwrap()),
                    name: Some("x"),
                    root_public_key: [2; 33],
                    store: &store,
                },
            )
            .await
            .unwrap_err();
            assert!(error.contains("open /dev/does-not-exist-uart"), "{error}");
            assert!(std::fs::read_dir(directory.path()).unwrap().next().is_none());
        });
    }

    #[test]
    fn pairing_over_a_cable_installs_credentials_and_saves_the_owned_record() {
        local(async {
            let cable = Cable::new();
            let (announce, vip6) = signed_device_announce();
            let installed = Arc::new(Mutex::new(Vec::new()));
            start_device(&cable, FakeDevice { announce, installed: installed.clone(), accept: true });
            let directory = tempfile::tempdir().unwrap();
            let store = DeviceStore::new(directory.path());
            let host = companion();
            let paired = host.pair(request(&cable, vip6, &store))
                .await
                .unwrap();
            assert_eq!(paired.vip6, vip6);
            let device_side = installed.lock().unwrap().clone();
            assert_eq!(device_side.len(), 1);
            assert_eq!(device_side[0].0, "sensor1");
            assert_eq!(device_side[0].1, [2u8; 33]);
            // The host's record carries the same secret the device committed.
            let owned = store.load(&vip6.to_string()).unwrap().unwrap();
            assert_eq!(owned.secret, device_side[0].2);
            assert_eq!(owned.secret.len(), 32);
            assert_eq!(owned.public_key, announce.public_key());
            assert_eq!(owned.endpoints.get("uart").map(String::as_str), cable.host_path.to_str());
            // The port stays attached and in use after the pairing.
            tokio::time::sleep(Duration::from_millis(200)).await;
            assert!(open_descriptors_of(&cable.host_path) > 0);
        });
    }

    #[test]
    fn pairing_again_over_the_wire_rotates_only_when_the_root_changes() {
        local(async {
            let cable = Cable::new();
            let (announce, vip6) = signed_device_announce();
            let installed = Arc::new(Mutex::new(Vec::new()));
            start_device(&cable, FakeDevice { announce, installed: installed.clone(), accept: true });
            let directory = tempfile::tempdir().unwrap();
            let store = DeviceStore::new(directory.path());
            // A record from an earlier pairing.
            store.save_paired(
                &DeviceRecord {
                    device_id: "00".repeat(16),
                    name: Some("old".to_owned()),
                    mac: None,
                    public_key: announce.public_key().to_vec(),
                    root_public_key: vec![3; 33],
                    vip6: Some(vip6.to_string()),
                    endpoints: Default::default(),
                    secret: vec![7; 32],
                    ..Default::default()
                },
            )
            .unwrap();
            let host = companion();
            host.pair(request(&cable, vip6, &store)).await.unwrap();
            let first = store.load(&vip6.to_string()).unwrap().unwrap();
            assert_ne!(first.secret, vec![7; 32]);
            assert_eq!(first.secret, installed.lock().unwrap()[0].2);
            assert_eq!(first.name.as_deref(), Some("sensor1"));
            // The port stayed attached, so a second pairing reuses that bearer
            // (a second open of the same port would be refused) and replaces
            // the record without rotating the secret for the same root.
            host.pair(request(&cable, vip6, &store)).await.unwrap();
            let second = store.load(&vip6.to_string()).unwrap().unwrap();
            assert_eq!(second.secret, first.secret);
            assert_eq!(second.secret, installed.lock().unwrap()[1].2);
        });
    }

    #[test]
    fn the_port_alone_is_enough_and_the_device_is_paired_under_its_own_identity() {
        local(async {
            let cable = Cable::new();
            let (announce, vip6) = signed_device_announce();
            let installed = Arc::new(Mutex::new(Vec::new()));
            start_device(&cable, FakeDevice { announce, installed: installed.clone(), accept: true });
            let directory = tempfile::tempdir().unwrap();
            let store = DeviceStore::new(directory.path());
            let mut pairing = request(&cable, vip6, &store);
            pairing.vip6 = None;
            let paired = companion().pair(pairing).await.unwrap();
            assert_eq!(paired.vip6, vip6);
            assert!(store.load(&vip6.to_string()).unwrap().is_some());
            assert_eq!(installed.lock().unwrap().len(), 1);
        });
    }

    #[test]
    fn a_device_with_a_different_identity_is_not_paired() {
        local(async {
            let cable = Cable::new();
            let (announce, _) = signed_device_announce();
            let installed = Arc::new(Mutex::new(Vec::new()));
            start_device(&cable, FakeDevice { announce, installed: installed.clone(), accept: true });
            let directory = tempfile::tempdir().unwrap();
            let store = DeviceStore::new(directory.path());
            let error = companion().pair(request(&cable, "fc00::1234".parse().unwrap(), &store),
            )
            .await
            .unwrap_err();
            assert!(error.contains("not the expected"), "{error}");
            assert!(installed.lock().unwrap().is_empty());
            assert!(std::fs::read_dir(directory.path()).unwrap().next().is_none());
        });
    }

    #[test]
    fn a_refusing_device_leaves_no_owned_record() {
        local(async {
            let cable = Cable::new();
            let (announce, vip6) = signed_device_announce();
            let installed = Arc::new(Mutex::new(Vec::new()));
            start_device(&cable, FakeDevice { announce, installed, accept: false });
            let directory = tempfile::tempdir().unwrap();
            let store = DeviceStore::new(directory.path());
            let error = companion().pair(request(&cable, vip6, &store))
                .await
                .unwrap_err();
            assert!(error.contains("refused"), "{error}");
            assert!(std::fs::read_dir(directory.path()).unwrap().next().is_none());
        });
    }

    #[test]
    fn unpair_resets_the_device_and_preserves_the_discovery_record() {
        local(async {
            let cable = Cable::new();
            let (announce, vip6) = signed_device_announce();
            let installed =
                Arc::new(Mutex::new(vec![("sensor1".to_owned(), vec![2; 33], vec![9; 32])]));
            start_device(&cable, FakeDevice { announce, installed: installed.clone(), accept: true });
            let directory = tempfile::tempdir().unwrap();
            let store = DeviceStore::new(directory.path());
            store.save_paired(
                &DeviceRecord {
                    device_id: "00".repeat(16),
                    name: Some("sensor1".to_owned()),
                    mac: None,
                    public_key: announce.public_key().to_vec(),
                    root_public_key: vec![2; 33],
                    vip6: Some(vip6.to_string()),
                    endpoints: Default::default(),
                    secret: vec![9; 32],
                    ..Default::default()
                },
            )
            .unwrap();
            let removed = companion()
                .unpair(cable.host_path.to_str().unwrap(), None, &store)
                .await
                .unwrap();
            assert_eq!(removed, vip6);
            assert!(installed.lock().unwrap().is_empty());
            let reset = store.load(&vip6.to_string()).unwrap().unwrap();
            assert!(reset.secret.is_empty() && reset.root_public_key.is_empty());
            assert!(!reset.companion);
        });
    }
}
