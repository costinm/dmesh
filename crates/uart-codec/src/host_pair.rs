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
//! bearer-independent one in `dmesh_server::companion_pair`.

use std::boxed::Box;
use std::{
    collections::HashMap,
    format,
    marker::PhantomData,
    net::Ipv6Addr,
    path::Path,
    string::{String, ToString},
    sync::Mutex,
    time::Duration,
};

use dmesh_server::companion_pair::{self, Paired};
use quic_lite::{
    BearerId, BearerName, PacketMeta, PeerL2Address,
    packet_pool::PacketPool,
    tokio::{TokioAssociation, TokioNode},
};

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
    pub store: &'a dmesh_server::device_record::DeviceStore,
}

/// The serial ports attached to one QUIC node. `SLOTS` and `MTU` are the node's
/// packet pool.
pub struct UartCompanion<const SLOTS: usize, const MTU: usize> {
    node: TokioNode,
    attached: Mutex<HashMap<String, BearerId>>,
    _pool: PhantomData<fn() -> PacketPool<SLOTS, MTU>>,
}

impl<const SLOTS: usize, const MTU: usize> UartCompanion<SLOTS, MTU> {
    pub fn new(node: TokioNode) -> Self {
        Self {
            node,
            attached: Mutex::new(HashMap::new()),
            _pool: PhantomData,
        }
    }

    /// Record a port the daemon already attached to the node (for example from
    /// its startup configuration), so a pairing reuses that bearer instead of
    /// opening the port a second time.
    pub fn adopt(&self, path: &str, bearer: BearerId) {
        self.lock().insert(path.to_string(), bearer);
    }

    /// Pair the device on a serial port. The port stays attached afterwards.
    pub async fn pair(&self, request: Pairing<'_>) -> Result<Paired, String> {
        self.with_association(request.path, request.baud, |association| async move {
            companion_pair::pair(
                &association,
                &companion_pair::Pairing {
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
    /// bonds) and remove its owned record. The port stays attached.
    pub async fn unpair(
        &self,
        path: &str,
        baud: Option<u32>,
        store: &dmesh_server::device_record::DeviceStore,
    ) -> Result<Ipv6Addr, String> {
        self.with_association(path, baud, |association| async move {
            companion_pair::unpair(&association, store).await
        })
        .await
    }

    /// Run `operation` on a fresh association over the port's bearer, attaching
    /// the port first when needed. A port this call attached is detached again
    /// if the association cannot be set up, since nothing then answers on it;
    /// so is a stale one, so the next attempt reopens the port.
    async fn with_association<T, F>(
        &self,
        path: &str,
        baud: Option<u32>,
        operation: impl FnOnce(TokioAssociation) -> F,
    ) -> Result<T, String>
    where
        F: std::future::Future<Output = Result<T, String>>,
    {
        let existing = self.lock().get(path).copied();
        let bearer = match existing {
            Some(bearer) => bearer,
            None => self.attach(path, baud).await?,
        };
        let association = match self.associate(bearer).await {
            Ok(association) => association,
            Err(error) => {
                self.lock().remove(path);
                self.node.remove_bearer(bearer).await;
                return Err(format!("UART {path}: {error}"));
            }
        };
        let outcome = operation(association.clone()).await;
        let _ = association.finish().await;
        outcome
    }

    async fn attach(&self, path: &str, baud: Option<u32>) -> Result<BearerId, String> {
        let port = UartPort::open(path, baud).map_err(|error| format!("open {path}: {error}"))?;
        let bearer = port
            .into_tokio::<SLOTS, MTU>(BearerName::new("uart").ok_or("bearer name")?)
            .map_err(|error| format!("start UART bearer: {error}"))?;
        let id = self
            .node
            .add_bearer::<PacketPool<SLOTS, MTU>, { quic_lite::DEFAULT_MAX_PACKET_SIZE }, _>(bearer)
            .await?;
        self.lock().insert(path.to_string(), id);
        Ok(id)
    }

    async fn associate(&self, bearer: BearerId) -> Result<TokioAssociation, String> {
        tokio::time::timeout(SETUP_TIMEOUT, async {
            let association = self
                .node
                .associate(
                    PacketMeta {
                        bearer,
                        peer_l2_address: PeerL2Address::new(1).ok_or("peer address")?,
                        received_at_us: 0,
                    },
                    0,
                )
                .await
                .map_err(|error| format!("start association: {error:?}"))?;
            association
                .wait_established()
                .await
                .map_err(|error| format!("establish association: {error:?}"))?;
            Ok(association)
        })
        .await
        .unwrap_or_else(|_| Err(format!("association timed out after {SETUP_TIMEOUT:?}")))
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, BearerId>> {
        self.attached
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

#[async_trait::async_trait]
impl<const SLOTS: usize, const MTU: usize> dmesh_server::companion::CompanionLink
    for UartCompanion<SLOTS, MTU>
{
    async fn pair(&self, request: dmesh_server::companion::PairRequest<'_>) -> Result<(), String> {
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

    async fn unpair(&self, id: &str, store: &dmesh_server::device_record::DeviceStore) -> Result<(), String> {
        UartCompanion::unpair(self, id, None, store).await.map(|_| ())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dmesh_server::announce::{self, Announce};
    use dmesh_server::device_record::{DeviceRecord, DeviceStore};
    use dmesh_server::{provision, tagged};
    use quic_lite::{QuicNode, tokio::TokioNodeDriver};
    use std::{boxed::Box, vec, vec::Vec, string::ToString, borrow::ToOwned, format, future::Future};
    const SLOTS: usize = 16;
    const MTU: usize = quic_lite::DEFAULT_PACKET_POOL_SLOT_SIZE;
    type Pool = PacketPool<SLOTS, MTU>;

    use dmesh_discovery::{Engine, NoFacts, P256Identity};
    use dmesh_server::stream_service::{RecordHandler, RecordStreamHandler};

    use std::os::fd::{AsRawFd, FromRawFd};
    use std::sync::{Arc, Mutex, atomic::{AtomicBool, Ordering}};

    /// A fake unpaired device: signed discovery plus `provision.install`.
    struct FakeDevice {
        announce: Announce,
        installed: Arc<Mutex<Vec<(String, Vec<u8>, Vec<u8>)>>>,
        accept: bool,
    }

    impl RecordHandler for FakeDevice {
        fn handle<'a>(
            &'a self,
            request: Vec<u8>,
        ) -> std::pin::Pin<Box<dyn Future<Output = std::io::Result<Vec<u8>>> + 'a>> {
            Box::pin(async move {
                let record = tagged::decode(&request).unwrap();
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
                Ok(out[..used.unwrap()].to_vec())
            })
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

    static DEVICE_POOL: Pool = Pool::new();
    static HOST_POOL: Pool = Pool::new();

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
                    let mut node = QuicNode::<Pool>::new(&DEVICE_POOL);
                    node.set_limits(quic_lite::NodeLimits::host()).unwrap();
                    node.set_default_association_limits(quic_lite::AssociationLimits::host()).unwrap();
                    let port = UartPort::open(&path, None).unwrap();
                    node.add_bearer(port.into_tokio::<SLOTS, MTU>(BearerName::new("uart").unwrap()).unwrap()).unwrap();
                    let (handle, driver) =
                        TokioNodeDriver::new(node, quic_lite::AssociationLimits::host().connection);
                    let handler = RecordStreamHandler::new(device, 4096);
                    tokio::select! {
                        _ = driver.run() => {}
                        _ = async {
                            loop {
                                if dmesh_server::stream_service::accept_one(&handle, &handler).await.is_err() {
                                    break;
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


    /// The host's node, as lmesh runs it: one long-lived node whose driver is
    /// already running when a pairing attaches its bearer.
    fn host_node() -> TokioNode {
        let mut node = QuicNode::<Pool>::new(&HOST_POOL);
        node.set_limits(quic_lite::NodeLimits::host()).unwrap();
        node.set_default_association_limits(quic_lite::AssociationLimits::host()).unwrap();
        let (handle, driver) =
            TokioNodeDriver::new(node, quic_lite::AssociationLimits::host().connection);
        tokio::task::spawn_local(async move {
            let _ = driver.run().await;
        });
        handle
    }

    fn companion() -> UartCompanion<SLOTS, MTU> {
        UartCompanion::new(host_node())
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
            let paired = companion().pair(request(&cable, vip6, &store))
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
    fn pairing_again_over_the_wire_replaces_the_secret_and_the_record() {
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
            // the secret again.
            host.pair(request(&cable, vip6, &store)).await.unwrap();
            let second = store.load(&vip6.to_string()).unwrap().unwrap();
            assert_ne!(second.secret, first.secret);
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
    fn unpair_resets_the_device_and_removes_the_record() {
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
            assert!(store.load(&vip6.to_string()).unwrap().is_none());
        });
    }
}
