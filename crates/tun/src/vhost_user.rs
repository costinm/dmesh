use crate::policy::VmId;
use std::path::PathBuf;

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct VhostUserNetConfig {
    pub socket_path: PathBuf,
    pub vm_id: VmId,
    pub mtu: usize,
    pub mac: [u8; 6],
    pub queue_size: usize,
}

impl VhostUserNetConfig {
    pub fn new(socket_path: impl Into<PathBuf>, vm_id: impl Into<VmId>) -> Self {
        Self {
            socket_path: socket_path.into(),
            vm_id: vm_id.into(),
            mtu: 1500,
            mac: [0x02, 0x00, 0x00, 0x00, 0x00, 0x02],
            queue_size: 256,
        }
    }
}

#[cfg(feature = "vhost-user-net")]
mod backend {
    use super::VhostUserNetConfig;
    use std::io::{Error, Result};
    use std::sync::{Arc, Mutex, MutexGuard};
    use std::thread;

    use vhost::vhost_user::message::{VhostUserProtocolFeatures, VhostUserVirtioFeatures};
    use vhost_user_backend::{VhostUserBackendMut, VhostUserDaemon, VringRwLock};
    use vm_memory::{
        GuestAddress, GuestAddressSpace, GuestMemory, GuestMemoryAtomic, GuestMemoryMmap,
    };
    use vmm_sys_util::epoll::EventSet;

    const VIRTIO_F_VERSION_1: u32 = 32;
    const VIRTIO_NET_F_MTU: u32 = 3;
    const VIRTIO_NET_F_MAC: u32 = 5;
    const VIRTIO_NET_F_STATUS: u32 = 16;
    const VIRTIO_NET_S_LINK_UP: u16 = 1;

    #[derive(Debug, Default, Clone, Eq, PartialEq)]
    pub struct VhostUserNetStats {
        pub acked_features: u64,
        pub event_idx: bool,
        pub memory_regions: usize,
        pub handle_event_calls: u64,
        pub reset_count: u64,
    }

    #[derive(Debug)]
    pub struct VhostUserNetBackend {
        config: VhostUserNetConfig,
        stats: Arc<Mutex<VhostUserNetStats>>,
    }

    fn lock_or_recover<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
        mutex.lock().unwrap_or_else(|poison| poison.into_inner())
    }

    impl VhostUserNetBackend {
        pub fn new(config: VhostUserNetConfig) -> Self {
            Self {
                config,
                stats: Arc::new(Mutex::new(VhostUserNetStats::default())),
            }
        }

        pub fn stats(&self) -> Arc<Mutex<VhostUserNetStats>> {
            self.stats.clone()
        }

        fn config_space(&self) -> [u8; 12] {
            // Virtio-net config space layout per the specification:
            //   offset 0..6   : mac[6]
            //   offset 6..8   : status (u16, VIRTIO_NET_S_LINK_UP etc.)
            //   offset 8..10  : max_virtqueue_pairs (u16)
            //   offset 10..12 : mtu (u16, only valid if VIRTIO_NET_F_MTU set)
            let mut config = [0u8; 12];
            config[..6].copy_from_slice(&self.config.mac);
            config[6..8].copy_from_slice(&VIRTIO_NET_S_LINK_UP.to_le_bytes());
            // We expose 2 queues (1 RX + 1 TX) = 1 virtqueue pair.
            config[8..10].copy_from_slice(&1u16.to_le_bytes());
            config[10..12].copy_from_slice(&(self.config.mtu as u16).to_le_bytes());
            config
        }
    }

    impl VhostUserBackendMut for VhostUserNetBackend {
        type Bitmap = ();
        type Vring = VringRwLock;

        fn num_queues(&self) -> usize {
            2
        }

        fn max_queue_size(&self) -> usize {
            self.config.queue_size
        }

        fn features(&self) -> u64 {
            (1u64 << VIRTIO_F_VERSION_1)
                | (1u64 << VIRTIO_NET_F_MAC)
                | (1u64 << VIRTIO_NET_F_MTU)
                | (1u64 << VIRTIO_NET_F_STATUS)
                | VhostUserVirtioFeatures::PROTOCOL_FEATURES.bits()
        }

        fn acked_features(&mut self, features: u64) {
            lock_or_recover(&self.stats).acked_features = features;
        }

        fn protocol_features(&self) -> VhostUserProtocolFeatures {
            VhostUserProtocolFeatures::MQ
                | VhostUserProtocolFeatures::CONFIG
                | VhostUserProtocolFeatures::REPLY_ACK
        }

        fn reset_device(&mut self) {
            let mut stats = lock_or_recover(&self.stats);
            stats.reset_count += 1;
            stats.acked_features = 0;
            stats.event_idx = false;
        }

        fn set_event_idx(&mut self, enabled: bool) {
            lock_or_recover(&self.stats).event_idx = enabled;
        }

        fn get_config(&self, offset: u32, size: u32) -> Vec<u8> {
            let config = self.config_space();
            let offset = offset as usize;
            let size = size as usize;
            config
                .get(offset..offset.saturating_add(size))
                .unwrap_or_default()
                .to_vec()
        }

        fn set_config(&mut self, _offset: u32, _buf: &[u8]) -> Result<()> {
            Ok(())
        }

        fn update_memory(&mut self, atomic_mem: GuestMemoryAtomic<GuestMemoryMmap>) -> Result<()> {
            let mem = atomic_mem.memory();
            lock_or_recover(&self.stats).memory_regions = mem.iter().count();
            Ok(())
        }

        fn queues_per_thread(&self) -> Vec<u64> {
            vec![2]
        }

        fn handle_event(
            &mut self,
            _device_event: u16,
            _evset: EventSet,
            _vrings: &[VringRwLock],
            _thread_id: usize,
        ) -> Result<()> {
            lock_or_recover(&self.stats).handle_event_calls += 1;
            Ok(())
        }
    }

    pub fn run_vhost_user_net_blocking(config: VhostUserNetConfig) -> Result<()> {
        bind_parent(&config.socket_path)?;
        let mem = GuestMemoryAtomic::new(
            GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0), 0x1000)])
                .map_err(|error| Error::other(format!("initial guest memory: {error}")))?,
        );
        let backend = Arc::new(Mutex::new(VhostUserNetBackend::new(config.clone())));
        let mut daemon = VhostUserDaemon::new("mesh-tun-vhost-net".to_string(), backend, mem)
            .map_err(|error| Error::other(error.to_string()))?;
        daemon
            .serve(&config.socket_path)
            .map_err(|error| Error::other(error.to_string()))
    }

    fn bind_parent(path: &std::path::Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        if path.exists() {
            std::fs::remove_file(path)?;
        }
        Ok(())
    }

    pub async fn run_vhost_user_net(config: VhostUserNetConfig) -> Result<()> {
        tokio::task::spawn_blocking(move || run_vhost_user_net_blocking(config))
            .await
            .map_err(|error| Error::other(error.to_string()))?
    }

    pub fn spawn_vhost_user_net(
        config: VhostUserNetConfig,
    ) -> Result<thread::JoinHandle<Result<()>>> {
        bind_parent(&config.socket_path)?;
        thread::Builder::new()
            .name(format!("mesh-tun-vhost-{}", config.vm_id))
            .spawn(move || run_vhost_user_net_blocking(config))
            .map_err(|error| Error::other(error.to_string()))
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::time::Duration;

        use vhost::vhost_user::message::{
            VhostUserConfigFlags, VhostUserHeaderFlag, VhostUserProtocolFeatures,
        };
        use vhost::vhost_user::{Frontend, VhostUserFrontend};
        use vhost::{VhostBackend, VhostUserMemoryRegionInfo, VringConfigData};
        use vm_memory::{FileOffset, GuestMemory, GuestMemoryMmap};
        use vmm_sys_util::eventfd::EventFd;

        #[test]
        #[ignore = "vhost-user vring negotiation is not used by the current mesh-tun path"]
        fn rust_vmm_frontend_negotiates_memory_and_vrings() {
            let temp = tempfile::tempdir().unwrap();
            let path = temp.path().join("vhost.sock");
            let config = VhostUserNetConfig::new(&path, "vm-test");
            let backend = Arc::new(Mutex::new(VhostUserNetBackend::new(config.clone())));
            let stats = backend.lock().unwrap().stats();
            let mem = GuestMemoryAtomic::new(
                GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0), 0x1000)]).unwrap(),
            );
            let mut daemon =
                VhostUserDaemon::new("test-mesh-tun-vhost".to_string(), backend, mem).unwrap();
            let frontend_path = path.clone();
            let frontend_config = config.clone();

            let server_thread = thread::spawn(move || daemon.serve(&frontend_path));
            while !path.exists() {
                thread::sleep(Duration::from_millis(10));
            }

            let mut frontend = Frontend::connect(&path, 1).unwrap();
            frontend.set_hdr_flags(VhostUserHeaderFlag::NEED_REPLY);

            let features = frontend.get_features().unwrap();
            assert_ne!(features & (1u64 << VIRTIO_NET_F_MAC), 0);
            frontend.set_features(features).unwrap();
            let protocol_features = frontend.get_protocol_features().unwrap();
            assert!(protocol_features.contains(VhostUserProtocolFeatures::MQ));
            assert!(protocol_features.contains(VhostUserProtocolFeatures::CONFIG));
            frontend.set_protocol_features(protocol_features).unwrap();

            assert_eq!(frontend.get_queue_num().unwrap(), 2);
            frontend.set_owner().unwrap();

            let memfd = tempfile::tempfile().unwrap();
            memfd.set_len(0x100000).unwrap();
            let file_offset = FileOffset::new(memfd, 0);
            let guest_mem = GuestMemoryMmap::<()>::from_ranges_with_files(&[(
                GuestAddress(0x100000),
                0x100000,
                Some(file_offset),
            )])
            .unwrap();
            let host_addr = guest_mem.get_host_address(GuestAddress(0x100000)).unwrap() as u64;
            let region = guest_mem.find_region(GuestAddress(0x100000)).unwrap();
            let regions = [VhostUserMemoryRegionInfo::from_guest_region(region).unwrap()];
            frontend.set_mem_table(&regions).unwrap();

            frontend.set_vring_num(0, 256).unwrap();
            let vring = VringConfigData {
                queue_max_size: 256,
                queue_size: 256,
                flags: 0,
                desc_table_addr: host_addr,
                used_ring_addr: host_addr + 0x10000,
                avail_ring_addr: host_addr + 0x20000,
                log_addr: None,
            };
            frontend.set_vring_addr(0, &vring).unwrap();
            let eventfd = EventFd::new(0).unwrap();
            frontend.set_vring_kick(0, &eventfd).unwrap();
            frontend.set_vring_call(0, &eventfd).unwrap();
            frontend.set_vring_enable(0, true).unwrap();

            let buf = [0u8; 12];
            let (_cfg, config_bytes) = frontend
                .get_config(0, 12, VhostUserConfigFlags::empty(), &buf)
                .unwrap();
            assert_eq!(&config_bytes[..6], &frontend_config.mac);
            assert_eq!(
                u16::from_le_bytes([config_bytes[10], config_bytes[11]]),
                1500
            );
            assert_eq!(u16::from_le_bytes([config_bytes[8], config_bytes[9]]), 1);
            frontend.reset_owner().unwrap();
            drop(frontend);
            drop(server_thread);

            let stats = stats.lock().unwrap().clone();
            assert_ne!(stats.acked_features, 0);
            assert_eq!(stats.memory_regions, 1);
        }
    }
}

#[cfg(feature = "vhost-user-net")]
pub use backend::{
    VhostUserNetBackend, VhostUserNetStats, run_vhost_user_net, run_vhost_user_net_blocking,
    spawn_vhost_user_net,
};

#[cfg(not(feature = "vhost-user-net"))]
pub async fn run_vhost_user_net(_config: VhostUserNetConfig) -> Result<(), anyhow::Error> {
    anyhow::bail!("mesh-tun was built without the vhost-user-net feature")
}

#[cfg(not(feature = "vhost-user-net"))]
pub fn spawn_vhost_user_net(
    _config: VhostUserNetConfig,
) -> Result<std::thread::JoinHandle<Result<(), std::io::Error>>, anyhow::Error> {
    anyhow::bail!("mesh-tun was built without the vhost-user-net feature")
}
