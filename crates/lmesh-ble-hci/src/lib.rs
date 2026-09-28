//! Linux BLE adapter for DMesh discovery, advertising, and HCI access.
//!
//! The `lmesh` daemon integrates this crate, but transport mechanics live here
//! so the mesh integration layer does not implement a platform bearer.

mod coc;
mod coc_bearer;
mod service;
mod wire;

pub use coc::{COC_PACKET_MAX, CocChannel, DEFAULT_COC_PSM};
pub use coc_bearer::CocBearer;
pub use service::BleService;
pub use wire::{Advertisement, DMESH_BLE_SERVICE_UUID16};

use anyhow::{Context, Result, bail};
use std::os::fd::{AsRawFd, RawFd};
use std::time::Duration;

pub const AF_BLUETOOTH: libc::c_int = 31;
pub const BTPROTO_HCI: libc::c_int = 1;
pub const HCI_CHANNEL_RAW: u16 = 0;

#[repr(C)]
struct SockaddrHci {
    family: libc::sa_family_t,
    dev: u16,
    channel: u16,
}

/// Raw HCI command socket bound to one controller.
pub struct HciDevice {
    fd: RawFd,
    pub dev_id: u16,
}

impl HciDevice {
    pub fn open(dev_id: u16) -> Result<Self> {
        let fd = unsafe { libc::socket(AF_BLUETOOTH, libc::SOCK_RAW, BTPROTO_HCI) };
        if fd < 0 {
            return Err(std::io::Error::last_os_error()).context("open HCI socket");
        }
        let address = SockaddrHci {
            family: AF_BLUETOOTH as _,
            dev: dev_id,
            channel: HCI_CHANNEL_RAW,
        };
        let result = unsafe {
            libc::bind(
                fd,
                (&address as *const SockaddrHci).cast(),
                std::mem::size_of::<SockaddrHci>() as _,
            )
        };
        if result < 0 {
            let error = std::io::Error::last_os_error();
            unsafe {
                libc::close(fd);
            }
            return Err(error).context("bind HCI socket");
        }
        Ok(Self { fd, dev_id })
    }

    pub fn send_command(&self, packet: &[u8]) -> Result<usize> {
        if packet.is_empty() {
            bail!("HCI command packet is empty");
        }
        let sent = unsafe { libc::send(self.fd, packet.as_ptr().cast(), packet.len(), 0) };
        if sent < 0 {
            return Err(std::io::Error::last_os_error()).context("send HCI command");
        }
        Ok(sent as usize)
    }

    pub fn send_le_command(&self, ocf: u16, params: &[u8]) -> Result<usize> {
        if params.len() > u8::MAX as usize {
            bail!("HCI command parameters too large");
        }
        let opcode = (0x08 << 10) | ocf;
        let mut packet = Vec::with_capacity(4 + params.len());
        packet.push(0x01);
        packet.extend_from_slice(&opcode.to_le_bytes());
        packet.push(params.len() as u8);
        packet.extend_from_slice(params);
        self.send_command(&packet)
    }

    pub fn recv_timeout(&self, timeout: Duration) -> Result<Option<Vec<u8>>> {
        let timeout_ms = timeout.as_millis().min(i32::MAX as u128) as i32;
        let mut poll_fd = libc::pollfd {
            fd: self.fd,
            events: libc::POLLIN,
            revents: 0,
        };
        let ready = unsafe { libc::poll(&mut poll_fd, 1, timeout_ms) };
        if ready < 0 {
            return Err(std::io::Error::last_os_error()).context("poll HCI socket");
        }
        if ready == 0 || (poll_fd.revents & libc::POLLIN) == 0 {
            return Ok(None);
        }
        let mut packet = vec![0u8; 260];
        let read = unsafe { libc::recv(self.fd, packet.as_mut_ptr().cast(), packet.len(), 0) };
        if read < 0 {
            return Err(std::io::Error::last_os_error()).context("receive HCI event");
        }
        packet.truncate(read as usize);
        Ok(Some(packet))
    }
}

impl AsRawFd for HciDevice {
    fn as_raw_fd(&self) -> RawFd {
        self.fd
    }
}

impl Drop for HciDevice {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.fd);
        }
    }
}
