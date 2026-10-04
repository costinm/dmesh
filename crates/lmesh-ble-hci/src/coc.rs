//! Linux L2CAP LE credit-based channel boundary.

use anyhow::{Context, Result, bail};
use std::os::fd::{AsRawFd, RawFd};

const AF_BLUETOOTH: libc::c_int = 31;
const BTPROTO_L2CAP: libc::c_int = 0;
const SOL_BLUETOOTH: libc::c_int = 274;
const BT_SECURITY: libc::c_int = 4;
/// No link encryption: the channel is a plain CoC. Confidentiality and authentication are the
/// QUIC layer's (the shared secret), as on every other DMesh bearer.
const BT_SECURITY_LOW: [u8; 2] = [1, 0];
const BDADDR_LE_PUBLIC: u8 = 0x01;
const BDADDR_LE_RANDOM: u8 = 0x02;

pub(crate) const DEFAULT_COC_PSM: u16 = 0x0080;
/// Maximum opaque QUIC-lite packet carried by one CoC SDU.
pub(crate) const COC_PACKET_MAX: usize = 1100;

#[repr(C)]
struct SockaddrL2 {
    family: libc::sa_family_t,
    psm: u16,
    address: [u8; 6],
    cid: u16,
    address_type: u8,
}

/// Connected kernel L2CAP CoC socket. Pairing and bond policy remain owned by
/// BlueZ/the kernel; this type owns only the reliable record-oriented channel.
pub(crate) struct CocChannel {
    fd: RawFd,
}

impl CocChannel {
    pub(crate) fn connect(address: &str, psm: u16) -> Result<Self> {
        if !(0x0080..=0x00ff).contains(&psm) {
            bail!("BLE CoC PSM must be in the dynamic range 0x0080..=0x00ff");
        }
        let parsed = parse_address(address)?;
        // The kernel refuses LE connections until LE is enabled, and nothing bonds without an
        // agent: do both here (a host with BlueZ has already; this then changes nothing).
        let setup_problem = crate::mgmt::ensure_ready().err();
        let mut last_error = None;
        // ESP controllers may expose either a public or random identity. The
        // Android API hides this distinction, so offer the same address-only
        // contract and try both kernel LE address types.
        for address_type in [BDADDR_LE_PUBLIC, BDADDR_LE_RANDOM]
        {
            match connect_one(parsed, psm, address_type) {
                Ok(fd) => return Ok(Self { fd }),
                Err(error) => last_error = Some(error),
            }
        }
        Err(last_error.expect("two BLE address types attempted"))
            .with_context(|| {
                format!(
                    "connect BLE CoC {address} psm=0x{psm:04x}{}",
                    setup_problem
                        .map(|reason| format!(" (controller setup: {reason})"))
                        .unwrap_or_default()
                )
            })
    }

    pub(crate) fn read_packet(&self, output: &mut [u8]) -> Result<usize> {
        let read = unsafe {
            libc::recv(
                self.fd,
                output.as_mut_ptr().cast(),
                output.len(),
                libc::MSG_TRUNC,
            )
        };
        if read < 0 {
            return Err(std::io::Error::last_os_error()).context("read BLE CoC");
        }
        let read = read as usize;
        if read == 0 {
            bail!("BLE CoC disconnected");
        }
        if read > output.len() {
            bail!(
                "BLE CoC packet of {read} bytes exceeds receive capacity {}",
                output.len()
            );
        }
        Ok(read)
    }

    pub(crate) fn write_packet(&self, packet: &[u8]) -> Result<()> {
        if packet.is_empty() || packet.len() > COC_PACKET_MAX {
            bail!("BLE CoC packet must contain 1..={COC_PACKET_MAX} bytes");
        }
        let sent = unsafe {
            libc::send(
                self.fd,
                packet.as_ptr().cast(),
                packet.len(),
                libc::MSG_NOSIGNAL,
            )
        };
        if sent < 0 {
            return Err(std::io::Error::last_os_error()).context("write BLE CoC packet");
        }
        if sent as usize != packet.len() {
            bail!(
                "partial BLE CoC packet write: {sent}/{} bytes",
                packet.len()
            );
        }
        Ok(())
    }
}

impl CocChannel {
    /// Wake a reader blocked in `read_packet` and fail later writes; the
    /// descriptor itself closes when the last owner drops.
    pub(crate) fn shutdown(&self) {
        unsafe { libc::shutdown(self.fd, libc::SHUT_RDWR) };
    }
}

impl AsRawFd for CocChannel {
    fn as_raw_fd(&self) -> RawFd {
        self.fd
    }
}

impl Drop for CocChannel {
    fn drop(&mut self) {
        unsafe { libc::close(self.fd) };
    }
}

fn connect_one(address: [u8; 6], psm: u16, address_type: u8) -> Result<RawFd> {
    let fd = unsafe {
        libc::socket(
            AF_BLUETOOTH,
            libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC,
            BTPROTO_L2CAP,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error()).context("open BLE L2CAP socket");
    }
    // Plain CoC: no pairing, no bond, nothing to confirm.
    if unsafe {
        libc::setsockopt(
            fd,
            SOL_BLUETOOTH,
            BT_SECURITY,
            BT_SECURITY_LOW.as_ptr().cast(),
            BT_SECURITY_LOW.len() as _,
        )
    } < 0
    {
        let error = std::io::Error::last_os_error();
        unsafe { libc::close(fd) };
        return Err(error).context("set BLE link security");
    }
    // Bind to an LE source address first. The kernel selects LE credit-based flow control (each
    // SDU prefixed with its length) only when the *source* is an LE address; an unbound socket
    // connects but then sends bare packets that the peer parses as K-frames.
    let any_le = SockaddrL2 {
        family: AF_BLUETOOTH as _,
        psm: 0,
        address: [0; 6],
        cid: 0,
        address_type: BDADDR_LE_PUBLIC,
    };
    if unsafe {
        libc::bind(
            fd,
            (&any_le as *const SockaddrL2).cast(),
            std::mem::size_of::<SockaddrL2>() as _,
        )
    } < 0
    {
        let error = std::io::Error::last_os_error();
        unsafe { libc::close(fd) };
        return Err(error).context("bind BLE L2CAP socket to an LE source");
    }
    let peer = SockaddrL2 {
        family: AF_BLUETOOTH as _,
        psm: psm.to_le(),
        address,
        cid: 0,
        address_type,
    };
    let rc = unsafe {
        libc::connect(
            fd,
            (&peer as *const SockaddrL2).cast(),
            std::mem::size_of::<SockaddrL2>() as _,
        )
    };
    if rc < 0 {
        let error = std::io::Error::last_os_error();
        unsafe { libc::close(fd) };
        return Err(error).context("kernel L2CAP connect");
    }
    Ok(fd)
}

fn parse_address(value: &str) -> Result<[u8; 6]> {
    let parts = value.split(':').collect::<Vec<_>>();
    if parts.len() != 6 {
        bail!("BLE address must contain six colon-separated bytes");
    }
    let mut address = [0u8; 6];
    for (index, part) in parts.into_iter().rev().enumerate() {
        if part.len() != 2 {
            bail!("invalid BLE address byte {part:?}");
        }
        address[index] = u8::from_str_radix(part, 16)
            .with_context(|| format!("invalid BLE address byte {part:?}"))?;
    }
    Ok(address)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn linux_address_uses_bluetooth_byte_order() {
        assert_eq!(
            parse_address("AA:BB:CC:DD:EE:FF").unwrap(),
            [0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa]
        );
        assert!(parse_address("AA:BB").is_err());
    }
}
