//! Linux L2CAP LE credit-based channel boundary.

use anyhow::{Context, Result, bail};
use std::os::fd::{AsRawFd, RawFd};
use std::time::Duration;

const BTPROTO_L2CAP: libc::c_int = 0;
const SOL_BLUETOOTH: libc::c_int = 274;
const BT_SECURITY: libc::c_int = 4;
const BT_SECURITY_MEDIUM: [u8; 2] = [2, 0];
const BDADDR_LE_PUBLIC: u8 = 0x01;
const BDADDR_LE_RANDOM: u8 = 0x02;

pub const DEFAULT_COC_PSM: u16 = 0x0080;
/// Maximum opaque QUIC-lite packet carried by one CoC SDU.
pub const COC_PACKET_MAX: usize = 1100;

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
pub struct CocChannel {
    fd: RawFd,
    pub address: String,
    pub psm: u16,
    pub random_address: bool,
}

impl CocChannel {
    /// Legacy manual packet submission. New integrations register this
    /// record-oriented bearer with QuicNode.
    #[deprecated(note = "register the BLE CoC packet bearer with QuicNode")]
    pub fn send_packet(&self, packet: &[u8]) -> Result<()> {
        self.write_packet(packet)
    }

    /// Legacy manual packet receive. New integrations register this
    /// record-oriented bearer with QuicNode.
    #[deprecated(note = "register the BLE CoC packet bearer with QuicNode")]
    pub fn receive_packet(&self, timeout: Duration) -> Result<Option<Vec<u8>>> {
        let mut poll = libc::pollfd {
            fd: self.fd,
            events: libc::POLLIN,
            revents: 0,
        };
        let ready = unsafe {
            libc::poll(
                &mut poll,
                1,
                timeout.as_millis().min(i32::MAX as u128) as i32,
            )
        };
        if ready < 0 {
            return Err(std::io::Error::last_os_error()).context("poll BLE CoC");
        }
        if ready == 0 {
            return Ok(None);
        }
        if poll.revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL) != 0 {
            bail!("BLE CoC disconnected");
        }
        let mut bytes = [0u8; COC_PACKET_MAX];
        let used = self.read_packet(&mut bytes)?;
        Ok(Some(bytes[..used].to_vec()))
    }

    pub fn connect(address: &str, psm: u16) -> Result<Self> {
        if !(0x0080..=0x00ff).contains(&psm) {
            bail!("BLE CoC PSM must be in the dynamic range 0x0080..=0x00ff");
        }
        let parsed = parse_address(address)?;
        let mut last_error = None;
        // ESP controllers may expose either a public or random identity. The
        // Android API hides this distinction, so offer the same address-only
        // contract and try both kernel LE address types.
        for (address_type, random_address) in [(BDADDR_LE_PUBLIC, false), (BDADDR_LE_RANDOM, true)]
        {
            match connect_one(parsed, psm, address_type) {
                Ok(fd) => {
                    let mut security = [0u8; 2];
                    let mut length = security.len() as libc::socklen_t;
                    if unsafe {
                        libc::getsockopt(
                            fd,
                            SOL_BLUETOOTH,
                            BT_SECURITY,
                            security.as_mut_ptr().cast(),
                            &mut length,
                        )
                    } < 0
                        || length < 1
                        || security[0] < BT_SECURITY_MEDIUM[0]
                    {
                        unsafe { libc::close(fd) };
                        bail!("BLE CoC did not negotiate an encrypted link");
                    }
                    return Ok(Self {
                        fd,
                        address: address.to_ascii_uppercase(),
                        psm,
                        random_address,
                    });
                }
                Err(error) => last_error = Some(error),
            }
        }
        Err(last_error.expect("two BLE address types attempted"))
            .with_context(|| format!("connect BLE CoC {address} psm=0x{psm:04x}"))
    }

    pub fn read_packet(&self, output: &mut [u8]) -> Result<usize> {
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

    pub fn write_packet(&self, packet: &[u8]) -> Result<()> {
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
            crate::AF_BLUETOOTH,
            libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC,
            BTPROTO_L2CAP,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error()).context("open BLE L2CAP socket");
    }
    // Ask BlueZ/the kernel for an encrypted link. Its configured agent owns
    // consent and bond persistence; a bare CoC connection is not pairing.
    if unsafe {
        libc::setsockopt(
            fd,
            SOL_BLUETOOTH,
            BT_SECURITY,
            BT_SECURITY_MEDIUM.as_ptr().cast(),
            BT_SECURITY_MEDIUM.len() as _,
        )
    } < 0
    {
        let error = std::io::Error::last_os_error();
        unsafe { libc::close(fd) };
        return Err(error).context("require BLE link security");
    }
    let peer = SockaddrL2 {
        family: crate::AF_BLUETOOTH as _,
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
