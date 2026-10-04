//! Enable LE on the controller through the kernel's Bluetooth management socket.
//!
//! BlueZ is not what the kernel needs; the *LE enabled* controller flag is. Until something sets
//! it through this socket (`bluetoothd` normally does), the kernel refuses every LE connection
//! at once with `ECONNREFUSED`. Setting a controller flag needs `CAP_NET_ADMIN`, which lmesh has
//! from mesh-init. Nothing else is needed: the CoC is not encrypted, so there is no pairing,
//! bond or consent prompt (see `coc.rs`).
//!
//! Setup is best effort and runs once; a host that runs BlueZ already has LE enabled.

use anyhow::{Context, Result, bail};
use std::os::fd::RawFd;
use std::sync::OnceLock;

const AF_BLUETOOTH: libc::c_int = 31;
const BTPROTO_HCI: libc::c_int = 1;
const HCI_CHANNEL_CONTROL: u16 = 3;
const HCI_DEV_NONE: u16 = 0xffff;

const OP_READ_INDEX_LIST: u16 = 0x0003;
const OP_SET_POWERED: u16 = 0x0005;
const OP_SET_LE: u16 = 0x000d;
const EV_COMMAND_COMPLETE: u16 = 0x0001;
const EV_COMMAND_STATUS: u16 = 0x0002;
/// Status of a command the controller already satisfies (for example, powered on).
const STATUS_SUCCESS: u8 = 0;
const STATUS_REJECTED_ALREADY: u8 = 0x0b;

#[repr(C)]
struct SockaddrHci {
    family: libc::sa_family_t,
    dev: u16,
    channel: u16,
}

fn open_control() -> Result<RawFd> {
    let fd = unsafe {
        libc::socket(
            AF_BLUETOOTH,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC,
            BTPROTO_HCI,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error()).context("open Bluetooth management socket");
    }
    let address = SockaddrHci {
        family: AF_BLUETOOTH as _,
        dev: HCI_DEV_NONE,
        channel: HCI_CHANNEL_CONTROL,
    };
    let rc = unsafe {
        libc::bind(
            fd,
            (&address as *const SockaddrHci).cast(),
            std::mem::size_of::<SockaddrHci>() as _,
        )
    };
    if rc < 0 {
        let error = std::io::Error::last_os_error();
        unsafe { libc::close(fd) };
        return Err(error).context("bind Bluetooth management socket (needs CAP_NET_ADMIN)");
    }
    Ok(fd)
}

fn command(opcode: u16, index: u16, parameters: &[u8]) -> Vec<u8> {
    let mut wire = Vec::with_capacity(6 + parameters.len());
    wire.extend_from_slice(&opcode.to_le_bytes());
    wire.extend_from_slice(&index.to_le_bytes());
    wire.extend_from_slice(&(parameters.len() as u16).to_le_bytes());
    wire.extend_from_slice(parameters);
    wire
}

/// One decoded management event: its code, controller index and parameters.
fn parse_event(packet: &[u8]) -> Option<(u16, u16, &[u8])> {
    if packet.len() < 6 {
        return None;
    }
    let code = u16::from_le_bytes([packet[0], packet[1]]);
    let index = u16::from_le_bytes([packet[2], packet[3]]);
    let length = usize::from(u16::from_le_bytes([packet[4], packet[5]]));
    Some((code, index, packet.get(6..6 + length)?))
}

/// The status of the reply to `opcode`, and its data, waiting up to two seconds.
fn exchange(fd: RawFd, opcode: u16, index: u16, parameters: &[u8]) -> Result<(u8, Vec<u8>)> {
    let wire = command(opcode, index, parameters);
    if unsafe { libc::write(fd, wire.as_ptr().cast(), wire.len()) } < 0 {
        return Err(std::io::Error::last_os_error()).context("write management command");
    }
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
    let mut buffer = [0u8; 1024];
    while std::time::Instant::now() < deadline {
        let mut poll = libc::pollfd { fd, events: libc::POLLIN, revents: 0 };
        if unsafe { libc::poll(&mut poll, 1, 200) } <= 0 {
            continue;
        }
        let read = unsafe { libc::read(fd, buffer.as_mut_ptr().cast(), buffer.len()) };
        if read < 0 {
            return Err(std::io::Error::last_os_error()).context("read management event");
        }
        let Some((code, _, parameters)) = parse_event(&buffer[..read as usize]) else {
            continue;
        };
        if matches!(code, EV_COMMAND_COMPLETE | EV_COMMAND_STATUS)
            && parameters.len() >= 3
            && u16::from_le_bytes([parameters[0], parameters[1]]) == opcode
        {
            return Ok((parameters[2], parameters[3..].to_vec()));
        }
    }
    bail!("management command {opcode:#06x} timed out")
}

fn set(fd: RawFd, opcode: u16, index: u16, value: u8) -> Result<()> {
    let (status, _) = exchange(fd, opcode, index, &[value])?;
    if status != STATUS_SUCCESS && status != STATUS_REJECTED_ALREADY {
        bail!("management command {opcode:#06x} failed with status {status:#04x}");
    }
    Ok(())
}

/// Power the first controller, enable LE and bonding, and set the IO capability.
fn configure(fd: RawFd) -> Result<u16> {
    let (status, list) = exchange(fd, OP_READ_INDEX_LIST, HCI_DEV_NONE, &[])?;
    if status != STATUS_SUCCESS || list.len() < 4 || u16::from_le_bytes([list[0], list[1]]) == 0 {
        bail!("no Bluetooth controller");
    }
    let index = u16::from_le_bytes([list[2], list[3]]);
    set(fd, OP_SET_POWERED, index, 1)?;
    set(fd, OP_SET_LE, index, 1)?;
    Ok(index)
}

static READY: OnceLock<std::result::Result<u16, String>> = OnceLock::new();

/// Prepare the controller once. The error is kept and returned on every call, so each
/// connection attempt can report why LE was not available.
pub(crate) fn ensure_ready() -> std::result::Result<u16, String> {
    READY
        .get_or_init(|| {
            let fd = open_control().map_err(|error| format!("{error:#}"))?;
            match configure(fd) {
                Ok(index) => {
                    unsafe { libc::close(fd) };
                    Ok(index)
                }
                Err(error) => {
                    unsafe { libc::close(fd) };
                    Err(format!("{error:#}"))
                }
            }
        })
        .clone()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_command_is_opcode_index_length_then_parameters_in_little_endian() {
        assert_eq!(
            command(OP_SET_LE, 0, &[1]),
            [0x0d, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01]
        );
        assert_eq!(command(OP_READ_INDEX_LIST, HCI_DEV_NONE, &[]), [3, 0, 0xff, 0xff, 0, 0]);
    }

    #[test]
    fn an_event_is_decoded_and_a_truncated_one_is_refused() {
        let wire = [0x0f, 0x00, 0x02, 0x00, 0x03, 0x00, 1, 2, 3];
        assert_eq!(parse_event(&wire), Some((0x000f, 2, &[1u8, 2, 3][..])));
        assert_eq!(parse_event(&wire[..8]), None);
        assert_eq!(parse_event(&wire[..5]), None);
    }
}
