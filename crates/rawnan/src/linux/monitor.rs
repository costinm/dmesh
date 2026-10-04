//! Moved from `lmesh-wifi/src/radio.rs` (see notes/plans/lmesh-wifi-extraction.md).
#![allow(clippy::too_many_arguments)]
use super::*;

pub struct MonitorTxSocket {
    pub fd: RawFd,
}

pub struct MonitorRxSocket {
    pub fd: RawFd,
}

pub struct DataSocket {
    pub fd: RawFd,
    pub ifindex: u32,
}

impl MonitorTxSocket {
    pub fn open(iface: &str) -> Result<Self> {
        let ifindex = ifindex(iface)?;
        let fd = unsafe {
            libc::socket(
                libc::AF_PACKET,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                (ETH_P_ALL.to_be()) as i32,
            )
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error())
                .context("failed to open AF_PACKET raw socket for monitor TX");
        }
        let addr = libc::sockaddr_ll {
            sll_family: libc::AF_PACKET as libc::sa_family_t,
            sll_protocol: ETH_P_ALL.to_be(),
            sll_ifindex: ifindex as i32,
            sll_hatype: 0,
            sll_pkttype: 0,
            sll_halen: 0,
            sll_addr: [0; 8],
        };
        let rc = unsafe {
            libc::bind(
                fd,
                &addr as *const libc::sockaddr_ll as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
            )
        };
        if rc < 0 {
            let error = std::io::Error::last_os_error();
            unsafe {
                libc::close(fd);
            }
            return Err(error).with_context(|| format!("failed to bind AF_PACKET to {iface}"));
        }
        Ok(Self { fd })
    }

    pub fn send(&self, packet: &[u8]) -> Result<usize> {
        // The monitor socket is already bound to its VIF and protocol.  Use
        // the connected-style write rather than a destination-less sendto:
        // mt7921u accepts the latter locally without placing the radiotap
        // packet on the driver TX queue.
        let written = unsafe {
            libc::send(
                self.fd,
                packet.as_ptr() as *const libc::c_void,
                packet.len(),
                libc::MSG_DONTWAIT,
            )
        };
        if written < 0 {
            Err(std::io::Error::last_os_error()).context("failed to send monitor frame")
        } else {
            Ok(written as usize)
        }
    }
}

impl MonitorRxSocket {
    pub fn open(iface: &str) -> Result<Self> {
        let ifindex = ifindex(iface)?;
        let fd = unsafe {
            libc::socket(
                libc::AF_PACKET,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                (ETH_P_ALL.to_be()) as i32,
            )
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error())
                .context("failed to open AF_PACKET raw socket for monitor RX");
        }
        let addr = libc::sockaddr_ll {
            sll_family: libc::AF_PACKET as libc::sa_family_t,
            sll_protocol: ETH_P_ALL.to_be(),
            sll_ifindex: ifindex as i32,
            sll_hatype: 0,
            sll_pkttype: 0,
            sll_halen: 0,
            sll_addr: [0; 8],
        };
        let rc = unsafe {
            libc::bind(
                fd,
                &addr as *const libc::sockaddr_ll as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
            )
        };
        if rc < 0 {
            let error = std::io::Error::last_os_error();
            unsafe {
                libc::close(fd);
            }
            return Err(error).with_context(|| format!("failed to bind AF_PACKET to {iface}"));
        }
        // Bursty action responses can arrive while the callback is parsing
        // and re-encoding a QUIC datagram. Increase the kernel receive queue
        // so a short userspace scheduling delay is measured as QUIC loss only
        // when the RF frame was actually missed, not as AF_PACKET overflow.
        let receive_buffer: libc::c_int = 1 << 20;
        unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_RCVBUF,
                &receive_buffer as *const libc::c_int as *const libc::c_void,
                std::mem::size_of_val(&receive_buffer) as libc::socklen_t,
            );
        }
        Ok(Self { fd })
    }

    pub fn recv(&self, buf: &mut [u8]) -> std::io::Result<usize> {
        let read =
            unsafe { libc::recv(self.fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0) };
        if read < 0 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(read as usize)
        }
    }

    pub fn set_receive_timeout(&self, timeout: Duration) -> Result<()> {
        let micros = timeout.as_micros().min(i64::MAX as u128) as i64;
        let value = libc::timeval {
            tv_sec: micros / 1_000_000,
            tv_usec: micros % 1_000_000,
        };
        let rc = unsafe {
            libc::setsockopt(
                self.fd,
                libc::SOL_SOCKET,
                libc::SO_RCVTIMEO,
                &value as *const libc::timeval as *const libc::c_void,
                std::mem::size_of_val(&value) as libc::socklen_t,
            )
        };
        if rc < 0 {
            return Err(std::io::Error::last_os_error())
                .context("failed to set monitor RX timeout");
        }
        Ok(())
    }

}

impl DataSocket {
    pub fn open(iface: &str) -> Result<Self> {
        let ifindex = ifindex(iface)?;
        let fd = unsafe {
            libc::socket(
                libc::AF_PACKET,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                (ETH_P_ALL.to_be()) as i32,
            )
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error())
                .context("failed to open AF_PACKET raw socket for data path");
        }
        let addr = libc::sockaddr_ll {
            sll_family: libc::AF_PACKET as libc::sa_family_t,
            sll_protocol: ETH_P_ALL.to_be(),
            sll_ifindex: ifindex as i32,
            sll_hatype: 0,
            sll_pkttype: 0,
            sll_halen: 0,
            sll_addr: [0; 8],
        };
        let rc = unsafe {
            libc::bind(
                fd,
                &addr as *const libc::sockaddr_ll as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
            )
        };
        if rc < 0 {
            let error = std::io::Error::last_os_error();
            unsafe {
                libc::close(fd);
            }
            return Err(error).with_context(|| format!("failed to bind AF_PACKET to {iface}"));
        }
        Ok(Self { fd, ifindex })
    }


    pub fn send(&self, packet: &[u8]) -> Result<usize> {
        let written = unsafe {
            libc::send(
                self.fd,
                packet.as_ptr() as *const libc::c_void,
                packet.len(),
                0,
            )
        };
        if written < 0 {
            Err(std::io::Error::last_os_error()).context("failed to send data frame")
        } else {
            Ok(written as usize)
        }
    }

}

impl Drop for MonitorTxSocket {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.fd);
        }
    }
}

impl Drop for MonitorRxSocket {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.fd);
        }
    }
}

impl Drop for DataSocket {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.fd);
        }
    }
}

pub fn send_monitor_frame(
    iface: &str,
    channel: u8,
    frame: &[u8],
    tx_rate_mbps: Option<u8>,
) -> Result<Value> {
    let monitor_iface = monitor_iface_name(iface);
    // NAN receive and NOW TX use one service-owned monitor fixture. A packet
    // send must not replace it: that used to turn a working broad NAN receive
    // setup into a TX-only active monitor, and it made a test request alter
    // host radio state. Service startup owns the one-time fixture setup.
    let setup = require_existing_monitor_iface(&monitor_iface)?;
    let packet = build_radiotap_packet_at_rate(frame, tx_rate_mbps)?;
    let socket = MonitorTxSocket::open(&monitor_iface)?;
    let written = socket.send(&packet)?;
    if written != packet.len() {
        bail!(
            "short monitor frame write: wrote {written}, expected {}",
            packet.len()
        );
    }
    Ok(json!({
        "iface": monitor_iface,
        "channel": channel,
        "packet_len": packet.len(),
        "setup": setup,
    }))
}

pub fn ensure_monitor_iface(
    base_iface: &str,
    monitor_iface: &str,
    channel: u8,
    active: bool,
    recreate: bool,
    exclusive_phy: bool,
) -> Result<Value> {
    // Public raw-radio calls may name either the owned base (`wlan0`) or its
    // conventional monitor child (`wlan0mon`).  A monitor cannot create or
    // own another monitor VIF, so always perform VIF lifecycle operations on
    // the base in the latter case.
    let base_iface = base_iface.strip_suffix("mon").unwrap_or(base_iface);
    // `send_monitor_frame` is on the packet path. Once the listener/client
    // has prepared the VIF, repeating `ip`/`iw` setup for every response adds
    // hundreds of milliseconds and can itself perturb the radio. Reuse the
    // existing VIF for the non-recreate path; explicit active-mode startup
    // still takes the full lifecycle below when the caller requested it.
    if !recreate && ifindex(monitor_iface).is_ok() {
        return Ok(json!({
            "iface": monitor_iface,
            "reused": true,
            "channel": channel,
            "active": true,
        }));
    }
    let mut steps = Vec::new();
    // A monitor VIF can exist while its parent is administratively down. For
    // active raw-NAN operation the dedicated radio must be owned by monitor
    // mode: leaving the managed parent up makes channel selection succeed only
    // nominally and packets are looped back to AF_PACKET without reaching RF.
    // An active monitor must own the PHY.  In particular, do not bring the
    // managed parent up before replacing a passive monitor: mac80211 then
    // keeps the old VIF busy and AF_PACKET reports a successful local write
    // without an RF transmit.  Take the parent down first, replace the VIF,
    // then bring only the active monitor up.
    if active && recreate && exclusive_phy {
        steps.push(link_state_result(base_iface, false));
    } else {
        steps.push(link_state_result(base_iface, true));
    }
    if recreate && ifindex(monitor_iface).is_ok() {
        steps.push(link_state_result(monitor_iface, false));
        let delete = ifindex(monitor_iface)
            .and_then(|index| Nl80211Socket::open()?.delete_interface(index))
            .map(|_| {
                json!({
                    "ok": true,
                    "backend": "nl80211",
                    "operation": "del_interface",
                    "iface": monitor_iface,
                })
            })
            .unwrap_or_else(|error| {
                json!({
                    "ok": false,
                    "backend": "nl80211",
                    "operation": "del_interface",
                    "iface": monitor_iface,
                    "error": format!("{error:#}"),
                })
            });
        steps.push(delete);
    }
    if ifindex(monitor_iface).is_err() {
        let create = ifindex(base_iface)
            .and_then(|index| {
                let socket = Nl80211Socket::open()?;
                let wiphy = socket.interface_wiphy(index)?;
                socket
                    .new_interface(wiphy, monitor_iface, NL80211_IFTYPE_MONITOR)
                    .map(|_| wiphy)
            })
            .map(|wiphy| {
                json!({
                    "ok": true,
                    "backend": "nl80211",
                    "operation": "new_interface",
                    "type": "monitor",
                    "iface": monitor_iface,
                    "wiphy": wiphy,
                })
            })
            .unwrap_or_else(|error| {
                json!({
                    "ok": false,
                    "backend": "nl80211",
                    "operation": "new_interface",
                    "type": "monitor",
                    "iface": monitor_iface,
                    "error": format!("{error:#}"),
                })
            });
        steps.push(create);
    }
    steps.push(link_state_result(monitor_iface, true));
    if active && !recreate && exclusive_phy {
        steps.push(link_state_result(base_iface, false));
    }
    let channel_step = ifindex(monitor_iface)
        .and_then(|index| Nl80211Socket::open()?.set_channel_ht20(index, channel_to_freq(channel)))
        .map(|_| {
            json!({
                "program": "nl80211",
                "operation": "set_channel_ht20",
                "iface": monitor_iface,
                "channel": channel,
                "ok": true,
            })
        })
        .unwrap_or_else(|error| {
            json!({
                "program": "nl80211",
                "operation": "set_channel_ht20",
                "iface": monitor_iface,
                "channel": channel,
                "ok": false,
                "error": format!("{error:#}"),
            })
        });
    let channel_busy = !channel_step
        .get("ok")
        .and_then(Value::as_bool)
        .unwrap_or(false)
        && channel_step
            .get("error")
            .and_then(Value::as_str)
            .map(|error| error.contains("busy"))
            .unwrap_or(false);
    steps.push(channel_step);
    if channel_busy {
        steps.push(json!({
            "program": "nl80211",
            "operation": "set_channel_ht20",
            "iface": monitor_iface,
            "channel": channel,
            "ok": true,
            "skipped": true,
            "reason": "base interface owns the channel; monitor follows it",
        }));
    }
    // The managed parent is deliberately down for an active monitor.  Pin the
    // final monitor VIF through nl80211 as well: several USB drivers accept
    // the earlier parent-VIF channel request but leave the newly-created
    // monitor with no operational channel and silently consume AF_PACKET TX.
    let monitor_channel = ifindex(monitor_iface).and_then(|ifindex| {
        let socket = Nl80211Socket::open()?;
        socket.set_channel_ht20(ifindex, channel_to_freq(channel))
    });
    steps.push(match monitor_channel {
        Ok(()) => json!({
            "program": "nl80211",
            "operation": "set_channel_ht20",
            "iface": monitor_iface,
            "channel": channel,
            "ok": true,
        }),
        Err(error) => json!({
            "program": "nl80211",
            "operation": "set_channel_ht20",
            "iface": monitor_iface,
            "channel": channel,
            "ok": false,
            "error": format!("{error:#}"),
        }),
    });
    let channel_ok = steps.iter().any(|step| {
        step.get("ok").and_then(Value::as_bool).unwrap_or(false)
            && step.get("operation").and_then(Value::as_str) == Some("set_channel_ht20")
    });
    let failed = steps
        .iter()
        .filter(|step| {
            if step.get("ok").and_then(Value::as_bool).unwrap_or(false) {
                return false;
            }
            let is_channel_busy = step.get("operation").and_then(Value::as_str)
                == Some("set_channel_ht20")
                && step
                    .get("error")
                    .and_then(Value::as_str)
                    .map(|error| error.contains("busy"))
                    .unwrap_or(false);
            if is_channel_busy && channel_ok {
                return false;
            }
            true
        })
        .cloned()
        .collect::<Vec<_>>();
    if !failed.is_empty() {
        bail!(
            "failed to prepare monitor interface {monitor_iface}: {}",
            json!(failed)
        );
    }
    Ok(json!(steps))
}

/// Test-facing monitor users may only consume the persistent fixture.  Radio
/// setup is deliberately kept out of this helper so a listener/check/probe
/// request cannot disturb a live AP or make a passive local loopback appear
/// to be an RF result.
pub fn require_existing_monitor_iface(monitor_iface: &str) -> Result<Value> {
    ifindex(monitor_iface)?;
    Ok(json!({
        "iface": monitor_iface,
        "reused": true,
        "lifecycle": "externally_prepared",
    }))
}

pub fn build_radiotap_packet_at_rate(frame: &[u8], rate_mbps: Option<u8>) -> Result<Vec<u8>> {
    build_radiotap_packet_at_rate_with_ack(frame, rate_mbps, false)
}

pub fn build_radiotap_packet_at_rate_with_ack(
    frame: &[u8],
    rate_mbps: Option<u8>,
    request_ack: bool,
) -> Result<Vec<u8>> {
    let rate_mbps = rate_mbps.unwrap_or(1);
    if !matches!(
        rate_mbps,
        1 | 2 | 5 | 6 | 9 | 11 | 12 | 18 | 24 | 36 | 48 | 54
    ) {
        bail!("unsupported radiotap legacy rate {rate_mbps} Mbps");
    }
    let mut packet = Vec::with_capacity(12 + frame.len());
    packet.extend_from_slice(&[
        0x00,
        0x00, // radiotap version, pad
        0x0c,
        0x00, // radiotap length
        0x04,
        0x80,
        0x00,
        0x00,                        // present: RATE and TX_FLAGS
        rate_mbps.saturating_mul(2), // RATE in 500 kbps units
        0x00,                        // pad TX_FLAGS to u16 alignment
        if request_ack { 0x00 } else { 0x08 },
        0x00, // TX_FLAGS: request MAC ACK for unicast, no ACK for broadcast
    ]);
    packet.extend_from_slice(frame);
    Ok(packet)
}
