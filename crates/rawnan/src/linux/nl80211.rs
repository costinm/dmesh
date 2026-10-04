//! Moved from `lmesh-wifi/src/radio.rs` (see notes/plans/lmesh-wifi-extraction.md).
#![allow(clippy::too_many_arguments)]
use super::*;

pub const NETLINK_GENERIC: libc::c_int = 16;

pub const NETLINK_EXT_ACK: libc::c_int = 11;

pub const GENL_ID_CTRL: u16 = 16;

pub const CTRL_CMD_GETFAMILY: u8 = 3;

pub const CTRL_ATTR_FAMILY_ID: u16 = 1;

pub const CTRL_ATTR_FAMILY_NAME: u16 = 2;

pub const NLMSGERR_ATTR_MSG: u16 = 1;

pub const NLMSGERR_ATTR_OFFS: u16 = 2;

pub const NLMSGERR_ATTR_MISS_TYPE: u16 = 5;

pub const NL80211_GENL_VERSION: u8 = 1;

pub const NL80211_CMD_SET_WIPHY: u8 = 2;

pub const NL80211_CMD_GET_INTERFACE: u8 = 5;

// `NL80211_ATTR_TX_RATES` is interpreted only by this command.  Sending the
// attribute in SET_WIPHY can ACK without constraining per-interface data TX.
pub const NL80211_CMD_SET_TX_BITRATE_MASK: u8 = 57;

pub const NL80211_CMD_SET_INTERFACE: u8 = 6;

pub const NL80211_CMD_NEW_INTERFACE: u8 = 7;

pub const NL80211_CMD_DEL_INTERFACE: u8 = 8;

pub const NL80211_CMD_REMAIN_ON_CHANNEL: u8 = 55;

pub const NL80211_CMD_REGISTER_FRAME: u8 = 58;

pub const NL80211_CMD_FRAME: u8 = 59;

pub const NL80211_CMD_START_AP: u8 = 15;

pub const NL80211_CMD_STOP_AP: u8 = 16;

pub const NL80211_CMD_GET_STATION: u8 = 17;

pub const NL80211_CMD_NEW_STATION: u8 = 19;

pub const NL80211_CMD_DEL_STATION: u8 = 20;

pub const NL80211_CMD_CONNECT: u8 = 46;

pub const NL80211_ATTR_WIPHY: u16 = 1;

pub const NL80211_ATTR_IFINDEX: u16 = 3;

pub const NL80211_ATTR_IFNAME: u16 = 4;

pub const NL80211_ATTR_IFTYPE: u16 = 5;

// NL80211_ATTR_TX_RATES is the nested per-band rate policy used by `iw
// set bitrates`.  Keep the values local rather than depending on libnl/iw.
pub const NL80211_ATTR_TX_RATES: u16 = 90;

pub const NL80211_ATTR_MAC: u16 = 6;

pub const NL80211_ATTR_BEACON_INTERVAL: u16 = 12;

pub const NL80211_ATTR_DTIM_PERIOD: u16 = 13;

pub const NL80211_ATTR_BEACON_HEAD: u16 = 14;

pub const NL80211_ATTR_BEACON_TAIL: u16 = 15;

pub const NL80211_ATTR_STA_AID: u16 = 16;

pub const NL80211_ATTR_STA_FLAGS2: u16 = 67;

pub const NL80211_ATTR_STA_LISTEN_INTERVAL: u16 = 18;

pub const NL80211_ATTR_STA_SUPPORTED_RATES: u16 = 19;

pub const NL80211_ATTR_STA_INFO: u16 = 21;

pub const NL80211_ATTR_HT_CAPABILITY: u16 = 31;

pub const NL80211_ATTR_BSS_BASIC_RATES: u16 = 36;

pub const NL80211_ATTR_WIPHY_FREQ: u16 = 38;

pub const NL80211_ATTR_WIPHY_CHANNEL_TYPE: u16 = 39;

pub const NL80211_ATTR_IE: u16 = 42;

pub const NL80211_ATTR_FREQ_FIXED: u16 = 60;

pub const NL80211_ATTR_FRAME: u16 = 51;

pub const NL80211_ATTR_SSID: u16 = 52;

pub const NL80211_ATTR_AUTH_TYPE: u16 = 53;

pub const NL80211_ATTR_CIPHER_SUITE_GROUP: u16 = 74;

pub const NL80211_ATTR_DURATION: u16 = 87;

pub const NL80211_ATTR_FRAME_MATCH: u16 = 91;

pub const NL80211_ATTR_FRAME_TYPE: u16 = 101;

pub const NL80211_ATTR_BSS_HT_OPMODE: u16 = 109;

pub const NL80211_ATTR_OFFCHANNEL_TX_OK: u16 = 108;

pub const NL80211_ATTR_HIDDEN_SSID: u16 = 126;

pub const NL80211_ATTR_IE_PROBE_RESP: u16 = 127;

pub const NL80211_ATTR_IE_ASSOC_RESP: u16 = 128;

pub const NL80211_ATTR_STA_WME: u16 = 129;

pub const NL80211_ATTR_STA_CAPABILITY: u16 = 171;

pub const NL80211_ATTR_STA_EXT_CAPABILITY: u16 = 172;

pub const NL80211_ATTR_TX_NO_CCK_RATE: u16 = 135;

pub const NL80211_ATTR_DONT_WAIT_FOR_ACK: u16 = 142;

pub const NL80211_ATTR_PROBE_RESP: u16 = 145;

pub const NL80211_ATTR_RX_SIGNAL_DBM: u16 = 151;

pub const NL80211_ATTR_CHANNEL_WIDTH: u16 = 159;

pub const NL80211_ATTR_CENTER_FREQ1: u16 = 160;

pub const NL80211_ATTR_SOCKET_OWNER: u16 = 204;

pub const NL80211_ATTR_COOKIE: u16 = 88;

pub const NL80211_AUTHTYPE_OPEN_SYSTEM: u32 = 0;

pub const NL80211_HIDDEN_SSID_NOT_IN_USE: u32 = 0;

pub const NL80211_CHAN_NO_HT: u32 = 0;

pub const NL80211_CHAN_HT20: u32 = 1;

pub const NL80211_CHAN_HT40PLUS: u32 = 3;

pub const NL80211_CHAN_WIDTH_20_NOHT: u32 = 0;

pub const NL80211_CHAN_WIDTH_20: u32 = 1;

pub const NL80211_CHAN_WIDTH_40: u32 = 2;

pub const WLAN_CIPHER_SUITE_WEP40: u32 = 0x000f_ac01;

pub const NL80211_STA_INFO_INACTIVE_TIME: u16 = 1;

pub const NL80211_STA_INFO_RX_BYTES: u16 = 2;

pub const NL80211_STA_INFO_TX_BYTES: u16 = 3;

pub const NL80211_STA_INFO_SIGNAL: u16 = 7;

pub const NL80211_STA_INFO_TX_BITRATE: u16 = 8;

pub const NL80211_STA_INFO_RX_PACKETS: u16 = 9;

pub const NL80211_STA_INFO_TX_PACKETS: u16 = 10;

pub const NL80211_STA_INFO_TX_RETRIES: u16 = 11;

pub const NL80211_STA_INFO_TX_FAILED: u16 = 12;

pub const NL80211_STA_INFO_SIGNAL_AVG: u16 = 13;

pub const NL80211_STA_INFO_RX_BITRATE: u16 = 14;

pub const NL80211_STA_INFO_CONNECTED_TIME: u16 = 16;

pub const NL80211_STA_INFO_STA_FLAGS: u16 = 17;

pub const NL80211_STA_INFO_RX_BYTES64: u16 = 23;

pub const NL80211_STA_INFO_TX_BYTES64: u16 = 24;

pub const NL80211_STA_INFO_EXPECTED_THROUGHPUT: u16 = 28;

pub const NL80211_STA_INFO_RX_DROP_MISC: u16 = 29;

pub const NL80211_STA_INFO_RX_DURATION: u16 = 32;

pub const NL80211_STA_INFO_ACK_SIGNAL: u16 = 34;

pub const NL80211_STA_INFO_ACK_SIGNAL_AVG: u16 = 35;

pub const NL80211_STA_INFO_RX_MPDUS: u16 = 36;

pub const NL80211_STA_INFO_FCS_ERROR_COUNT: u16 = 37;

pub const NL80211_STA_INFO_TX_DURATION: u16 = 39;

pub const NL80211_RATE_INFO_BITRATE: u16 = 1;

pub const NL80211_RATE_INFO_MCS: u16 = 2;

pub const NL80211_RATE_INFO_40_MHZ_WIDTH: u16 = 3;

pub const NL80211_RATE_INFO_SHORT_GI: u16 = 4;

pub const NL80211_RATE_INFO_BITRATE32: u16 = 5;

pub const NL80211_RATE_INFO_VHT_MCS: u16 = 6;

pub const NL80211_RATE_INFO_VHT_NSS: u16 = 7;

pub const NL80211_TXRATE_LEGACY: u16 = 1;

pub const NL80211_TXRATE_HT: u16 = 2;

pub const NL80211_IFTYPE_STATION: u32 = 2;

pub const NL80211_IFTYPE_AP: u32 = 3;

pub const NL80211_IFTYPE_MONITOR: u32 = 6;

pub const NL80211_STA_FLAG_AUTHORIZED: u32 = 1 << 1;

pub const NL80211_STA_FLAG_SHORT_PREAMBLE: u32 = 1 << 2;

pub const NL80211_STA_FLAG_WME: u32 = 1 << 3;

pub const NL80211_STA_FLAG_AUTHENTICATED: u32 = 1 << 5;

pub const NL80211_STA_FLAG_ASSOCIATED: u32 = 1 << 7;

// The stable Recovery AP is a bulk-data HT20 network.  Do not admit CCK or
// low OFDM fallbacks. The ESP C6 refuses association when 24 Mbps is present
// in this AP's basic-rate set, so retain mandatory 6 Mbps solely for
// BSS/control compatibility while excluding 9/12/18 Mbps and all CCK rates.
// Optional data rates remain 24/36/48/54 plus HT. This rate set applies to
// beacon, probe, association, and the nl80211 AP profile.
pub const OPEN_AP_OFDM_BASIC_RATES: [u8; 1] = [0x8c];

pub const OPEN_AP_OFDM_EXTENDED_RATES: [u8; 4] = [0x30, 0x48, 0x60, 0x6c];

// The AP driver selects HT short-GI data rates when the peer supports them.
// Advertise SGI-20 in the management IE as well: sending short-GI frames
// after advertising no SGI leaves an ESP STA with a contradictory negotiated
// PHY profile. HT40 additionally enables the matching SGI-40 bit below.
pub const HOSTAPD_HT20_CAPABILITY: [u8; 28] = [
    0x2d, 26, 0x2c, 0x00, 0x1b, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

// The manual AP SME must advertise the same width in beacon, probe, and
// association response as nl80211 operates. Keep the shared channel-6 lab
// and production default at HT20: NAN/NOW, STA, and AP must all share the
// same 20 MHz channel without occupying the adjacent channel. HT40 is an
// explicit opt-in for a dedicated AP experiment only.
pub const DEFAULT_OPEN_AP_HT40: bool = false;

pub const NLM_F_DUMP: u16 = 0x300;

// Netlink attributes reserve the high two type bits for NLA_F_NESTED and
// NLA_F_NET_BYTEORDER.  Match the attribute number independently of those
// flags; station/rate information is commonly nested.
pub const NLA_TYPE_MASK: u16 = 0x3fff;

pub const NLMSG_ERROR: u16 = 2;

pub const NLMSG_DONE: u16 = 3;

pub const NLM_F_REQUEST: u16 = 0x01;

pub const NLM_F_ACK: u16 = 0x04;

pub const IFF_UP: u32 = 0x1;

pub const NLM_F_CREATE: u16 = 0x400;

pub const NLM_F_REPLACE: u16 = 0x100;

pub const IFA_ADDRESS: u16 = 1;

pub const IFA_LOCAL: u16 = 2;

pub const IFA_BROADCAST: u16 = 4;

/// Linux uses this flag in `/proc/net/if_inet6` while duplicate-address
/// detection is still running.  Do not bind the scoped UDP6 bearer until it
/// has cleared.
pub const IPV6_ADDR_TENTATIVE: u32 = 0x40;

pub fn open_ap_basic_rates() -> &'static [u8] {
    &OPEN_AP_OFDM_BASIC_RATES
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct GenlMsgHdr {
    pub cmd: u8,
    pub version: u8,
    pub reserved: u16,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct NlAttrHdr {
    pub nla_len: u16,
    pub nla_type: u16,
}

pub struct Nl80211Socket {
    pub fd: RawFd,
    pub family_id: u16,
}

impl Nl80211Socket {
    pub fn open() -> Result<Self> {
        let fd = unsafe {
            libc::socket(
                libc::AF_NETLINK,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                NETLINK_GENERIC,
            )
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error())
                .context("failed to open NETLINK_GENERIC socket");
        }
        let enable: libc::c_int = 1;
        unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_NETLINK,
                NETLINK_EXT_ACK,
                &enable as *const libc::c_int as *const libc::c_void,
                std::mem::size_of_val(&enable) as libc::socklen_t,
            );
        }
        let mut addr: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        addr.nl_family = libc::AF_NETLINK as libc::sa_family_t;
        addr.nl_pid = 0;
        addr.nl_groups = 0;
        let rc = unsafe {
            libc::bind(
                fd,
                &addr as *const libc::sockaddr_nl as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
            )
        };
        if rc < 0 {
            let error = std::io::Error::last_os_error();
            unsafe {
                libc::close(fd);
            }
            return Err(error).context("failed to bind NETLINK_GENERIC socket");
        }
        let mut socket = Self { fd, family_id: 0 };
        let family_id = socket.resolve_family("nl80211")?;
        socket.family_id = family_id;
        Ok(socket)
    }

    pub fn resolve_family(&self, name: &str) -> Result<u16> {
        let mut payload = genl_payload(CTRL_CMD_GETFAMILY, 2);
        let mut name_bytes = name.as_bytes().to_vec();
        name_bytes.push(0);
        append_attr(&mut payload, CTRL_ATTR_FAMILY_NAME, &name_bytes);
        self.send_genl(GENL_ID_CTRL, libc::NLM_F_REQUEST as u16, 1, &payload)?;
        let response = self.recv_netlink()?;
        let attrs = genl_attrs(&response)?;
        for (kind, value) in attrs {
            if kind == CTRL_ATTR_FAMILY_ID && value.len() >= 2 {
                return Ok(u16::from_ne_bytes([value[0], value[1]]));
            }
        }
        bail!("nl80211 generic netlink family id not found")
    }

    pub fn register_dmesh_action(&self, ifindex: u32) -> Result<()> {
        let mut matches = vec![
            dmesh_vendor_action_header(RAW_WIFI_BROADCAST),
            dmesh_vendor_action_header(RAW_WIFI_MULTICAST),
        ];
        if let Some(iface) = ifname_from_ifindex(ifindex) {
            if let Ok(mac) = iface_mac(&iface) {
                matches.push(dmesh_vendor_action_header(mac));
                matches.push(dmesh_vendor_action_header(raw_receive_mac(mac)));
            }
        }
        let mut registered = 0;
        for frame_match in matches {
            match self.register_frame(ifindex, IEEE80211_ACTION_FRAME_TYPE, &frame_match) {
                Ok(()) => registered += 1,
                Err(error) if error.to_string().contains("Match already configured") => {}
                Err(error) if registered == 0 => return Err(error),
                Err(_) => {}
            }
        }
        Ok(())
    }

    pub fn register_nan_discovery_frames(&self, ifindex: u32) -> Result<()> {
        // The fallback receives both NAN timing beacons and Service Discovery
        // Frames.  Some adapters suppress management RX on an active monitor
        // VIF, while still delivering registered frames on the base interface.
        // Register only the NAN public/vendor action categories rather than a
        // catch-all action frame so normal P2P/WPA traffic cannot fill this
        // discovery path.
        for (frame_type, frame_match) in [
            (0x0080, &[][..]),
            (IEEE80211_ACTION_FRAME_TYPE, &[0x04][..]),
            (IEEE80211_ACTION_FRAME_TYPE, &[0x7f][..]),
        ] {
            match self.register_frame(ifindex, frame_type, frame_match) {
                Ok(()) => {}
                Err(error) if error.to_string().contains("Match already configured") => {}
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }

    /// Match raw-NAN USD frames while retaining the
    /// ESP-NOW/DMesh vendor-action registrations on the same nl80211 socket.
    pub fn register_open_ap_sme_frames(&self, ifindex: u32) -> Vec<Value> {
        // AP SME, NAN public, and DMesh/ESP-NOW vendor actions share this
        // nl80211 receive socket; the broad public/vendor matches cover all
        // of them without duplicate registrations.
        let registrations: [(&str, u16, &[u8]); 17] = [
            ("auth_open", 0x00b0, &[0x00, 0x00]),
            ("assoc_req", 0x0000, &[]),
            ("reassoc_req", 0x0020, &[]),
            ("disassoc", 0x00a0, &[]),
            ("deauth", 0x00c0, &[]),
            ("probe_req", 0x0040, &[]),
            // NAN discovery/beacon frames are ordinary management beacons;
            // receive them on the same AP-SME socket as AP management.
            ("beacon", 0x0080, &[]),
            ("action_public", IEEE80211_ACTION_FRAME_TYPE, &[0x04]),
            (
                "action_radio_measurement",
                IEEE80211_ACTION_FRAME_TYPE,
                &[0x05, 0x01],
            ),
            (
                "action_link_measurement",
                IEEE80211_ACTION_FRAME_TYPE,
                &[0x05, 0x03],
            ),
            (
                "action_neighbor_report",
                IEEE80211_ACTION_FRAME_TYPE,
                &[0x05, 0x04],
            ),
            (
                "action_fast_bss_transition",
                IEEE80211_ACTION_FRAME_TYPE,
                &[0x06],
            ),
            ("action_sa_query", IEEE80211_ACTION_FRAME_TYPE, &[0x08]),
            (
                "action_protected_dual",
                IEEE80211_ACTION_FRAME_TYPE,
                &[0x09],
            ),
            ("action_wnm", IEEE80211_ACTION_FRAME_TYPE, &[0x0a]),
            ("action_fils", IEEE80211_ACTION_FRAME_TYPE, &[0x11]),
            ("action_vendor", IEEE80211_ACTION_FRAME_TYPE, &[0x7f]),
        ];
        let mut reports = Vec::new();
        for (idx, (name, frame_type, frame_match)) in registrations.iter().enumerate() {
            match self.register_frame_with_seq(
                ifindex,
                *frame_type,
                frame_match,
                20_u32.saturating_add(idx as u32),
            ) {
                Ok(()) => reports.push(json!({
                    "name": name,
                    "ok": true,
                    "frame_type": format!("0x{frame_type:04x}"),
                    "match_hex": hex_bytes(frame_match),
                })),
                Err(error) if *name == "beacon" => reports.push(json!({
                    "name": name,
                    "ok": false,
                    "required": false,
                    "frame_type": format!("0x{frame_type:04x}"),
                    "match_hex": hex_bytes(frame_match),
                    "error": format!("{error:#}"),
                })),
                Err(error) if format!("{error:#}").contains("Operation already in progress") => {
                    reports.push(json!({
                        "name": name,
                        "ok": true,
                        "already_registered": true,
                        "frame_type": format!("0x{frame_type:04x}"),
                        "match_hex": hex_bytes(frame_match),
                    }))
                }
                Err(error) => reports.push(json!({
                    "name": name,
                    "ok": false,
                    "frame_type": format!("0x{frame_type:04x}"),
                    "match_hex": hex_bytes(frame_match),
                    "error": format!("{error:#}"),
                })),
            }
        }
        reports
    }

    pub fn register_frame(&self, ifindex: u32, frame_type: u16, frame_match: &[u8]) -> Result<()> {
        self.register_frame_with_seq(ifindex, frame_type, frame_match, 2)
    }

    pub fn register_frame_with_seq(
        &self,
        ifindex: u32,
        frame_type: u16,
        frame_match: &[u8],
        seq: u32,
    ) -> Result<()> {
        let mut payload = genl_payload(NL80211_CMD_REGISTER_FRAME, NL80211_GENL_VERSION);
        append_attr(&mut payload, NL80211_ATTR_IFINDEX, &ifindex.to_ne_bytes());
        append_attr(
            &mut payload,
            NL80211_ATTR_FRAME_TYPE,
            &frame_type.to_ne_bytes(),
        );
        append_attr(&mut payload, NL80211_ATTR_FRAME_MATCH, frame_match);
        self.send_genl(
            self.family_id,
            (libc::NLM_F_REQUEST | libc::NLM_F_ACK) as u16,
            seq,
            &payload,
        )?;
        self.recv_ack()
    }

    pub fn remain_on_channel(&self, ifindex: u32, freq: u32, duration_ms: u32) -> Result<u64> {
        let mut payload = genl_payload(NL80211_CMD_REMAIN_ON_CHANNEL, NL80211_GENL_VERSION);
        append_attr(&mut payload, NL80211_ATTR_IFINDEX, &ifindex.to_ne_bytes());
        append_attr(&mut payload, NL80211_ATTR_WIPHY_FREQ, &freq.to_ne_bytes());
        append_attr(
            &mut payload,
            NL80211_ATTR_DURATION,
            &duration_ms.to_ne_bytes(),
        );
        self.send_genl(
            self.family_id,
            (libc::NLM_F_REQUEST | libc::NLM_F_ACK) as u16,
            4,
            &payload,
        )?;
        let response = self
            .recv_reply()
            .context("nl80211 remain-on-channel failed")?;
        let cookie = genl_attrs(&response)?
            .into_iter()
            .find_map(|(kind, value)| {
                (kind & NLA_TYPE_MASK == NL80211_ATTR_COOKIE && value.len() >= 8)
                    .then(|| u64::from_ne_bytes(value[..8].try_into().unwrap()))
            })
            .ok_or_else(|| anyhow::anyhow!("nl80211 remain-on-channel returned no cookie"))?;
        let settle_ms = duration_ms.saturating_div(2).clamp(1, 20);
        std::thread::sleep(Duration::from_millis(settle_ms as u64));
        Ok(cookie)
    }

    pub fn set_interface_type(&self, ifindex: u32, iftype: u32) -> Result<()> {
        let mut payload = genl_payload(NL80211_CMD_SET_INTERFACE, NL80211_GENL_VERSION);
        append_attr(&mut payload, NL80211_ATTR_IFINDEX, &ifindex.to_ne_bytes());
        append_attr(&mut payload, NL80211_ATTR_IFTYPE, &iftype.to_ne_bytes());
        self.send_genl(
            self.family_id,
            (libc::NLM_F_REQUEST | libc::NLM_F_ACK) as u16,
            5,
            &payload,
        )?;
        self.recv_ack().context("nl80211 set interface type failed")
    }

    pub fn delete_interface(&self, ifindex: u32) -> Result<()> {
        let mut payload = genl_payload(NL80211_CMD_DEL_INTERFACE, NL80211_GENL_VERSION);
        append_attr(&mut payload, NL80211_ATTR_IFINDEX, &ifindex.to_ne_bytes());
        self.send_genl(
            self.family_id,
            (libc::NLM_F_REQUEST | libc::NLM_F_ACK) as u16,
            7,
            &payload,
        )?;
        self.recv_ack().context("nl80211 delete interface failed")
    }

    pub fn interface_wiphy(&self, ifindex: u32) -> Result<u32> {
        let mut payload = genl_payload(NL80211_CMD_GET_INTERFACE, NL80211_GENL_VERSION);
        append_attr(&mut payload, NL80211_ATTR_IFINDEX, &ifindex.to_ne_bytes());
        self.send_genl(self.family_id, libc::NLM_F_REQUEST as u16, 8, &payload)?;
        let response = self.recv_reply().context("nl80211 get interface failed")?;
        genl_attrs(&response)?
            .into_iter()
            .find_map(|(kind, value)| {
                (kind & NLA_TYPE_MASK == NL80211_ATTR_WIPHY && value.len() >= 4)
                    .then(|| u32::from_ne_bytes(value[..4].try_into().unwrap()))
            })
            .ok_or_else(|| anyhow::anyhow!("nl80211 get interface returned no wiphy"))
    }

    /// Read an interface's type, wiphy and operating frequency back from the kernel.
    /// `freq` is absent while the interface has no channel context (for example an
    /// AP that is not started).
    pub fn interface_info(&self, ifindex: u32) -> Result<InterfaceInfo> {
        let mut payload = genl_payload(NL80211_CMD_GET_INTERFACE, NL80211_GENL_VERSION);
        append_attr(&mut payload, NL80211_ATTR_IFINDEX, &ifindex.to_ne_bytes());
        self.send_genl(self.family_id, libc::NLM_F_REQUEST as u16, 8, &payload)?;
        let response = self.recv_reply().context("nl80211 get interface failed")?;
        let mut info = InterfaceInfo::default();
        for (kind, value) in genl_attrs(&response)? {
            let number = |value: &[u8]| {
                (value.len() >= 4).then(|| u32::from_ne_bytes(value[..4].try_into().unwrap()))
            };
            match kind & NLA_TYPE_MASK {
                NL80211_ATTR_IFTYPE => info.iftype = number(value),
                NL80211_ATTR_WIPHY => info.wiphy = number(value),
                NL80211_ATTR_WIPHY_FREQ => info.freq = number(value),
                _ => {}
            }
        }
        Ok(info)
    }

    pub fn new_interface(&self, wiphy: u32, name: &str, iftype: u32) -> Result<()> {
        if name.is_empty() || name.len() > libc::IFNAMSIZ - 1 || name.as_bytes().contains(&0) {
            bail!("invalid child interface name {name:?}");
        }
        let mut payload = genl_payload(NL80211_CMD_NEW_INTERFACE, NL80211_GENL_VERSION);
        append_attr(&mut payload, NL80211_ATTR_WIPHY, &wiphy.to_ne_bytes());
        let mut nul_name = Vec::with_capacity(name.len() + 1);
        nul_name.extend_from_slice(name.as_bytes());
        nul_name.push(0);
        append_attr(&mut payload, NL80211_ATTR_IFNAME, &nul_name);
        append_attr(&mut payload, NL80211_ATTR_IFTYPE, &iftype.to_ne_bytes());
        self.send_genl(
            self.family_id,
            (libc::NLM_F_REQUEST | libc::NLM_F_ACK) as u16,
            9,
            &payload,
        )?;
        self.recv_ack().context("nl80211 new interface failed")
    }

    pub fn recv_reply(&self) -> Result<Vec<u8>> {
        loop {
            let response = self.recv_netlink_raw()?;
            if let Some(error) = netlink_error(&response) {
                bail!(
                    "netlink error: {}{}",
                    std::io::Error::from_raw_os_error(error),
                    netlink_extack_message(&response)
                );
            }
            if genl_header(&response).is_some() {
                return Ok(response);
            }
        }
    }

    pub fn set_channel_ht20(&self, ifindex: u32, freq: u32) -> Result<()> {
        let mut payload = genl_payload(NL80211_CMD_SET_WIPHY, NL80211_GENL_VERSION);
        append_attr(&mut payload, NL80211_ATTR_IFINDEX, &ifindex.to_ne_bytes());
        append_attr(&mut payload, NL80211_ATTR_WIPHY_FREQ, &freq.to_ne_bytes());
        append_attr(
            &mut payload,
            NL80211_ATTR_WIPHY_CHANNEL_TYPE,
            &NL80211_CHAN_HT20.to_ne_bytes(),
        );
        append_attr(
            &mut payload,
            NL80211_ATTR_CHANNEL_WIDTH,
            &NL80211_CHAN_WIDTH_20.to_ne_bytes(),
        );
        append_attr(&mut payload, NL80211_ATTR_CENTER_FREQ1, &freq.to_ne_bytes());
        self.send_genl(
            self.family_id,
            (libc::NLM_F_REQUEST | libc::NLM_F_ACK) as u16,
            16,
            &payload,
        )?;
        self.recv_ack().context("nl80211 set HT20 channel failed")
    }

    pub fn set_channel_ht40_plus(&self, ifindex: u32, freq: u32) -> Result<()> {
        let mut payload = genl_payload(NL80211_CMD_SET_WIPHY, NL80211_GENL_VERSION);
        append_attr(&mut payload, NL80211_ATTR_IFINDEX, &ifindex.to_ne_bytes());
        append_attr(&mut payload, NL80211_ATTR_WIPHY_FREQ, &freq.to_ne_bytes());
        append_attr(
            &mut payload,
            NL80211_ATTR_WIPHY_CHANNEL_TYPE,
            &NL80211_CHAN_HT40PLUS.to_ne_bytes(),
        );
        append_attr(
            &mut payload,
            NL80211_ATTR_CHANNEL_WIDTH,
            &NL80211_CHAN_WIDTH_40.to_ne_bytes(),
        );
        append_attr(
            &mut payload,
            NL80211_ATTR_CENTER_FREQ1,
            &(freq + 10).to_ne_bytes(),
        );
        self.send_genl(
            self.family_id,
            (libc::NLM_F_REQUEST | libc::NLM_F_ACK) as u16,
            16,
            &payload,
        )?;
        self.recv_ack().context("nl80211 set HT40+ channel failed")
    }

    /// Set the per-wiphy 2.4 GHz TX-rate allow-list. Legacy rates are encoded
    /// in 500-kbit/s units; HT rates are MCS indexes. Omitting both restores
    /// the driver's automatic rate policy.
    pub fn set_tx_rate_profile(
        &self,
        ifindex: u32,
        rate_mbps: Option<u8>,
        ht_mcs: Option<u8>,
        disable_b: bool,
    ) -> Result<()> {
        let mut payload = genl_payload(NL80211_CMD_SET_TX_BITRATE_MASK, NL80211_GENL_VERSION);
        append_attr(&mut payload, NL80211_ATTR_IFINDEX, &ifindex.to_ne_bytes());
        if let Some(band) = tx_rate_profile_band(rate_mbps, ht_mcs, disable_b) {
            let mut bands = Vec::new();
            append_attr(&mut bands, 1 << 15, &band); // NL80211_BAND_2GHZ | NLA_F_NESTED
            append_attr(&mut payload, NL80211_ATTR_TX_RATES | (1 << 15), &bands);
        }
        self.send_genl(
            self.family_id,
            (libc::NLM_F_REQUEST | libc::NLM_F_ACK) as u16,
            17,
            &payload,
        )?;
        self.recv_ack()
            .context("nl80211 set TX rate profile failed")
    }



    pub fn start_open_ap(
        &self,
        ifindex: u32,
        mac: [u8; 6],
        ssid: &str,
        channel: u8,
        freq: u32,
        ht40: bool,
        beacon_interval_tu: u16,
    ) -> std::result::Result<Value, (anyhow::Error, Vec<Value>)> {
        let esp_beacon_head =
            build_open_beacon_head(mac, ssid, channel).map_err(|error| (error, Vec::new()))?;
        let hostapd_beacon_head =
            build_open_beacon_head_with_capability(mac, ssid, channel, 0x0401)
                .map_err(|error| (error, Vec::new()))?;
        let esp_beacon_tail = esp_open_ap_beacon_tail_for_device(mac, channel);
        let hostapd_beacon_tail = hostapd_open_ap_beacon_tail_for_device(mac, channel, ht40);
        let esp_probe_ies = esp_open_ap_probe_ies_for_device(ssid, mac, channel)
            .map_err(|error| (error, Vec::new()))?;
        let esp_probe_resp =
            build_open_probe_resp_with_ies(mac, ssid, channel, 0x0421, &esp_probe_ies)
                .map_err(|error| (error, Vec::new()))?;
        let hostapd_probe_ies = hostapd_open_ap_probe_ies_for_device(ssid, mac, channel, ht40)
            .map_err(|error| (error, Vec::new()))?;
        let hostapd_probe_resp =
            build_open_probe_resp_with_ies(mac, ssid, channel, 0x0401, &hostapd_probe_ies)
                .map_err(|error| (error, Vec::new()))?;
        let profiles = [
            ApStartProfile {
                name: "hostapd_exact_ht",
                probe_resp: true,
                channel_type: if ht40 {
                    NL80211_CHAN_HT40PLUS
                } else {
                    NL80211_CHAN_HT20
                },
                channel_width: if ht40 {
                    NL80211_CHAN_WIDTH_40
                } else {
                    NL80211_CHAN_WIDTH_20
                },
                explicit_width: false,
                freq_fixed: false,
                hostapd_ies: true,
                hostapd_crypto: true,
                hostapd_tail: true,
                capability: 0x0401,
            },
            ApStartProfile {
                name: "hostapd_exact_noht",
                probe_resp: true,
                channel_type: NL80211_CHAN_NO_HT,
                channel_width: NL80211_CHAN_WIDTH_20_NOHT,
                explicit_width: false,
                freq_fixed: false,
                hostapd_ies: true,
                hostapd_crypto: true,
                hostapd_tail: true,
                capability: 0x0401,
            },
            ApStartProfile {
                name: "hostapd_noht",
                probe_resp: true,
                channel_type: NL80211_CHAN_NO_HT,
                channel_width: NL80211_CHAN_WIDTH_20_NOHT,
                explicit_width: false,
                freq_fixed: false,
                hostapd_ies: false,
                hostapd_crypto: false,
                hostapd_tail: false,
                capability: 0x0421,
            },
            ApStartProfile {
                name: "hostapd_noht_no_probe",
                probe_resp: false,
                channel_type: NL80211_CHAN_NO_HT,
                channel_width: NL80211_CHAN_WIDTH_20_NOHT,
                explicit_width: false,
                freq_fixed: false,
                hostapd_ies: false,
                hostapd_crypto: false,
                hostapd_tail: false,
                capability: 0x0421,
            },
            ApStartProfile {
                name: "esp_ht20",
                probe_resp: true,
                channel_type: NL80211_CHAN_HT20,
                channel_width: NL80211_CHAN_WIDTH_20,
                explicit_width: false,
                freq_fixed: false,
                hostapd_ies: false,
                hostapd_crypto: false,
                hostapd_tail: false,
                capability: 0x0421,
            },
            ApStartProfile {
                name: "esp_ht20_no_probe",
                probe_resp: false,
                channel_type: NL80211_CHAN_HT20,
                channel_width: NL80211_CHAN_WIDTH_20,
                explicit_width: false,
                freq_fixed: false,
                hostapd_ies: false,
                hostapd_crypto: false,
                hostapd_tail: false,
                capability: 0x0421,
            },
            ApStartProfile {
                name: "explicit_20_noht",
                probe_resp: true,
                channel_type: NL80211_CHAN_NO_HT,
                channel_width: NL80211_CHAN_WIDTH_20_NOHT,
                explicit_width: true,
                freq_fixed: true,
                hostapd_ies: false,
                hostapd_crypto: false,
                hostapd_tail: false,
                capability: 0x0421,
            },
            ApStartProfile {
                name: "explicit_20_ht",
                probe_resp: true,
                channel_type: NL80211_CHAN_HT20,
                channel_width: NL80211_CHAN_WIDTH_20,
                explicit_width: true,
                freq_fixed: true,
                hostapd_ies: false,
                hostapd_crypto: false,
                hostapd_tail: false,
                capability: 0x0421,
            },
        ];
        let mut attempts = Vec::new();
        let mut last_error = None;
        for (idx, profile) in profiles.iter().enumerate() {
            let mut payload = genl_payload(NL80211_CMD_START_AP, NL80211_GENL_VERSION);
            append_attr(&mut payload, NL80211_ATTR_IFINDEX, &ifindex.to_ne_bytes());
            append_attr(&mut payload, NL80211_ATTR_WIPHY_FREQ, &freq.to_ne_bytes());
            append_attr(
                &mut payload,
                NL80211_ATTR_WIPHY_CHANNEL_TYPE,
                &profile.channel_type.to_ne_bytes(),
            );
            if profile.explicit_width {
                append_attr(
                    &mut payload,
                    NL80211_ATTR_CHANNEL_WIDTH,
                    &profile.channel_width.to_ne_bytes(),
                );
                append_attr(
                    &mut payload,
                    NL80211_ATTR_CENTER_FREQ1,
                    &(if ht40 { freq + 10 } else { freq }).to_ne_bytes(),
                );
            }
            if profile.freq_fixed {
                append_attr(&mut payload, NL80211_ATTR_FREQ_FIXED, &[]);
            }
            append_attr(
                &mut payload,
                NL80211_ATTR_BEACON_INTERVAL,
                &u32::from(beacon_interval_tu).to_ne_bytes(),
            );
            append_attr(&mut payload, NL80211_ATTR_DTIM_PERIOD, &1_u32.to_ne_bytes());
            let beacon_head = if profile.capability == 0x0401 {
                &hostapd_beacon_head
            } else {
                &esp_beacon_head
            };
            let beacon_tail = if profile.hostapd_tail {
                &hostapd_beacon_tail
            } else {
                &esp_beacon_tail
            };
            append_attr(&mut payload, NL80211_ATTR_BEACON_HEAD, beacon_head);
            append_attr(&mut payload, NL80211_ATTR_BEACON_TAIL, beacon_tail);
            if profile.probe_resp {
                let probe_resp = if profile.hostapd_tail {
                    &hostapd_probe_resp
                } else {
                    &esp_probe_resp
                };
                append_attr(&mut payload, NL80211_ATTR_PROBE_RESP, probe_resp);
            }
            if profile.hostapd_ies {
                let ies = hostapd_open_ap_extra_ies();
                append_attr(&mut payload, NL80211_ATTR_IE, &ies);
                append_attr(&mut payload, NL80211_ATTR_IE_PROBE_RESP, &ies);
                append_attr(&mut payload, NL80211_ATTR_IE_ASSOC_RESP, &ies);
                append_attr(
                    &mut payload,
                    NL80211_ATTR_BSS_HT_OPMODE,
                    &0_u16.to_ne_bytes(),
                );
            }
            append_attr(&mut payload, NL80211_ATTR_SSID, ssid.as_bytes());
            append_attr(
                &mut payload,
                NL80211_ATTR_HIDDEN_SSID,
                &NL80211_HIDDEN_SSID_NOT_IN_USE.to_ne_bytes(),
            );
            append_attr(
                &mut payload,
                NL80211_ATTR_AUTH_TYPE,
                &NL80211_AUTHTYPE_OPEN_SYSTEM.to_ne_bytes(),
            );
            append_attr(
                &mut payload,
                NL80211_ATTR_BSS_BASIC_RATES,
                open_ap_basic_rates(),
            );
            if profile.hostapd_crypto {
                append_attr(
                    &mut payload,
                    NL80211_ATTR_CIPHER_SUITE_GROUP,
                    &WLAN_CIPHER_SUITE_WEP40.to_ne_bytes(),
                );
            }
            append_attr(&mut payload, NL80211_ATTR_SOCKET_OWNER, &[]);
            let send = self.send_genl(
                self.family_id,
                (libc::NLM_F_REQUEST | libc::NLM_F_ACK) as u16,
                6 + idx as u32,
                &payload,
            );
            let result = send.and_then(|_| self.recv_ack());
            match result {
                Ok(()) => {
                    attempts.push(json!({
                        "profile": profile.name,
                        "ok": true,
                        "probe_resp": profile.probe_resp,
                        "channel_type": profile.channel_type,
                        "channel_width": profile.channel_width,
                        "explicit_width": profile.explicit_width,
                        "freq_fixed": profile.freq_fixed,
                        "hostapd_ies": profile.hostapd_ies,
                        "hostapd_crypto": profile.hostapd_crypto,
                        "hostapd_tail": profile.hostapd_tail,
                        "capability": format!("0x{:04x}", profile.capability),
                        "beacon_head_len": beacon_head.len(),
                        "beacon_tail_len": beacon_tail.len(),
                    }));
                    return Ok(json!({
                        "selected": profile.name,
                        "attempts": attempts,
                    }));
                }
                Err(error) => {
                    let message = format!("{error:#}");
                    attempts.push(json!({
                        "profile": profile.name,
                        "ok": false,
                        "probe_resp": profile.probe_resp,
                        "channel_type": profile.channel_type,
                        "channel_width": profile.channel_width,
                        "explicit_width": profile.explicit_width,
                        "freq_fixed": profile.freq_fixed,
                        "hostapd_ies": profile.hostapd_ies,
                        "hostapd_crypto": profile.hostapd_crypto,
                        "hostapd_tail": profile.hostapd_tail,
                        "capability": format!("0x{:04x}", profile.capability),
                        "beacon_head_len": beacon_head.len(),
                        "beacon_tail_len": beacon_tail.len(),
                        "error": message,
                    }));
                    last_error = Some(error.context("nl80211 start open AP failed"));
                }
            }
        }
        Err((
            last_error.unwrap_or_else(|| anyhow::anyhow!("nl80211 start open AP had no profiles")),
            attempts,
        ))
    }

    pub fn stop_ap(&self, ifindex: u32) -> Result<()> {
        let mut payload = genl_payload(NL80211_CMD_STOP_AP, NL80211_GENL_VERSION);
        append_attr(&mut payload, NL80211_ATTR_IFINDEX, &ifindex.to_ne_bytes());
        self.send_genl(
            self.family_id,
            (libc::NLM_F_REQUEST | libc::NLM_F_ACK) as u16,
            7,
            &payload,
        )?;
        self.recv_ack().context("nl80211 stop AP failed")
    }

    pub fn flush_stations(&self, ifindex: u32) -> Result<()> {
        let mut payload = genl_payload(NL80211_CMD_DEL_STATION, NL80211_GENL_VERSION);
        append_attr(&mut payload, NL80211_ATTR_IFINDEX, &ifindex.to_ne_bytes());
        self.send_genl(
            self.family_id,
            (libc::NLM_F_REQUEST | libc::NLM_F_ACK) as u16,
            17,
            &payload,
        )?;
        self.recv_ack()
            .context("nl80211 flush station table failed")
    }

    pub fn remove_station(&self, ifindex: u32, mac: [u8; 6]) -> Result<()> {
        let mut payload = genl_payload(NL80211_CMD_DEL_STATION, NL80211_GENL_VERSION);
        append_attr(&mut payload, NL80211_ATTR_IFINDEX, &ifindex.to_ne_bytes());
        append_attr(&mut payload, NL80211_ATTR_MAC, &mac);
        self.send_genl(
            self.family_id,
            (libc::NLM_F_REQUEST | libc::NLM_F_ACK) as u16,
            18,
            &payload,
        )?;
        self.recv_ack().context("nl80211 remove station failed")
    }

    pub fn connect_open(
        &self,
        ifindex: u32,
        ssid: &str,
        freq: u32,
        bssid: Option<[u8; 6]>,
    ) -> Result<()> {
        let mut payload = genl_payload(NL80211_CMD_CONNECT, NL80211_GENL_VERSION);
        append_attr(&mut payload, NL80211_ATTR_IFINDEX, &ifindex.to_ne_bytes());
        append_attr(&mut payload, NL80211_ATTR_SSID, ssid.as_bytes());
        append_attr(&mut payload, NL80211_ATTR_WIPHY_FREQ, &freq.to_ne_bytes());
        if let Some(bssid) = bssid {
            append_attr(&mut payload, NL80211_ATTR_MAC, &bssid);
        }
        append_attr(
            &mut payload,
            NL80211_ATTR_AUTH_TYPE,
            &NL80211_AUTHTYPE_OPEN_SYSTEM.to_ne_bytes(),
        );
        self.send_genl(
            self.family_id,
            (libc::NLM_F_REQUEST | libc::NLM_F_ACK) as u16,
            8,
            &payload,
        )?;
        self.recv_ack().context("nl80211 open STA connect failed")
    }

    pub fn station_dump(&self, ifindex: u32) -> Result<Vec<Value>> {
        let mut payload = genl_payload(NL80211_CMD_GET_STATION, NL80211_GENL_VERSION);
        append_attr(&mut payload, NL80211_ATTR_IFINDEX, &ifindex.to_ne_bytes());
        self.send_genl(
            self.family_id,
            (libc::NLM_F_REQUEST as u16) | NLM_F_DUMP,
            9,
            &payload,
        )?;
        self.recv_station_dump()
            .context("nl80211 station dump failed")
    }




    pub fn add_station_from_assoc(
        &self,
        ifindex: u32,
        mac: [u8; 6],
        frame: &[u8],
        allow_ht: bool,
    ) -> Result<()> {
        let capability = read_u16_at(frame, IEEE80211_BODY);
        let listen_interval = read_u16_at(frame, IEEE80211_BODY + 2);
        let ies_offset = if frame_subtype(frame) == 2 {
            IEEE80211_BODY + 10
        } else {
            IEEE80211_BODY + 4
        };
        let ies = frame.get(ies_offset..).unwrap_or_default();
        let ht_capability = allow_ht.then(|| management_ie_bytes(ies, 45)).flatten();
        let extended_capability = management_ie_bytes(ies, 127);
        let mut supported_rates = Vec::with_capacity(16);
        if let Some(rates) = management_ie_bytes(ies, 1) {
            supported_rates.extend_from_slice(rates);
        }
        if let Some(rates) = management_ie_bytes(ies, 50) {
            supported_rates.extend_from_slice(rates);
        }
        let wme = management_ie_bytes(ies, 221)
            .is_some_and(|value| value.len() >= 4 && value[..4] == [0x00, 0x50, 0xf2, 0x02]);
        let short_preamble = capability.is_some_and(|value| value & (1 << 5) != 0);
        self.add_station(
            ifindex,
            mac,
            1,
            capability,
            listen_interval,
            ht_capability,
            extended_capability,
            (!supported_rates.is_empty()).then_some(supported_rates.as_slice()),
            wme,
            short_preamble,
        )
    }

    pub fn add_station(
        &self,
        ifindex: u32,
        mac: [u8; 6],
        aid: u16,
        capability: Option<u16>,
        listen_interval: Option<u16>,
        ht_capability: Option<&[u8]>,
        extended_capability: Option<&[u8]>,
        supported_rates: Option<&[u8]>,
        wme: bool,
        short_preamble: bool,
    ) -> Result<()> {
        let mut payload = genl_payload(NL80211_CMD_NEW_STATION, NL80211_GENL_VERSION);
        append_attr(&mut payload, NL80211_ATTR_IFINDEX, &ifindex.to_ne_bytes());
        append_attr(&mut payload, NL80211_ATTR_MAC, &mac);
        append_attr(&mut payload, NL80211_ATTR_STA_AID, &aid.to_ne_bytes());
        append_attr(
            &mut payload,
            NL80211_ATTR_STA_LISTEN_INTERVAL,
            &listen_interval.unwrap_or(10).to_ne_bytes(),
        );
        append_attr(
            &mut payload,
            NL80211_ATTR_STA_SUPPORTED_RATES,
            supported_rates.unwrap_or(&OPEN_AP_OFDM_BASIC_RATES),
        );
        if let Some(capability) = capability {
            append_attr(
                &mut payload,
                NL80211_ATTR_STA_CAPABILITY,
                &capability.to_ne_bytes(),
            );
        }
        if let Some(ht_capability) = ht_capability.filter(|value| value.len() == 26) {
            append_attr(&mut payload, NL80211_ATTR_HT_CAPABILITY, ht_capability);
        }
        if let Some(extended_capability) = extended_capability {
            append_attr(
                &mut payload,
                NL80211_ATTR_STA_EXT_CAPABILITY,
                extended_capability,
            );
        }
        let mut station_flags = NL80211_STA_FLAG_AUTHORIZED
            | NL80211_STA_FLAG_AUTHENTICATED
            | NL80211_STA_FLAG_ASSOCIATED;
        if wme {
            station_flags |= NL80211_STA_FLAG_WME;
        }
        if short_preamble {
            station_flags |= NL80211_STA_FLAG_SHORT_PREAMBLE;
        }
        if wme {
            let mut wme_attributes = Vec::with_capacity(16);
            append_attr(&mut wme_attributes, 1, &[0]);
            append_attr(&mut wme_attributes, 2, &[0]);
            append_attr(
                &mut payload,
                NL80211_ATTR_STA_WME | (1 << 15),
                &wme_attributes,
            );
        }
        let mut flags_update = Vec::with_capacity(8);
        flags_update.extend_from_slice(&station_flags.to_ne_bytes());
        flags_update.extend_from_slice(&station_flags.to_ne_bytes());
        append_attr(&mut payload, NL80211_ATTR_STA_FLAGS2, &flags_update);
        self.send_genl(
            self.family_id,
            (libc::NLM_F_REQUEST | libc::NLM_F_ACK) as u16,
            10,
            &payload,
        )?;
        self.recv_ack()
            .context("nl80211 add minimal station failed")
    }

    pub fn send_frame(
        &self,
        ifindex: u32,
        freq: u32,
        options: &RawWifiTxOptions,
        frame: &[u8],
        tx_rate_mbps: Option<u8>,
    ) -> Result<()> {
        let mut payload = genl_payload(NL80211_CMD_FRAME, NL80211_GENL_VERSION);
        append_attr(&mut payload, NL80211_ATTR_IFINDEX, &ifindex.to_ne_bytes());
        if options.include_freq {
            append_attr(&mut payload, NL80211_ATTR_WIPHY_FREQ, &freq.to_ne_bytes());
        }
        if let Some(duration_ms) = options.duration_ms {
            append_attr(
                &mut payload,
                NL80211_ATTR_DURATION,
                &duration_ms.to_ne_bytes(),
            );
        }
        append_attr(&mut payload, NL80211_ATTR_FRAME, frame);
        if options.offchannel_tx_ok {
            append_attr(&mut payload, NL80211_ATTR_OFFCHANNEL_TX_OK, &[]);
        }
        if options.dont_wait_for_ack {
            append_attr(&mut payload, NL80211_ATTR_DONT_WAIT_FOR_ACK, &[]);
        }
        if options.tx_no_cck_rate {
            append_attr(&mut payload, NL80211_ATTR_TX_NO_CCK_RATE, &[]);
        }
        if let Some(rate) = tx_rate_mbps {
            if !matches!(rate, 6 | 9 | 12 | 18 | 24 | 36 | 48 | 54) {
                bail!("unsupported per-frame legacy rate {rate} Mbps");
            }
            let mut band = Vec::new();
            append_attr(&mut band, 1, &[rate.saturating_mul(2)]); // TXRATE_LEGACY, 500 kbit/s units
            let mut bands = Vec::new();
            append_attr(&mut bands, 1 << 15, &band); // 2 GHz band, nested
            append_attr(&mut payload, NL80211_ATTR_TX_RATES | (1 << 15), &bands);
        }
        self.send_genl(
            self.family_id,
            (libc::NLM_F_REQUEST | libc::NLM_F_ACK) as u16,
            3,
            &payload,
        )?;
        self.recv_ack().context("nl80211 frame TX failed")
    }

    pub fn send_mgmt_frame(&self, ifindex: u32, frame: &[u8], tx_rate_mbps: Option<u8>) -> Result<()> {
        let mut payload = genl_payload(NL80211_CMD_FRAME, NL80211_GENL_VERSION);
        append_attr(&mut payload, NL80211_ATTR_IFINDEX, &ifindex.to_ne_bytes());
        // The AP SME response is emitted while the phy is also carrying the
        // NAN monitor path.  Supplying the already-owned channel and a short
        // on-channel duration makes this an explicit managed-interface TX
        // request; mt76 otherwise intermittently returns ENOMEM for the
        // otherwise valid frame while it is draining monitor traffic.
        let freq = channel_to_freq(DEFAULT_RAW_WIFI_CHANNEL);
        append_attr(&mut payload, NL80211_ATTR_WIPHY_FREQ, &freq.to_ne_bytes());
        append_attr(&mut payload, NL80211_ATTR_DURATION, &100_u32.to_ne_bytes());
        append_attr(&mut payload, NL80211_ATTR_FRAME, frame);
        if let Some(rate) = tx_rate_mbps {
            if !matches!(rate, 6 | 9 | 12 | 18 | 24 | 36 | 48 | 54) {
                bail!("unsupported per-frame legacy rate {rate} Mbps");
            }
            let mut band = Vec::new();
            append_attr(&mut band, 1, &[rate.saturating_mul(2)]);
            let mut bands = Vec::new();
            append_attr(&mut bands, 1 << 15, &band);
            append_attr(&mut payload, NL80211_ATTR_TX_RATES | (1 << 15), &bands);
        }
        // Management TX is transiently rejected with ENOMEM when the driver
        // is draining a burst of NAN/raw frames. Auth/association responses
        // must not be lost in that window: retry the same bounded request so
        // an ESP STA can complete its open-AP handshake.
        for attempt in 0..20 {
            self.send_genl(
                self.family_id,
                (libc::NLM_F_REQUEST | libc::NLM_F_ACK) as u16,
                18 + attempt,
                &payload,
            )?;
            match self.recv_ack() {
                Ok(()) => return Ok(()),
                Err(error)
                    if attempt < 19
                        && (error.to_string().contains("Out of memory")
                            || error.to_string().contains("os error 12")) =>
                {
                    std::thread::sleep(Duration::from_millis(20));
                }
                Err(error) => {
                    return Err(error).context("nl80211 management frame TX failed");
                }
            }
        }
        unreachable!()
    }

    pub fn recv_frame(&self) -> Result<Vec<u8>> {
        self.recv_frame_with_signal().map(|(frame, _)| frame)
    }

    pub fn recv_frame_with_signal(&self) -> Result<(Vec<u8>, Option<i32>)> {
        loop {
            let response = self.recv_netlink()?;
            let Some(header) = genl_header(&response) else {
                continue;
            };
            if header.cmd != NL80211_CMD_FRAME {
                continue;
            }
            let mut frame = None;
            let mut rx_signal_dbm = None;
            for (kind, value) in genl_attrs(&response)? {
                match kind {
                    NL80211_ATTR_FRAME => frame = Some(value.to_vec()),
                    NL80211_ATTR_RX_SIGNAL_DBM if value.len() >= 4 => {
                        rx_signal_dbm =
                            Some(i32::from_ne_bytes([value[0], value[1], value[2], value[3]]));
                    }
                    _ => {}
                }
            }
            if let Some(frame) = frame {
                return Ok((frame, rx_signal_dbm));
            }
        }
    }

    pub fn send_genl(&self, nlmsg_type: u16, flags: u16, seq: u32, payload: &[u8]) -> Result<()> {
        let header = libc::nlmsghdr {
            nlmsg_len: (std::mem::size_of::<libc::nlmsghdr>() + payload.len()) as u32,
            nlmsg_type,
            nlmsg_flags: flags,
            nlmsg_seq: seq,
            nlmsg_pid: 0,
        };
        let mut request = Vec::with_capacity(header.nlmsg_len as usize);
        append_struct(&mut request, &header);
        request.extend_from_slice(payload);
        let mut kernel: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        kernel.nl_family = libc::AF_NETLINK as libc::sa_family_t;
        kernel.nl_pid = 0;
        kernel.nl_groups = 0;
        let written = unsafe {
            libc::sendto(
                self.fd,
                request.as_ptr() as *const libc::c_void,
                request.len(),
                0,
                &kernel as *const libc::sockaddr_nl as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
            )
        };
        if written < 0 {
            let os_error = std::io::Error::last_os_error();
            bail!(
                "failed to send netlink request type={} len={} flags=0x{:x}: {}",
                nlmsg_type,
                request.len(),
                flags,
                os_error
            );
        }
        Ok(())
    }

    pub fn recv_netlink(&self) -> Result<Vec<u8>> {
        let buf = self.recv_netlink_raw()?;
        if let Some(error) = netlink_error(&buf) {
            bail!(
                "netlink error: {}{}",
                std::io::Error::from_raw_os_error(error),
                netlink_extack_message(&buf)
            );
        }
        Ok(buf)
    }

    pub fn recv_ack(&self) -> Result<()> {
        loop {
            let response = self.recv_netlink_raw()?;
            let mut offset = 0;
            while offset + std::mem::size_of::<libc::nlmsghdr>() <= response.len() {
                let header = unsafe {
                    std::ptr::read_unaligned(response[offset..].as_ptr() as *const libc::nlmsghdr)
                };
                let len = header.nlmsg_len as usize;
                if len < std::mem::size_of::<libc::nlmsghdr>() || offset + len > response.len() {
                    break;
                }
                let msg = &response[offset..offset + len];
                if header.nlmsg_type == NLMSG_ERROR {
                    if let Some(error) = netlink_error(msg) {
                        bail!(
                            "netlink error: {}{}",
                            std::io::Error::from_raw_os_error(error),
                            netlink_extack_message(msg)
                        );
                    }
                    if netlink_is_ack(msg) {
                        return Ok(());
                    }
                }
                offset += nlmsg_align(len);
            }
        }
    }

    pub fn recv_station_dump(&self) -> Result<Vec<Value>> {
        let mut stations = Vec::new();
        loop {
            let response = self.recv_netlink_raw()?;
            let mut offset = 0;
            while offset + std::mem::size_of::<libc::nlmsghdr>() <= response.len() {
                let header = unsafe {
                    std::ptr::read_unaligned(response[offset..].as_ptr() as *const libc::nlmsghdr)
                };
                let len = header.nlmsg_len as usize;
                if len < std::mem::size_of::<libc::nlmsghdr>() || offset + len > response.len() {
                    break;
                }
                let msg = &response[offset..offset + len];
                if header.nlmsg_type == libc::NLMSG_DONE as u16 {
                    return Ok(stations);
                }
                if header.nlmsg_type == NLMSG_ERROR {
                    if let Some(error) = netlink_error(msg) {
                        bail!(
                            "netlink error: {}{}",
                            std::io::Error::from_raw_os_error(error),
                            netlink_extack_message(msg)
                        );
                    }
                } else if header.nlmsg_type == self.family_id {
                    stations.push(parse_station_dump_message(msg)?);
                }
                offset += nlmsg_align(len);
            }
        }
    }


    pub fn recv_netlink_raw(&self) -> Result<Vec<u8>> {
        let mut buf = vec![0_u8; 65536];
        // Requests are sent with sendto() on an unconnected generic-netlink
        // socket. Use recvfrom() symmetrically; recv() returns ENOTCONN on
        // kernels that do not implicitly connect AF_NETLINK sockets.
        let mut peer: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        let mut peer_len = std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t;
        let read = unsafe {
            libc::recvfrom(
                self.fd,
                buf.as_mut_ptr() as *mut libc::c_void,
                buf.len(),
                0,
                &mut peer as *mut libc::sockaddr_nl as *mut libc::sockaddr,
                &mut peer_len,
            )
        };
        if read < 0 {
            return Err(std::io::Error::last_os_error()).context("failed to receive netlink reply");
        }
        buf.truncate(read as usize);
        Ok(buf)
    }

    pub fn set_receive_timeout(&self, timeout: Duration) -> Result<()> {
        let micros = timeout.as_micros().min(i64::MAX as u128) as i64;
        let value = libc::timeval {
            tv_sec: micros / 1_000_000,
            tv_usec: micros % 1_000_000,
        };
        let result = unsafe {
            libc::setsockopt(
                self.fd,
                libc::SOL_SOCKET,
                libc::SO_RCVTIMEO,
                &value as *const libc::timeval as *const libc::c_void,
                std::mem::size_of_val(&value) as libc::socklen_t,
            )
        };
        if result < 0 {
            return Err(std::io::Error::last_os_error())
                .context("failed to set nl80211 receive timeout");
        }
        Ok(())
    }
}

impl Drop for Nl80211Socket {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.fd);
        }
    }
}

pub struct ApStartProfile {
    pub name: &'static str,
    pub probe_resp: bool,
    pub channel_type: u32,
    pub channel_width: u32,
    pub explicit_width: bool,
    pub freq_fixed: bool,
    pub hostapd_ies: bool,
    pub hostapd_crypto: bool,
    pub hostapd_tail: bool,
    pub capability: u16,
}

/// Build the nested 2.4 GHz rate attributes used by `NL80211_ATTR_TX_RATES`.
/// This is kept independent of the socket so host tests cover the exact
/// no-legacy HT diagnostic payload before it is sent to the live AP.
pub fn tx_rate_profile_band(
    rate_mbps: Option<u8>,
    ht_mcs: Option<u8>,
    disable_b: bool,
) -> Option<Vec<u8>> {
    if rate_mbps.is_none() && ht_mcs.is_none() && !disable_b {
        return None;
    }
    let mut band = Vec::new();
    if let Some(rate) = rate_mbps {
        append_attr(&mut band, NL80211_TXRATE_LEGACY, &[rate.saturating_mul(2)]);
    } else if disable_b && ht_mcs.is_none() {
        // OFDM-only 2.4 GHz policy: exclude 1/2/5.5/11 Mbps CCK while
        // retaining the normal OFDM fallback ladder.
        let rates: Vec<u8> = [6_u8, 9, 12, 18, 24, 36, 48, 54]
            .into_iter()
            .map(|rate| rate.saturating_mul(2))
            .collect();
        append_attr(&mut band, NL80211_TXRATE_LEGACY, &rates);
    }
    if let Some(mcs) = ht_mcs {
        // Exact HT-only diagnostic: leave legacy data rates out of this
        // rate-control profile so rate fallback cannot hide a low-MCS result.
        // AP management/control retains its BSS basic-rate policy separately.
        append_attr(&mut band, NL80211_TXRATE_HT, &[mcs]);
    }
    Some(band)
}

pub fn genl_payload(cmd: u8, version: u8) -> Vec<u8> {
    let mut payload = Vec::new();
    append_struct(
        &mut payload,
        &GenlMsgHdr {
            cmd,
            version,
            reserved: 0,
        },
    );
    payload
}

pub fn append_attr(out: &mut Vec<u8>, kind: u16, value: &[u8]) {
    let len = std::mem::size_of::<NlAttrHdr>() + value.len();
    append_struct(
        out,
        &NlAttrHdr {
            nla_len: len as u16,
            nla_type: kind,
        },
    );
    out.extend_from_slice(value);
    while out.len() % 4 != 0 {
        out.push(0);
    }
}

pub fn netlink_payload(response: &[u8]) -> Result<&[u8]> {
    if response.len() < std::mem::size_of::<libc::nlmsghdr>() {
        bail!("short netlink message");
    }
    let header = unsafe { std::ptr::read_unaligned(response.as_ptr() as *const libc::nlmsghdr) };
    let len = header.nlmsg_len as usize;
    if len < std::mem::size_of::<libc::nlmsghdr>() || len > response.len() {
        bail!("invalid netlink message length {len}");
    }
    Ok(&response[std::mem::size_of::<libc::nlmsghdr>()..len])
}

pub fn genl_header(response: &[u8]) -> Option<GenlMsgHdr> {
    let payload = netlink_payload(response).ok()?;
    if payload.len() < std::mem::size_of::<GenlMsgHdr>() {
        return None;
    }
    Some(unsafe { std::ptr::read_unaligned(payload.as_ptr() as *const GenlMsgHdr) })
}

pub fn genl_attrs(response: &[u8]) -> Result<Vec<(u16, &[u8])>> {
    let payload = netlink_payload(response)?;
    if payload.len() < std::mem::size_of::<GenlMsgHdr>() {
        bail!("short generic netlink message");
    }
    parse_attrs(&payload[std::mem::size_of::<GenlMsgHdr>()..])
}

pub fn parse_station_dump_message(response: &[u8]) -> Result<Value> {
    let mut mac = None;
    let mut station_info = Vec::new();
    for (kind, value) in genl_attrs(response)? {
        match kind & NLA_TYPE_MASK {
            NL80211_ATTR_MAC if value.len() >= 6 => {
                let mut station_mac = [0_u8; 6];
                station_mac.copy_from_slice(&value[..6]);
                mac = Some(colon_mac(&station_mac));
            }
            NL80211_ATTR_STA_INFO => station_info = parse_attrs(value)?,
            _ => {}
        }
    }
    let mut out = serde_json::Map::new();
    if let Some(mac) = mac {
        out.insert("mac".to_string(), Value::String(mac));
    }
    for (kind, value) in station_info {
        match kind & NLA_TYPE_MASK {
            NL80211_STA_INFO_INACTIVE_TIME => {
                insert_u32(&mut out, "inactive_ms", value);
            }
            NL80211_STA_INFO_RX_BYTES => {
                insert_u32(&mut out, "rx_bytes", value);
            }
            NL80211_STA_INFO_TX_BYTES => {
                insert_u32(&mut out, "tx_bytes", value);
            }
            NL80211_STA_INFO_SIGNAL => {
                if let Some(signal) = value.first() {
                    out.insert("signal_dbm".to_string(), json!(*signal as i8));
                }
            }
            NL80211_STA_INFO_RX_PACKETS => {
                insert_u32(&mut out, "rx_packets", value);
            }
            NL80211_STA_INFO_TX_PACKETS => {
                insert_u32(&mut out, "tx_packets", value);
            }
            NL80211_STA_INFO_TX_RETRIES => {
                insert_u32(&mut out, "tx_retries", value);
            }
            NL80211_STA_INFO_TX_FAILED => {
                insert_u32(&mut out, "tx_failed", value);
            }
            NL80211_STA_INFO_SIGNAL_AVG => {
                if let Some(signal) = value.first() {
                    out.insert("signal_avg_dbm".to_string(), json!(*signal as i8));
                }
            }
            NL80211_STA_INFO_TX_BITRATE => {
                if let Ok(rate_attributes) = parse_attrs(value) {
                    insert_station_rate_info(&mut out, "tx", &rate_attributes);
                }
            }
            NL80211_STA_INFO_RX_BITRATE => {
                if let Ok(rate_attributes) = parse_attrs(value) {
                    insert_station_rate_info(&mut out, "rx", &rate_attributes);
                }
            }
            NL80211_STA_INFO_CONNECTED_TIME => {
                insert_u32(&mut out, "connected_sec", value);
            }
            NL80211_STA_INFO_STA_FLAGS if value.len() >= 8 => {
                let mask = u32::from_ne_bytes([value[0], value[1], value[2], value[3]]);
                let set = u32::from_ne_bytes([value[4], value[5], value[6], value[7]]);
                out.insert("wmm".to_string(), json!(set & NL80211_STA_FLAG_WME != 0));
                out.insert(
                    "authorized".to_string(),
                    json!(set & NL80211_STA_FLAG_AUTHORIZED != 0),
                );
                out.insert("station_flags_mask".to_string(), json!(mask));
            }
            NL80211_STA_INFO_RX_BYTES64 => {
                insert_u64(&mut out, "rx_bytes", value);
            }
            NL80211_STA_INFO_TX_BYTES64 => {
                insert_u64(&mut out, "tx_bytes", value);
            }
            // These driver-maintained aggregates explain why application
            // goodput can be far below the last selected MCS.  They are
            // intentionally reported only by the command-rate AP status
            // endpoint, never from a packet hot path.
            NL80211_STA_INFO_EXPECTED_THROUGHPUT => {
                insert_u32(&mut out, "expected_throughput_kbit_s", value);
            }
            NL80211_STA_INFO_RX_DROP_MISC => {
                insert_u64(&mut out, "rx_drop_misc", value);
            }
            NL80211_STA_INFO_RX_DURATION => {
                insert_u64(&mut out, "rx_airtime_us", value);
            }
            NL80211_STA_INFO_ACK_SIGNAL => {
                if let Some(signal) = value.first() {
                    out.insert("ack_signal_dbm".to_string(), json!(*signal as i8));
                }
            }
            NL80211_STA_INFO_ACK_SIGNAL_AVG => {
                if let Some(signal) = value.first() {
                    out.insert("ack_signal_avg_dbm".to_string(), json!(*signal as i8));
                }
            }
            NL80211_STA_INFO_RX_MPDUS => {
                insert_u32(&mut out, "rx_mpdus", value);
            }
            NL80211_STA_INFO_FCS_ERROR_COUNT => {
                insert_u32(&mut out, "rx_fcs_errors", value);
            }
            NL80211_STA_INFO_TX_DURATION => {
                insert_u64(&mut out, "tx_airtime_us", value);
            }
            _ => {}
        }
    }
    Ok(Value::Object(out))
}


/// Preserve PHY metadata alongside the calculated rate.  A value such as
/// 26 Mbps is ambiguous on its own: it can be legacy or HT MCS 3.  Exposing
/// this in the stable AP status avoids using a legacy-rate assumption to tune
/// the Recovery data path.
pub fn insert_station_rate_info(
    out: &mut serde_json::Map<String, Value>,
    direction: &str,
    attributes: &[(u16, &[u8])],
) {
    let attr = |kind| {
        attributes
            .iter()
            .find(|(attribute_kind, _)| *attribute_kind & NLA_TYPE_MASK == kind)
            .map(|(_, value)| *value)
    };
    let bitrate = attr(NL80211_RATE_INFO_BITRATE32)
        .filter(|value| value.len() >= 4)
        .map(|value| u32::from_ne_bytes([value[0], value[1], value[2], value[3]]) * 100)
        .or_else(|| {
            attr(NL80211_RATE_INFO_BITRATE)
                .filter(|value| value.len() >= 2)
                .map(|value| u16::from_ne_bytes([value[0], value[1]]) as u32 * 100)
        });
    if let Some(bitrate) = bitrate {
        out.insert(format!("{direction}_bitrate_kbit_s"), json!(bitrate));
    }
    if let Some(mcs) = attr(NL80211_RATE_INFO_MCS).and_then(|value| value.first()) {
        out.insert(format!("{direction}_phy"), json!("ht"));
        out.insert(format!("{direction}_mcs"), json!(*mcs));
        out.insert(
            format!("{direction}_width_mhz"),
            json!(if attr(NL80211_RATE_INFO_40_MHZ_WIDTH).is_some() {
                40
            } else {
                20
            }),
        );
        out.insert(
            format!("{direction}_short_gi"),
            json!(attr(NL80211_RATE_INFO_SHORT_GI).is_some()),
        );
    } else if let (Some(mcs), Some(nss)) = (
        attr(NL80211_RATE_INFO_VHT_MCS).and_then(|value| value.first()),
        attr(NL80211_RATE_INFO_VHT_NSS).and_then(|value| value.first()),
    ) {
        out.insert(format!("{direction}_phy"), json!("vht"));
        out.insert(format!("{direction}_mcs"), json!(*mcs));
        out.insert(format!("{direction}_nss"), json!(*nss));
    }
}

pub fn insert_u32(out: &mut serde_json::Map<String, Value>, key: &str, value: &[u8]) {
    if value.len() >= 4 {
        out.insert(
            key.to_string(),
            json!(u32::from_ne_bytes([value[0], value[1], value[2], value[3]])),
        );
    }
}

pub fn insert_u64(out: &mut serde_json::Map<String, Value>, key: &str, value: &[u8]) {
    if value.len() >= 8 {
        out.insert(
            key.to_string(),
            json!(u64::from_ne_bytes([
                value[0], value[1], value[2], value[3], value[4], value[5], value[6], value[7],
            ])),
        );
    }
}

pub fn insert_u16_at(out: &mut serde_json::Map<String, Value>, key: &str, bytes: &[u8], offset: usize) {
    if let Some(value) = read_u16_at(bytes, offset) {
        out.insert(key.to_string(), json!(value));
    }
}

pub fn read_u16_at(bytes: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_le_bytes(
        bytes.get(offset..offset + 2)?.try_into().ok()?,
    ))
}

pub fn read_u64_at(bytes: &[u8], offset: usize) -> Option<u64> {
    Some(u64::from_le_bytes(
        bytes.get(offset..offset + 8)?.try_into().ok()?,
    ))
}

pub fn parse_attrs(mut bytes: &[u8]) -> Result<Vec<(u16, &[u8])>> {
    let mut attrs = Vec::new();
    while bytes.len() >= std::mem::size_of::<NlAttrHdr>() {
        let header = unsafe { std::ptr::read_unaligned(bytes.as_ptr() as *const NlAttrHdr) };
        let len = header.nla_len as usize;
        if len < std::mem::size_of::<NlAttrHdr>() || len > bytes.len() {
            break;
        }
        attrs.push((
            header.nla_type,
            &bytes[std::mem::size_of::<NlAttrHdr>()..len],
        ));
        let aligned = (len + 3) & !3;
        if aligned > bytes.len() {
            break;
        }
        bytes = &bytes[aligned..];
    }
    Ok(attrs)
}

pub fn netlink_error(response: &[u8]) -> Option<i32> {
    if response.len() < std::mem::size_of::<libc::nlmsghdr>() + 4 {
        return None;
    }
    let header = unsafe { std::ptr::read_unaligned(response.as_ptr() as *const libc::nlmsghdr) };
    if header.nlmsg_type != NLMSG_ERROR {
        return None;
    }
    let offset = std::mem::size_of::<libc::nlmsghdr>();
    let error = unsafe { std::ptr::read_unaligned(response[offset..].as_ptr() as *const i32) };
    (error < 0).then_some(-error)
}

pub fn netlink_extack_message(response: &[u8]) -> String {
    let Some(attrs) = netlink_extack_attrs(response) else {
        return String::new();
    };
    let mut details = Vec::new();
    for (kind, value) in attrs {
        match kind {
            NLMSGERR_ATTR_MSG => {
                let text = String::from_utf8_lossy(trim_nul(value)).trim().to_string();
                if !text.is_empty() {
                    details.push(format!("msg={text:?}"));
                }
            }
            NLMSGERR_ATTR_OFFS if value.len() >= 4 => {
                let offset = u32::from_ne_bytes([value[0], value[1], value[2], value[3]]);
                details.push(format!("offset={offset}"));
            }
            NLMSGERR_ATTR_MISS_TYPE if value.len() >= 4 => {
                let attr = u32::from_ne_bytes([value[0], value[1], value[2], value[3]]);
                details.push(format!("missing_attr={attr}"));
            }
            _ => {}
        }
    }
    if details.is_empty() {
        String::new()
    } else {
        format!(" ({})", details.join(", "))
    }
}

pub fn netlink_extack_attrs(response: &[u8]) -> Option<Vec<(u16, &[u8])>> {
    let header_len = std::mem::size_of::<libc::nlmsghdr>();
    let error_len = std::mem::size_of::<i32>();
    if response.len() < header_len + error_len + header_len {
        return None;
    }
    let header = unsafe { std::ptr::read_unaligned(response.as_ptr() as *const libc::nlmsghdr) };
    if header.nlmsg_type != NLMSG_ERROR {
        return None;
    }
    let original_offset = header_len + error_len;
    let original = unsafe {
        std::ptr::read_unaligned(response[original_offset..].as_ptr() as *const libc::nlmsghdr)
    };
    let full_original_error_len = nlmsg_align(error_len + original.nlmsg_len as usize);
    let compact_error_len = nlmsg_align(error_len + header_len);
    for ext_offset in [
        header_len + full_original_error_len,
        header_len + compact_error_len,
    ] {
        if ext_offset < response.len()
            && let Ok(attrs) = parse_attrs(&response[ext_offset..])
            && !attrs.is_empty()
        {
            return Some(attrs);
        }
    }
    None
}

pub fn trim_nul(value: &[u8]) -> &[u8] {
    match value.iter().position(|byte| *byte == 0) {
        Some(pos) => &value[..pos],
        None => value,
    }
}

pub fn nlmsg_align(len: usize) -> usize {
    (len + 3) & !3
}

pub fn netlink_is_ack(response: &[u8]) -> bool {
    if response.len() < std::mem::size_of::<libc::nlmsghdr>() + 4 {
        return false;
    }
    let header = unsafe { std::ptr::read_unaligned(response.as_ptr() as *const libc::nlmsghdr) };
    if header.nlmsg_type != NLMSG_ERROR {
        return false;
    }
    let offset = std::mem::size_of::<libc::nlmsghdr>();
    let error = unsafe { std::ptr::read_unaligned(response[offset..].as_ptr() as *const i32) };
    error == 0
}

pub fn channel_to_freq(channel: u8) -> u32 {
    if channel == 14 {
        2484
    } else {
        2407 + (channel as u32 * 5)
    }
}

pub fn freq_to_channel(freq: u32) -> Option<u8> {
    match freq {
        2484 => Some(14),
        2412..=2472 => Some(((freq - 2407) / 5) as u8),
        5180..=5895 => Some(((freq - 5000) / 5) as u8),
        5955..=7115 => Some(((freq - 5950) / 5) as u8),
        _ => None,
    }
}

/// What nl80211 reports for one interface.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct InterfaceInfo {
    pub iftype: Option<u32>,
    pub wiphy: Option<u32>,
    /// Operating frequency in MHz, when the interface has a channel context.
    pub freq: Option<u32>,
}
