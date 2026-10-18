//! DMesh transport profile: the desired bearer state shared by firmware, Android and host (`TransportProfile`), its tagged-CBOR
//! field codec (wire tags in `docs/transport-cbor.md`, frozen), the mode rules. Hardware state and protocol policy belong to owners.
pub use mesh_api::cbor;
mod codec;
pub use codec::*;
pub mod store;

/// Results of the mode rules (the values of the module ABI: `ERR_ARG`, `ERR_UNSUPPORTED`).
pub const ERR_ARG: i32 = -1;
pub const ERR_UNSUPPORTED: i32 = -2;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransportKind { Off, Sta, Nan, Uart }

pub const fn mode(kind: Option<TransportKind>) -> u8 {
    match kind { None | Some(TransportKind::Off) => 0, Some(TransportKind::Sta) => 1,
        Some(TransportKind::Uart) => 5, Some(TransportKind::Nan) => 6 }
}
pub fn transport_kind(value: u64) -> Option<TransportKind> {
    Some(match value { 0 => TransportKind::Off, 1 => TransportKind::Sta,
        5 => TransportKind::Uart, 6 => TransportKind::Nan, _ => return None })
}
pub const fn uart_baud(selector: u8) -> u32 {
    match selector { 2 => 9_600, 3 => 19_200, 4 => 38_400, 5 => 57_600,
        6 => 230_400, 7 => 460_800, 9 => 921_600, _ => 115_200 }
}

fn valid_bool(_: bool) -> Option<()> { Some(()) }
fn valid_u32(_: u32) -> Option<()> { Some(()) }
fn valid_mac(_: [u8; 6]) -> Option<()> { Some(()) }
fn valid_text(v: &[u8]) -> Option<()> { (v.len() <= 32 && !v.contains(&0)).then_some(()) }
pub fn valid_ssid(v: &[u8]) -> Option<()> { (!v.is_empty() && v.len() <= 32 && !v.contains(&0)).then_some(()) }
pub fn valid_passphrase(v: &[u8]) -> Option<()> { ((8..=63).contains(&v.len()) && !v.contains(&0)).then_some(()) }
fn valid_channel(v: u8) -> Option<()> { (1..=14).contains(&v).then_some(()) }
fn valid_rate(v: u8) -> Option<()> { matches!(v, 0 | 6 | 9 | 12 | 18 | 24 | 36 | 48 | 54).then_some(()) }
fn valid_dw(v: u8) -> Option<()> { matches!(v, 0 | 1 | 8 | 16).then_some(()) }
fn valid_policy(v: u8) -> Option<()> { (v <= 2).then_some(()) }
fn valid_enable(v: u8) -> Option<()> { (v <= 1).then_some(()) }
fn valid_uart(v: u8) -> Option<()> { normalize_uart_selector(v).map(|_| ()) }
fn valid_baud(v: u32) -> Option<()> { (v != 0 && v <= 5_000_000).then_some(()) }
fn valid_port(v: u8) -> Option<()> { (v <= 3).then_some(()) }
fn valid_power(v: i32) -> Option<()> { (-40..=30).contains(&v).then_some(()) }
fn valid_sf(v: u8) -> Option<()> { (v == 0 || (5..=12).contains(&v)).then_some(()) }
fn valid_cr(v: u8) -> Option<()> { (v == 0 || (5..=8).contains(&v)).then_some(()) }

fn read_bytes<'a>(d: &mut cbor::Decoder<'a>) -> Option<&'a [u8]> {
    let saved = d.position();
    d.text_ref().or_else(|| { d.set_position(saved); d.bytes_ref() })
}
pub fn parse_bssid_text(text: &[u8]) -> Option<[u8; 6]> {
    if text.len() != 17 { return None; }
    let mut mac = [0; 6];
    for (i, value) in mac.iter_mut().enumerate() {
        if i != 5 && text[i * 3 + 2] != b':' { return None; }
        let digit = |v| match v { b'0'..=b'9' => Some(v - b'0'), b'a'..=b'f' => Some(v - b'a' + 10), b'A'..=b'F' => Some(v - b'A' + 10), _ => None };
        *value = digit(text[i * 3])? * 16 + digit(text[i * 3 + 1])?;
    }
    Some(mac)
}
fn read_mac(d: &mut cbor::Decoder<'_>) -> Option<[u8; 6]> {
    let saved = d.position();
    if let Some(bytes) = d.bytes_ref() { return bytes.try_into().ok(); }
    d.set_position(saved);
    parse_bssid_text(d.text_ref()?)
}

/// A partial desired-state request. Decoding does not mutate a profile or
/// derive run intent. Routing and wake metadata remain visible to the owner.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct TransportRequest<'a> {
    pub mode: Option<TransportKind>,
    pub config: TransportConfig<'a>,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RequestEffect { Applied, LeaseRenewed }

pub fn decode_request(input: &[u8]) -> Option<TransportRequest<'_>> {
    let config = decode_config(input)?;
    let mut d = cbor::Decoder::new(input);
    let (_, count) = d.head()?;
    let mut mode = None;
    for _ in 0..count {
        if d.uint()? == 1 { mode = Some(transport_kind(d.uint()?)?); } else { d.skip()?; }
    }
    Some(TransportRequest { mode, config })
}
pub fn encode_request(request: TransportRequest<'_>, out: &mut [u8]) -> Option<usize> {
    let mut e = cbor::Encoder::new(out);
    e.map(field_count(request.config) + u64::from(request.mode.is_some()))?;
    if let Some(kind) = request.mode { e.uint(1)?; e.uint(u64::from(mode(Some(kind))))?; }
    encode_config_into(request.config, &mut e)?;
    Some(e.len())
}
/// Common request semantics. Products validate routing/wake metadata before
/// calling this helper and perform lease side effects after it returns.
pub fn apply_request(request: TransportRequest<'_>, profile: &mut TransportProfile) -> Result<RequestEffect, i32> {
    validate_config(request.config).ok_or(ERR_ARG)?;
    let c = request.config;
    if request.mode == Some(TransportKind::Uart) { return Err(ERR_UNSUPPORTED); }
    if request.mode == Some(TransportKind::Sta) && c.ssid.is_none() && c.bssid.is_none() && !profile.has_sta_profile() {
        return Err(ERR_ARG);
    }
    if request.mode == Some(TransportKind::Sta) && c.wake_target.is_some()
        && profile.requested_transport == Some(TransportKind::Sta)
        && c == (TransportConfig { wake_target: c.wake_target, iface: c.iface, ..Default::default() }) {
        return Ok(RequestEffect::LeaseRenewed);
    }
    let mut next = *profile;
    match request.mode {
        Some(TransportKind::Off) => next = TransportProfile::off(),
        Some(TransportKind::Sta) if c.ssid.is_some() || c.bssid.is_some() => {
            next.sta_passphrase.fill(0); next.sta_passphrase_len = 0;
        }
        _ => {}
    }
    apply_config(c, &mut next).ok_or(ERR_ARG)?;
    if let Some(kind) = request.mode {
        next.requested_transport = (kind != TransportKind::Off).then_some(kind);
        next.run_requested = kind != TransportKind::Off;
    }
    *profile = next;
    Ok(RequestEffect::Applied)
}

pub const UART_DEFAULT: u8 = 0;
/// The product's default physical UART rate.
pub const UART_115200: u8 = 1;
/// Explicitly stop a real UART bearer. USB-Serial/JTAG deliberately ignores
/// this selector: it is a debug/JTAG path, not a controllable UART peripheral.
pub const UART_OFF: u8 = 8;
pub const UART_921600: u8 = 9;

/// Parse the persistent physical UART rate. Native USB ignores this setting.
pub fn parse_uart_baud(value: &[u8]) -> Option<i32> {
    match value {
        b"115200" => Some(115_200),
        b"230400" => Some(230_400),
        b"460800" => Some(460_800),
        b"921600" => Some(921_600),
        _ => None,
    }
}

/// Normalize the transport profile's legacy on/off/speed selector.
pub const fn normalize_uart_selector(selector: u8) -> Option<u8> {
    match selector {
        UART_DEFAULT => Some(UART_115200),
        UART_115200..=7 | UART_OFF | UART_921600 => Some(selector),
        _ => None,
    }
}

/// Shared transport profile used by esp-xip-modules and DMesh Android/host.
/// The transport fields and tagged-CBOR representation are the same as DMesh's
/// `crates/dmesh-server/src/firmware_profile.rs::TransportProfile::bearers` and
/// `control::TransportConfig`; Android/host also use the generated
/// `platform_api::TransportSetRequest` in that crate.
/// Keep the field meanings, tags, defaults and encodings in sync on both sides.
/// dmesh `docs/transport-cbor.md` is the common schema of both representations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransportProfile {
    pub ssid: [u8; 33],
    pub ssid_len: usize,
    /// STA credential. Included only in explicit saved defaults; no implied
    /// credential or security policy belongs to this generic profile.
    pub sta_passphrase: [u8; 64],
    pub sta_passphrase_len: usize,
    /// Optional exact AP identity supplied with the transient STA start.
    pub sta_bssid: [u8; 6],
    pub sta_bssid_set: bool,
    /// `0` lets ESP-IDF choose; a nonzero value pins the association scan.
    pub sta_channel: u8,
    /// Explicit opt-in for the tested associated STA+NAN+NOW coexistence
    /// personality. It is false by default so STA/UDP6 remains the baseline.
    /// It is not the planned unassociated NAN+NOW boot policy, nor does it
    /// encode NAN SD rendezvous/retry timing.
    pub espnow_capture: bool,
    /// NAN discovery-window interval in 512 ms DWs. Main defaults to one so
    /// NAN remains available in every radio mode; zero is an explicit
    /// diagnostic off spelling, while eight and sixteen select lower-duty
    /// cadences.
    pub nan_dw_interval: u8,
    /// `now=0` is the default private NOW action path; `now=1` is an explicit
    /// on spelling and `now=2` is the raw-UDP6-only regression baseline. A
    /// future `udp6` setting remains independent.
    pub now: u8,
    /// Requested NAN Data Path policy. ESP adapters currently retain this
    /// common transport-start parameter without implementing NDP; Android
    /// turns it into a Wi-Fi Aware data-path capability for the epoch.
    pub ndp: u8,
    /// `ap=1` enables a local AP alongside the selected STA or NAN mode.
    pub ap: u8,
    /// Desired open AP/STA policy. Products choose their credential defaults.
    pub open: bool,
    /// UART selector: `0` is the default 115200 setting, `1` explicitly means
    /// 115200, `2..=7` select other common rates, `8` is off, and `9` is921600.
    /// USB packet mode ignores this selector.
    pub uart: u8,
    pub ble: u8,
    pub uart_mode: u8,
    pub uart_baud: u32,
    pub uart_port: u8,
    pub radio_mode: u8,
    pub radio_frequency: u32,
    pub radio_bandwidth: u32,
    pub radio_bitrate: u32,
    pub radio_tx_power: i32,
    pub radio_spreading_factor: u8,
    pub radio_coding_rate: u8,
    pub ap_ssid: [u8; 33],
    pub ap_ssid_len: usize,
    pub ap_passphrase: [u8; 64],
    pub ap_passphrase_len: usize,
    pub run_requested: bool,
    /// Requested physical bearer personality. `None` means the shared Wi-Fi
    /// owner must be stopped. Other bearer intentions remain independent.
    pub requested_transport: Option<TransportKind>,
    /// Raw radio transmit rate; zero selects the driver default.
    pub raw_tx_rate: u8,
    /// Associated-STA egress policy: true submits Ethernet through ESP-IDF's
    /// normal STA data path. Raw 802.11 injection remains a runtime
    /// diagnostic opt-out for A/B investigations.
    pub sta_driver_tx: bool,
    /// Preserve the previously proven raw-receive policy by default, while
    /// allowing a direct runtime A/B with standard STA BSSID filtering.
    pub sta_bssid_check_disabled: bool,
    /// Association-scoped A-MPDU policy. Changing this requires a controlled
    /// Wi-Fi driver reinitialization so ESP-IDF sees it in wifi_init_config_t.
    pub sta_ampdu_enabled: bool,
    /// Pre-start 802.11b rate suppression.  Keep the existing raw UDP6
    /// baseline by default, but make the association policy testable.
    pub sta_11b_rates_disabled: bool,
    /// Raw UDP6 takes ownership of the driver RX buffer only when explicitly
    /// enabled. `false` is the standard ESP-IDF esp-netif/lwIP RX path.
    pub sta_raw_rx_enabled: bool,
}

impl TransportProfile {
    pub const fn off() -> Self {
        let mut profile = Self::new();
        profile.requested_transport = None;
        profile.run_requested = false;
        profile.ap = 0;
        profile.now = 2;
        profile.nan_dw_interval = 0;
        profile.uart = UART_OFF;
        profile.uart_mode = 0;
        profile.ble = 0;
        profile.radio_mode = 0;
        profile
    }
    /// Stored STA credentials do not activate STA. UART also remains
    /// available without changing the NAN-only Wi-Fi sleep personality.
    pub fn is_nan_only(&self) -> bool {
        self.requested_transport == Some(TransportKind::Nan)
            && self.now == 2 && self.ap == 0
    }
    pub const fn new() -> Self {
        Self {
            ssid: [0; 33],
            ssid_len: 0,
            sta_passphrase: [0; 64],
            sta_passphrase_len: 0,
            sta_bssid: [0; 6],
            sta_bssid_set: false,
            sta_channel: 0,
            espnow_capture: false,
            nan_dw_interval: 1,
            now: 0,
            ndp: 0,
            // The out-of-box unassociated radio is AP+NOW on channel 6 for
            // the current NOW/NAN validation lane. An explicit start can
            // replace it with `ap=0` or associated STA later.
            ap: 1,
            open: false,
            uart: UART_115200,
            ble: 0,
            uart_mode: 2,
            uart_baud: 115_200,
            uart_port: 0,
            radio_mode: 0,
            radio_frequency: 0,
            radio_bandwidth: 0,
            radio_bitrate: 0,
            radio_tx_power: 0,
            radio_spreading_factor: 0,
            radio_coding_rate: 0,
            ap_ssid: [0; 33],
            ap_ssid_len: 0,
            ap_passphrase: [0; 64],
            ap_passphrase_len: 0,
            run_requested: false,
            requested_transport: None,
            raw_tx_rate: 0,
            sta_driver_tx: true,
            sta_bssid_check_disabled: true,
            sta_ampdu_enabled: true,
            sta_11b_rates_disabled: true,
            sta_raw_rx_enabled: true,
        }
    }

    pub const fn has_sta_profile(&self) -> bool {
        self.ssid_len != 0 || self.sta_bssid_set
    }
}

impl Default for TransportProfile {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn decoding_keeps_partial_fields_and_metadata() {
        let request = decode_request(&[0xa2, 0x18, 27, 0x63, b'w', b'l', b'0', 0x18, 28, 1]).unwrap();
        assert_eq!(request.mode, None); assert_eq!(request.config.iface, Some(&b"wl0"[..]));
        assert_eq!(request.config.uart_mode, Some(1));
    }
    #[test]
    fn mode_rules_preserve_or_replace_credentials() {
        let mut p = TransportProfile::new();
        assert_eq!(apply_request(TransportRequest { mode: Some(TransportKind::Sta), config: TransportConfig::default() }, &mut p), Err(ERR_ARG));
        apply_config(TransportConfig { ssid: Some(b"old"), passphrase: Some(b"oldsecret"), ..Default::default() }, &mut p).unwrap();
        let sta = TransportRequest { mode: Some(TransportKind::Sta), config: TransportConfig::default() };
        apply_request(sta, &mut p).unwrap(); assert_eq!(&p.sta_passphrase[..p.sta_passphrase_len], b"oldsecret");
        apply_request(TransportRequest { config: TransportConfig { ssid: Some(b"new"), ..Default::default() }, ..sta }, &mut p).unwrap();
        assert_eq!(p.sta_passphrase_len, 0);
        apply_request(TransportRequest { mode: Some(TransportKind::Nan), config: TransportConfig { ap: Some(0), ..Default::default() } }, &mut p).unwrap();
        assert_eq!(&p.ssid[..p.ssid_len], b"new");
        apply_request(TransportRequest { mode: Some(TransportKind::Off), config: TransportConfig { uart_mode: Some(2), ..Default::default() } }, &mut p).unwrap();
        assert_eq!((p.ap, p.now, p.uart_mode, p.run_requested), (0, 2, 2, false));
    }
    #[test]
    fn field_only_patch_preserves_inactive_mode_and_abi_roundtrip() {
        let mut p = TransportProfile::new(); p.requested_transport = Some(TransportKind::Nan); p.run_requested = false;
        apply_request(TransportRequest { mode: None, config: TransportConfig { ap: Some(0), ..Default::default() } }, &mut p).unwrap();
        assert_eq!((p.requested_transport, p.run_requested), (Some(TransportKind::Nan), false));
    }
    #[test]
    fn wake_renewal_is_not_an_edit_and_uart_mode_is_unsupported() {
        let mut p = TransportProfile::new(); p.requested_transport = Some(TransportKind::Sta); p.ssid_len = 1; p.ssid[0] = b'x';
        let before = p;
        assert_eq!(apply_request(TransportRequest { mode: Some(TransportKind::Sta), config: TransportConfig { wake_target: Some([1;6]), iface: Some(b"wifi"), ..Default::default() } }, &mut p), Ok(RequestEffect::LeaseRenewed));
        assert_eq!(p, before);
        assert_eq!(apply_request(TransportRequest { mode: Some(TransportKind::Uart), ..Default::default() }, &mut p), Err(ERR_UNSUPPORTED));
    }
    #[test]
    fn explicit_uart_fields_win_in_either_map_order() {
        for wire in [&[0xa3, 18, 9, 0x18, 28, 1, 0x18, 29, 0x19, 0x25, 0x80][..], &[0xa3, 0x18, 29, 0x19, 0x25, 0x80, 0x18, 28, 1, 18, 9]] {
            let request = decode_request(wire).unwrap(); let mut p = TransportProfile::new();
            apply_request(request, &mut p).unwrap(); assert_eq!((p.uart, p.uart_mode, p.uart_baud), (9, 1, 9600));
        }
    }
    #[test]
    fn request_codec_matches_the_c_fixture() {
        let mut p = TransportProfile::new();
        apply_config(TransportConfig { ssid: Some(b"mesh"), passphrase: Some(b"password"),
            ap_ssid: Some(b"guest"), ap_passphrase: Some(b"guestpass"),
            uart_mode: Some(1), uart_port: Some(3), radio_mode: Some(2), radio_tx_power: Some(-10), ..Default::default() }, &mut p).unwrap();
        let mut wire = [0;768]; let len = encode_request(TransportRequest { mode: Some(TransportKind::Sta), config: p.config().unwrap() }, &mut wire).unwrap();
        assert_eq!(&wire[..len], include_bytes!("../../tests/data/transport-profile.cbor"));
    }
    #[test]
    fn malformed_fields_are_rejected_before_mutation() {
        for wire in [&[0xa1, 18, 0x19, 1, 1][..], &[0xa2, 18, 1, 18, 9], &[0xa1, 28, 3], &[0xa1, 2, 0x65, b'a']] { assert!(decode_request(wire).is_none()); }
        let mut p = TransportProfile::new(); let before = p;
        assert!(apply_config(TransportConfig { ssid: Some(&[b'x'; 34]), ..Default::default() }, &mut p).is_none()); assert_eq!(p, before);
    }
}
