// Bearer profile codec. Hand-owned; being replaced by the wifi component.
use super::{cbor::{Decoder, Encoder}, TransportProfile};
/// Shared with DMesh control::TransportConfig and platform_api::TransportSetRequest
/// (crates/dmesh-server/src). Same transport fields and tagged-CBOR representation;
/// keep both sides in sync through the common dmesh docs/transport-cbor.md schema.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct TransportConfig<'a> {
    pub ssid: Option<&'a [u8]>,
    pub bssid: Option<[u8; 6]>,
    pub channel: Option<u8>,
    pub raw_tx_rate: Option<u8>,
    pub sta_driver_tx: Option<bool>,
    pub sta_bssid_check_disabled: Option<bool>,
    pub sta_ampdu_enabled: Option<bool>,
    pub sta_11b_rates_disabled: Option<bool>,
    pub sta_raw_rx_enabled: Option<bool>,
    pub espnow_capture: Option<bool>,
    pub nan_dw_interval: Option<u8>,
    pub now: Option<u8>,
    pub ap: Option<u8>,
    pub passphrase: Option<&'a [u8]>,
    pub uart: Option<u8>,
    pub ndp: Option<u8>,
    pub open: Option<bool>,
    pub wake_target: Option<[u8; 6]>,
    pub ble: Option<u8>,
    pub iface: Option<&'a [u8]>,
    pub uart_mode: Option<u8>,
    pub uart_baud: Option<u32>,
    pub uart_port: Option<u8>,
    pub radio_mode: Option<u8>,
    pub radio_frequency: Option<u32>,
    pub radio_bandwidth: Option<u32>,
    pub radio_bitrate: Option<u32>,
    pub radio_tx_power: Option<i32>,
    pub radio_spreading_factor: Option<u8>,
    pub radio_coding_rate: Option<u8>,
    pub ap_ssid: Option<&'a [u8]>,
    pub ap_passphrase: Option<&'a [u8]>,
}
pub fn field_count(config: TransportConfig<'_>) -> u64 {
    [config.ssid.is_some(), config.bssid.is_some(), config.channel.is_some(), config.raw_tx_rate.is_some(), config.sta_driver_tx.is_some(), config.sta_bssid_check_disabled.is_some(), config.sta_ampdu_enabled.is_some(), config.sta_11b_rates_disabled.is_some(), config.sta_raw_rx_enabled.is_some(), config.espnow_capture.is_some(), config.nan_dw_interval.is_some(), config.now.is_some(), config.ap.is_some(), config.passphrase.is_some(), config.uart.is_some(), config.ndp.is_some(), config.open.is_some(), config.wake_target.is_some(), config.ble.is_some(), config.iface.is_some(), config.uart_mode.is_some(), config.uart_baud.is_some(), config.uart_port.is_some(), config.radio_mode.is_some(), config.radio_frequency.is_some(), config.radio_bandwidth.is_some(), config.radio_bitrate.is_some(), config.radio_tx_power.is_some(), config.radio_spreading_factor.is_some(), config.radio_coding_rate.is_some(), config.ap_ssid.is_some(), config.ap_passphrase.is_some()]
        .into_iter().filter(|v| *v).count() as u64
}
pub fn validate_config(config: TransportConfig<'_>) -> Option<()> {
    if let Some(value) = config.ssid { super::valid_ssid(value)?; }
    if let Some(value) = config.bssid { super::valid_mac(value)?; }
    if let Some(value) = config.channel { super::valid_channel(value)?; }
    if let Some(value) = config.raw_tx_rate { super::valid_rate(value)?; }
    if let Some(value) = config.sta_driver_tx { super::valid_bool(value)?; }
    if let Some(value) = config.sta_bssid_check_disabled { super::valid_bool(value)?; }
    if let Some(value) = config.sta_ampdu_enabled { super::valid_bool(value)?; }
    if let Some(value) = config.sta_11b_rates_disabled { super::valid_bool(value)?; }
    if let Some(value) = config.sta_raw_rx_enabled { super::valid_bool(value)?; }
    if let Some(value) = config.espnow_capture { super::valid_bool(value)?; }
    if let Some(value) = config.nan_dw_interval { super::valid_dw(value)?; }
    if let Some(value) = config.now { super::valid_policy(value)?; }
    if let Some(value) = config.ap { super::valid_enable(value)?; }
    if let Some(value) = config.passphrase { super::valid_passphrase(value)?; }
    if let Some(value) = config.uart { super::valid_uart(value)?; }
    if let Some(value) = config.ndp { super::valid_enable(value)?; }
    if let Some(value) = config.open { super::valid_bool(value)?; }
    if let Some(value) = config.wake_target { super::valid_mac(value)?; }
    if let Some(value) = config.ble { super::valid_policy(value)?; }
    if let Some(value) = config.iface { super::valid_text(value)?; }
    if let Some(value) = config.uart_mode { super::valid_policy(value)?; }
    if let Some(value) = config.uart_baud { super::valid_baud(value)?; }
    if let Some(value) = config.uart_port { super::valid_port(value)?; }
    if let Some(value) = config.radio_mode { super::valid_policy(value)?; }
    if let Some(value) = config.radio_frequency { super::valid_u32(value)?; }
    if let Some(value) = config.radio_bandwidth { super::valid_u32(value)?; }
    if let Some(value) = config.radio_bitrate { super::valid_u32(value)?; }
    if let Some(value) = config.radio_tx_power { super::valid_power(value)?; }
    if let Some(value) = config.radio_spreading_factor { super::valid_sf(value)?; }
    if let Some(value) = config.radio_coding_rate { super::valid_cr(value)?; }
    if let Some(value) = config.ap_ssid { super::valid_ssid(value)?; }
    if let Some(value) = config.ap_passphrase { super::valid_passphrase(value)?; }
    Some(())
}
pub fn decode_config(encoded: &[u8]) -> Option<TransportConfig<'_>> {
    let mut d = Decoder::new(encoded);
    let (major, count) = d.head()?;
    if major != 5 || count == u64::MAX { return None; }
    let mut config = TransportConfig::default();
    let mut seen = 0u64;
    for _ in 0..count {
        let key = d.uint()?;
        if key < 64 { let bit = 1u64 << key; if seen & bit != 0 { return None; } seen |= bit; }
        match key {
            2 => config.ssid = Some(super::read_bytes(&mut d)?),
            3 => config.bssid = Some(super::read_mac(&mut d)?),
            4 => config.channel = Some(u8::try_from(d.uint()?).ok()?),
            5 => config.raw_tx_rate = Some(u8::try_from(d.uint()?).ok()?),
            6 => config.sta_driver_tx = Some(d.boolean()?),
            7 => config.sta_bssid_check_disabled = Some(d.boolean()?),
            8 => config.sta_ampdu_enabled = Some(d.boolean()?),
            9 => config.sta_11b_rates_disabled = Some(d.boolean()?),
            10 => config.sta_raw_rx_enabled = Some(d.boolean()?),
            13 => config.espnow_capture = Some(d.boolean()?),
            14 => config.nan_dw_interval = Some(u8::try_from(d.uint()?).ok()?),
            15 => config.now = Some(u8::try_from(d.uint()?).ok()?),
            16 => config.ap = Some(u8::try_from(d.uint()?).ok()?),
            17 => config.passphrase = Some(super::read_bytes(&mut d)?),
            18 => config.uart = Some(u8::try_from(d.uint()?).ok()?),
            19 => config.ndp = Some(u8::try_from(d.uint()?).ok()?),
            24 => config.open = Some(d.boolean()?),
            25 => config.wake_target = Some(super::read_mac(&mut d)?),
            26 => config.ble = Some(u8::try_from(d.uint()?).ok()?),
            27 => config.iface = Some(super::read_bytes(&mut d)?),
            28 => config.uart_mode = Some(u8::try_from(d.uint()?).ok()?),
            29 => config.uart_baud = Some(u32::try_from(d.uint()?).ok()?),
            30 => config.uart_port = Some(u8::try_from(d.uint()?).ok()?),
            31 => config.radio_mode = Some(u8::try_from(d.uint()?).ok()?),
            32 => config.radio_frequency = Some(u32::try_from(d.uint()?).ok()?),
            33 => config.radio_bandwidth = Some(u32::try_from(d.uint()?).ok()?),
            34 => config.radio_bitrate = Some(u32::try_from(d.uint()?).ok()?),
            35 => config.radio_tx_power = Some(i32::try_from(d.int()?).ok()?),
            36 => config.radio_spreading_factor = Some(u8::try_from(d.uint()?).ok()?),
            37 => config.radio_coding_rate = Some(u8::try_from(d.uint()?).ok()?),
            38 => config.ap_ssid = Some(super::read_bytes(&mut d)?),
            39 => config.ap_passphrase = Some(super::read_bytes(&mut d)?),
            _ => d.skip()?,
        }
    }
    if !d.is_finished() { return None; }
    validate_config(config)?;
    Some(config)
}
pub fn encode_config_into(config: TransportConfig<'_>, e: &mut Encoder<'_>) -> Option<()> {
    validate_config(config)?;
    if let Some(value) = config.ssid { e.uint(2)?; e.text_value(value)?; }
    if let Some(value) = config.bssid { e.uint(3)?; e.bytes_value(&value)?; }
    if let Some(value) = config.channel { e.uint(4)?; e.uint(u64::from(value))?; }
    if let Some(value) = config.raw_tx_rate { e.uint(5)?; e.uint(u64::from(value))?; }
    if let Some(value) = config.sta_driver_tx { e.uint(6)?; e.boolean(value)?; }
    if let Some(value) = config.sta_bssid_check_disabled { e.uint(7)?; e.boolean(value)?; }
    if let Some(value) = config.sta_ampdu_enabled { e.uint(8)?; e.boolean(value)?; }
    if let Some(value) = config.sta_11b_rates_disabled { e.uint(9)?; e.boolean(value)?; }
    if let Some(value) = config.sta_raw_rx_enabled { e.uint(10)?; e.boolean(value)?; }
    if let Some(value) = config.espnow_capture { e.uint(13)?; e.boolean(value)?; }
    if let Some(value) = config.nan_dw_interval { e.uint(14)?; e.uint(u64::from(value))?; }
    if let Some(value) = config.now { e.uint(15)?; e.uint(u64::from(value))?; }
    if let Some(value) = config.ap { e.uint(16)?; e.uint(u64::from(value))?; }
    if let Some(value) = config.passphrase { e.uint(17)?; e.text_value(value)?; }
    if let Some(value) = config.uart { e.uint(18)?; e.uint(u64::from(value))?; }
    if let Some(value) = config.ndp { e.uint(19)?; e.uint(u64::from(value))?; }
    if let Some(value) = config.open { e.uint(24)?; e.boolean(value)?; }
    if let Some(value) = config.wake_target { e.uint(25)?; e.bytes_value(&value)?; }
    if let Some(value) = config.ble { e.uint(26)?; e.uint(u64::from(value))?; }
    if let Some(value) = config.iface { e.uint(27)?; e.text_value(value)?; }
    if let Some(value) = config.uart_mode { e.uint(28)?; e.uint(u64::from(value))?; }
    if let Some(value) = config.uart_baud { e.uint(29)?; e.uint(u64::from(value))?; }
    if let Some(value) = config.uart_port { e.uint(30)?; e.uint(u64::from(value))?; }
    if let Some(value) = config.radio_mode { e.uint(31)?; e.uint(u64::from(value))?; }
    if let Some(value) = config.radio_frequency { e.uint(32)?; e.uint(u64::from(value))?; }
    if let Some(value) = config.radio_bandwidth { e.uint(33)?; e.uint(u64::from(value))?; }
    if let Some(value) = config.radio_bitrate { e.uint(34)?; e.uint(u64::from(value))?; }
    if let Some(value) = config.radio_tx_power { e.uint(35)?; e.int(i64::from(value))?; }
    if let Some(value) = config.radio_spreading_factor { e.uint(36)?; e.uint(u64::from(value))?; }
    if let Some(value) = config.radio_coding_rate { e.uint(37)?; e.uint(u64::from(value))?; }
    if let Some(value) = config.ap_ssid { e.uint(38)?; e.text_value(value)?; }
    if let Some(value) = config.ap_passphrase { e.uint(39)?; e.text_value(value)?; }
    Some(())
}
pub fn apply_config(config: TransportConfig<'_>, profile: &mut TransportProfile) -> Option<()> {
    validate_config(config)?;
    if let Some(value) = config.ssid { profile.ssid.fill(0); profile.ssid[..value.len()].copy_from_slice(value); profile.ssid_len = value.len(); }
    if let Some(value) = config.bssid { profile.sta_bssid = value; profile.sta_bssid_set = true; }
    if let Some(value) = config.channel { profile.sta_channel = value; }
    if let Some(value) = config.raw_tx_rate { profile.raw_tx_rate = value; }
    if let Some(value) = config.sta_driver_tx { profile.sta_driver_tx = value; }
    if let Some(value) = config.sta_bssid_check_disabled { profile.sta_bssid_check_disabled = value; }
    if let Some(value) = config.sta_ampdu_enabled { profile.sta_ampdu_enabled = value; }
    if let Some(value) = config.sta_11b_rates_disabled { profile.sta_11b_rates_disabled = value; }
    if let Some(value) = config.sta_raw_rx_enabled { profile.sta_raw_rx_enabled = value; }
    if let Some(value) = config.espnow_capture { profile.espnow_capture = value; }
    if let Some(value) = config.nan_dw_interval { profile.nan_dw_interval = value; }
    if let Some(value) = config.now { profile.now = value; }
    if let Some(value) = config.ap { profile.ap = value; }
    if let Some(value) = config.passphrase { profile.sta_passphrase.fill(0); profile.sta_passphrase[..value.len()].copy_from_slice(value); profile.sta_passphrase_len = value.len(); }
    if let Some(value) = config.uart { profile.uart = value; }
    if let Some(value) = config.ndp { profile.ndp = value; }
    if let Some(value) = config.open { profile.open = value; }
    if let Some(value) = config.ble { profile.ble = value; }
    if let Some(value) = config.uart_mode { profile.uart_mode = value; }
    if let Some(value) = config.uart_baud { profile.uart_baud = value; }
    if let Some(value) = config.uart_port { profile.uart_port = value; }
    if let Some(value) = config.radio_mode { profile.radio_mode = value; }
    if let Some(value) = config.radio_frequency { profile.radio_frequency = value; }
    if let Some(value) = config.radio_bandwidth { profile.radio_bandwidth = value; }
    if let Some(value) = config.radio_bitrate { profile.radio_bitrate = value; }
    if let Some(value) = config.radio_tx_power { profile.radio_tx_power = value; }
    if let Some(value) = config.radio_spreading_factor { profile.radio_spreading_factor = value; }
    if let Some(value) = config.radio_coding_rate { profile.radio_coding_rate = value; }
    if let Some(value) = config.ap_ssid { profile.ap_ssid.fill(0); profile.ap_ssid[..value.len()].copy_from_slice(value); profile.ap_ssid_len = value.len(); }
    if let Some(value) = config.ap_passphrase { profile.ap_passphrase.fill(0); profile.ap_passphrase[..value.len()].copy_from_slice(value); profile.ap_passphrase_len = value.len(); }
    if let Some(selector) = config.uart {
        profile.uart = super::normalize_uart_selector(selector).unwrap_or(profile.uart);
        if config.uart_mode.is_none() { profile.uart_mode = if selector == super::UART_OFF { 0 } else { 2 }; }
        if config.uart_baud.is_none() { profile.uart_baud = super::uart_baud(selector); }
    }
    Some(())
}
impl TransportProfile {
    pub fn config(&self) -> Option<TransportConfig<'_>> {
        if self.ssid_len > 32 || self.sta_passphrase_len > 63 || self.ap_ssid_len > 32 || self.ap_passphrase_len > 63 { return None; }
        let config = TransportConfig {
            ssid: (self.ssid_len != 0).then_some(&self.ssid[..self.ssid_len]),
            bssid: self.sta_bssid_set.then_some(self.sta_bssid),
            channel: (self.sta_channel != 0).then_some(self.sta_channel),
            raw_tx_rate: Some(self.raw_tx_rate),
            sta_driver_tx: Some(self.sta_driver_tx),
            sta_bssid_check_disabled: Some(self.sta_bssid_check_disabled),
            sta_ampdu_enabled: Some(self.sta_ampdu_enabled),
            sta_11b_rates_disabled: Some(self.sta_11b_rates_disabled),
            sta_raw_rx_enabled: Some(self.sta_raw_rx_enabled),
            espnow_capture: Some(self.espnow_capture),
            nan_dw_interval: Some(self.nan_dw_interval),
            now: Some(self.now),
            ap: Some(self.ap),
            passphrase: (self.sta_passphrase_len != 0).then_some(&self.sta_passphrase[..self.sta_passphrase_len]),
            uart: Some(self.uart),
            ndp: Some(self.ndp),
            open: Some(self.open),
            wake_target: None,
            ble: Some(self.ble),
            iface: None,
            uart_mode: Some(self.uart_mode),
            uart_baud: Some(self.uart_baud),
            uart_port: Some(self.uart_port),
            radio_mode: Some(self.radio_mode),
            radio_frequency: Some(self.radio_frequency),
            radio_bandwidth: Some(self.radio_bandwidth),
            radio_bitrate: Some(self.radio_bitrate),
            radio_tx_power: Some(self.radio_tx_power),
            radio_spreading_factor: Some(self.radio_spreading_factor),
            radio_coding_rate: Some(self.radio_coding_rate),
            ap_ssid: (self.ap_ssid_len != 0).then_some(&self.ap_ssid[..self.ap_ssid_len]),
            ap_passphrase: (self.ap_passphrase_len != 0).then_some(&self.ap_passphrase[..self.ap_passphrase_len]),
        };
        validate_config(config)?;
        Some(config)
    }
}
