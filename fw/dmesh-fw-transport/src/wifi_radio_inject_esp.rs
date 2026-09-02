//! ESP implementation of the shared raw 802.11 action-injection schema.
//!
//! `dmesh_server::raw_wifi::RawWifiActionInjectRequest` defines the request bytes for
//! every adapter. This module is deliberately separate from radio control:
//! injection is a hardware capability, not a normal transport service. Linux
//! and ESP adapters may implement it; Android must reject it as unsupported.

use dmesh_server::raw_wifi::{RawWifiActionInjectRequest, RawWifiInterface, RawWifiRate};

/// Submit a caller-supplied action management frame through the common ESP-IDF
/// action lane. Complete non-action injection remains platform-specific until
/// its receive and sequence semantics are covered by the same matrix.
pub fn transmit_raw_action(request: RawWifiActionInjectRequest<'_>) -> Result<usize, &'static str> {
    if request.frame.len() < 24 || request.frame[0] != 0xd0 || request.frame[1] != 0 {
        return Err("raw action frame required");
    }
    if crate::wifi_radio_control_esp::channel() != Some(request.channel) {
        return Err("raw action channel mismatch");
    }
    // NAN Follow-ups are discovery-window control, never generic immediate
    // action traffic. The DW owner validates the selected cluster and rejects
    // a host probe outside its bounded capture/send interval.
    if dmesh_rawnan::is_nan_followup(request.frame) {
        return crate::wifi_nan_dw_capture_esp::send_followup_frame(request.frame);
    }
    // Active Subscribe Service Info is useful only while the peer is inside
    // its DW. Let the NAN owner send it from the next local discovery window
    // rather than attempting immediate off-channel transmission here.
    if dmesh_rawnan::is_nan_sdf(request.frame) {
        return crate::wifi_nan_dw_capture_esp::queue_sdf_frame(request.frame)
            .then_some(request.frame.len())
            .ok_or("NAN SDF queue rejected");
    }
    if request.rate != RawWifiRate::Auto
        && !crate::wifi_esp::configure_raw_tx_rate(rate_value(request.rate))
    {
        return Err("raw action rate rejected");
    }
    let interface = match request.interface {
        RawWifiInterface::Auto | RawWifiInterface::Sta => crate::wifi_esp::RadioInterface::Sta,
        RawWifiInterface::Ap => crate::wifi_esp::RadioInterface::Ap,
        RawWifiInterface::Nan => crate::wifi_esp::RadioInterface::Nan,
    };
    let destination = request.frame[4..10]
        .try_into()
        .map_err(|_| "raw action destination")?;
    let bssid = request.frame[16..22]
        .try_into()
        .map_err(|_| "raw action BSSID")?;
    if !crate::wifi_espnow_esp::transmit_public_action_on_interface(
        interface,
        destination,
        bssid,
        &request.frame[24..],
    ) {
        return Err("raw action driver rejected");
    }
    Ok(request.frame.len())
}

fn rate_value(value: RawWifiRate) -> u8 {
    match value {
        RawWifiRate::Auto => 0,
        RawWifiRate::Mbps6 => 6,
        RawWifiRate::Mbps9 => 9,
        RawWifiRate::Mbps12 => 12,
        RawWifiRate::Mbps18 => 18,
        RawWifiRate::Mbps24 => 24,
        RawWifiRate::Mbps36 => 36,
        RawWifiRate::Mbps48 => 48,
        RawWifiRate::Mbps54 => 54,
    }
}
