//! Service-local authorization envelope for generated Wi-Fi API requests.
//!
//! `api.rs` is generated from `API.md`. This enum deliberately stays outside
//! that artifact: it selects the reviewed operation after decoding, without
//! becoming a second wire schema.

use crate::api::*;

pub enum ReviewedWifiRequest {
    ApStatus(WifiApStatusRequest),
    StaStatus(WifiStaStatusRequest),
    RawNanStatus(WifiRawnanStatusRequest),
    InterfaceStatus(WifiInterfaceStatusRequest),
    ApStations(WifiApStationsRequest),
    RawMetrics(WifiRawMetricsRequest),
    RawStop(WifiRawStopRequest),
    RawListen(WifiRawListenRequest),
    RawCheck(WifiRawCheckRequest),
    RawIperf(WifiRawIperfRequest),
    RawSend(WifiRawSendRequest),
    RawNanPing(WifiRawnanPingRequest),
    RawNanListen(WifiRawnanListenRequest),
}
