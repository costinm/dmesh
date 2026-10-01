// Auto-generated command catalog for DMesh chat autocomplete
#[derive(Clone, Copy, Debug)]
pub struct CatalogItem {
    pub name: &'static str,
    pub title: &'static str,
    pub desc: &'static str,
}

pub static CATALOG: &[CatalogItem] = &[
    CatalogItem {
        name: "messages",
        title: "Subscribe / Stream Messages",
        desc: "Subscribe to mesh log and chat messages",
    },
    CatalogItem {
        name: "lmesh.nodes",
        title: "",
        desc: "List currently discovered local mesh nodes",
    },
    CatalogItem {
        name: "lmesh.get_node",
        title: "",
        desc: "Return one discovered node by public key",
    },
    CatalogItem {
        name: "lmesh.announce",
        title: "",
        desc: "Send a multicast local mesh announcement",
    },
    CatalogItem {
        name: "lmesh.status",
        title: "",
        desc: "Return local discovery and radio status",
    },
    CatalogItem {
        name: "lmesh.radios.list",
        title: "",
        desc: "Return configured local radio adapters",
    },
    CatalogItem {
        name: "lmesh.neighbors",
        title: "",
        desc: "Return recently observed neighbors",
    },
    CatalogItem {
        name: "lmesh.links.list",
        title: "",
        desc: "Return local link observations and selected paths",
    },
    CatalogItem {
        name: "lmesh.ping",
        title: "",
        desc: "Discover peers over one radio or all radios",
    },
    CatalogItem {
        name: "disc",
        title: "Discover",
        desc: "Alias for ping.",
    },
    CatalogItem {
        name: "lmesh.send",
        title: "",
        desc: "Send a mesh payload over the selected radio",
    },
    CatalogItem {
        name: "link.steer",
        title: "Steer Link",
        desc: "Record a steering hint for a peer and preferred radio.",
    },
    CatalogItem {
        name: "discovery.ping",
        title: "Ping All Media",
        desc: "Queue a discovery ping intent for one medium or all configured media.",
    },
    CatalogItem {
        name: "lmesh.messages.history",
        title: "",
        desc: "Return recent radio and backend message history",
    },
    CatalogItem {
        name: "object.nan.dry_run",
        title: "Dry-run NAN Object Transfer",
        desc: "Calculate QUIC-shaped NAN stream framing and rates without opening a socket.",
    },
    CatalogItem {
        name: "wifi.raw.listen",
        title: "Listen Raw Wi-Fi",
        desc: "Listen for the custom raw vendor-action bulk transport during NAN-synchronized active windows.",
    },
    CatalogItem {
        name: "wifi.raw.send",
        title: "Send Raw Wi-Fi",
        desc: "Send custom raw vendor-action bulk traffic using the stable DMesh marker rather than the ESP-NOW API.",
    },
    CatalogItem {
        name: "wifi.raw.iperf",
        title: "Raw Action IPERF",
        desc: "Run the shared QUIC-lite IPERF client over raw ESP-NOW-compatible action frames.",
    },
    CatalogItem {
        name: "wifi.raw.ping",
        title: "Ping Raw Wi-Fi",
        desc: "Send a small custom raw-action probe.",
    },
    CatalogItem {
        name: "wifi.data.listen",
        title: "Listen Wi-Fi Data",
        desc: "Listen for DMesh Ethernet frames on the normal AP/STA netdev path and request packet multicast membership for the DMesh receive addresses.",
    },
    CatalogItem {
        name: "wifi.data.send",
        title: "Send Wi-Fi Data",
        desc: "Send a DMesh Ethernet frame with EtherType 0x88b5 on the normal AP/STA netdev path.",
    },
    CatalogItem {
        name: "wifi.mgmt.capture",
        title: "",
        desc: "Capture a bounded host management-frame sample",
    },
    CatalogItem {
        name: "wifi.ap.start_open",
        title: "Start Open AP",
        desc: "Start a password-less open AP on channel 6. Default SSID is Direct-XXXXXXXX-Dmesh-local from the interface MAC suffix. Records AP SME auth/assoc/probe/deauth frames as wifi.ap.mgmt while running.",
    },
    CatalogItem {
        name: "wifi.ap.stop",
        title: "Stop AP",
        desc: "Stop AP operation on an interface.",
    },
    CatalogItem {
        name: "wifi.ap.status",
        title: "AP Status",
        desc: "Return open AP defaults and station metrics where available.",
    },
    CatalogItem {
        name: "wifi.ap.stations",
        title: "AP Stations",
        desc: "Dump associated station metrics through nl80211.",
    },
    CatalogItem {
        name: "wifi.ap.station.add",
        title: "Add Station",
        desc: "Experimental: add a station entry by MAC without a normal auth/assoc exchange.",
    },
    CatalogItem {
        name: "wifi.ap.station.remove",
        title: "Remove AP Station",
        desc: "Disconnect one associated station without stopping the AP.",
    },
    CatalogItem {
        name: "wifi.ap.station.remove_all",
        title: "Remove All AP Stations",
        desc: "Disconnect all associated stations without stopping the AP.",
    },
    CatalogItem {
        name: "wifi.sta.join_open",
        title: "Join Open AP",
        desc: "Join a password-less open AP on channel 6.",
    },
    CatalogItem {
        name: "wifi.sta.status",
        title: "Station Status",
        desc: "Return station-mode AP peer metrics from nl80211.",
    },
    CatalogItem {
        name: "wifi.sta.configure_ipv4",
        title: "Configure Station IPv4",
        desc: "Configure a static IPv4 address through the managed lmesh process.",
    },
    CatalogItem {
        name: "wifi.scan",
        title: "Wi-Fi Scan",
        desc: "Scan for nearby Wi-Fi BSS entries through the lmesh radio process.",
    },
    CatalogItem {
        name: "wifi.adv",
        title: "Wi-Fi Advertise",
        desc: "Enable or disable Wi-Fi service advertisement through the local adapter.",
    },
    CatalogItem {
        name: "wifi.con.start",
        title: "Start Wi-Fi Discovery",
        desc: "Start Wi-Fi Direct/service discovery through the local adapter.",
    },
    CatalogItem {
        name: "wifi.con.stop",
        title: "Stop Wi-Fi Discovery",
        desc: "Stop Wi-Fi Direct/service discovery through the local adapter.",
    },
    CatalogItem {
        name: "ble.scan",
        title: "BLE Scan",
        desc: "Request a BLE scan through the local adapter.",
    },
    CatalogItem {
        name: "ble.adv",
        title: "BLE Advertise",
        desc: "Enable or disable DMesh BLE service-data advertisements through raw Linux HCI sockets.",
    },
    CatalogItem {
        name: "lmesh.announces",
        title: "",
        desc: "List observed bearer-neutral announces",
    },
    CatalogItem {
        name: "lmesh.probe",
        title: "",
        desc: "Run a NAN-first peer health probe and select a bearer",
    },
    CatalogItem {
        name: "wifi.rawnan.status",
        title: "",
        desc: "Return raw-NAN status, the bounded one-hour cross-bearer discovered-device inventory, and NAN follow-ups. New/dropped devices append JSONL records to LMESH_DISCOVERY_LOG or LMESH_WIFI_DISCOVERY_LOG (default /run/mesh/lmesh-wifi/discovery.jsonl); routine refreshes do not log.",
    },
    CatalogItem {
        name: "wifi.rawnan.active_publish",
        title: "",
        desc: "Replace the local active NAN Publish Service Info. An enabled descriptor is emitted once in the next confirmed discovery window and then at the bounded refresh cadence; this request never transmits immediately or changes interface state. service_info_hex is the bounded CBOR Service Info payload.",
    },
    CatalogItem {
        name: "wifi.probe.plan",
        title: "",
        desc: "Resolve a discovery-selected comprehensive pair probe and return the live ESP/Android/Host fleet without changing the control-plane radio",
    },
    CatalogItem {
        name: "wifi.interface.status",
        title: "",
        desc: "Return owned interface status",
    },
    CatalogItem {
        name: "wifi.raw.metrics",
        title: "",
        desc: "Return bounded raw action receive and dispatch counters",
    },
    CatalogItem {
        name: "wifi.raw.stop",
        title: "",
        desc: "Stop the raw action listener",
    },
    CatalogItem {
        name: "wifi.raw.check",
        title: "",
        desc: "Run one raw action liveness check",
    },
    CatalogItem {
        name: "wifi.rawnan.ping",
        title: "",
        desc: "Send a bounded NAN discovery probe",
    },
    CatalogItem {
        name: "wifi.rawnan.listen",
        title: "",
        desc: "Start or renew a bounded raw-NAN listener",
    },
];
