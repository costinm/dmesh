//! Owned-interface rtnetlink recovery shared by every Linux mesh launcher.

use crate::InterfaceSet;

#[derive(Debug)]
pub struct LinkEvent {
    pub kind: u16,
    pub ifindex: i32,
    pub iface: Option<String>,
    pub mac: Option<String>,
}

const RTMGRP_LINK: u32 = 1;
const IFLA_ADDRESS: u16 = 1;
const IFLA_IFNAME: u16 = 3;
const NLMSG_ALIGNTO: usize = 4;

/// Block on route-link notifications and emit only events for interfaces owned
/// by this service instance.  Callers decide whether and how to reconcile.
pub fn watch_link_events(
    owned_interfaces: InterfaceSet,
    sender: tokio::sync::mpsc::UnboundedSender<LinkEvent>,
) {
    let fd = unsafe {
        libc::socket(
            libc::AF_NETLINK,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC,
            libc::NETLINK_ROUTE,
        )
    };
    if fd < 0 {
        tracing::error!(error = %std::io::Error::last_os_error(), "rtnetlink link watcher unavailable");
        return;
    }
    let mut address: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
    address.nl_family = libc::AF_NETLINK as libc::sa_family_t;
    address.nl_groups = RTMGRP_LINK;
    let bound = unsafe {
        libc::bind(
            fd,
            &address as *const libc::sockaddr_nl as *const libc::sockaddr,
            std::mem::size_of_val(&address) as libc::socklen_t,
        )
    };
    if bound != 0 {
        tracing::error!(error = %std::io::Error::last_os_error(), "rtnetlink link watcher bind failed");
        unsafe { libc::close(fd) };
        return;
    }
    let mut buffer = [0_u8; 8192];
    loop {
        let read = unsafe { libc::recv(fd, buffer.as_mut_ptr().cast(), buffer.len(), 0) };
        if read < 0 {
            if std::io::Error::last_os_error().kind() != std::io::ErrorKind::Interrupted {
                tracing::warn!(error = %std::io::Error::last_os_error(), "rtnetlink link watcher read failed");
            }
            continue;
        }
        for event in parse_link_events(&buffer[..read as usize]) {
            let Some(iface) = event.iface.as_deref() else {
                continue;
            };
            if owned_interfaces.contains(iface) && sender.send(event).is_err() {
                unsafe { libc::close(fd) };
                return;
            }
        }
    }
}

pub fn parse_link_events(mut bytes: &[u8]) -> Vec<LinkEvent> {
    const NLMSG_HDR_LEN: usize = 16;
    const IFINFO_LEN: usize = 16;
    let mut events = Vec::new();
    while bytes.len() >= NLMSG_HDR_LEN {
        let length = u32::from_ne_bytes(bytes[..4].try_into().expect("header length")) as usize;
        let kind = u16::from_ne_bytes(bytes[4..6].try_into().expect("header type"));
        if length < NLMSG_HDR_LEN || length > bytes.len() {
            break;
        }
        if matches!(kind, libc::RTM_NEWLINK | libc::RTM_DELLINK)
            && length >= NLMSG_HDR_LEN + IFINFO_LEN
        {
            let info = &bytes[NLMSG_HDR_LEN..NLMSG_HDR_LEN + IFINFO_LEN];
            let ifindex = i32::from_ne_bytes(info[4..8].try_into().expect("ifindex"));
            let mut iface = None;
            let mut mac = None;
            let mut attrs = &bytes[NLMSG_HDR_LEN + IFINFO_LEN..length];
            while attrs.len() >= 4 {
                let attr_len =
                    u16::from_ne_bytes(attrs[..2].try_into().expect("attribute length")) as usize;
                let attr_type = u16::from_ne_bytes(attrs[2..4].try_into().expect("attribute type"));
                if attr_len < 4 || attr_len > attrs.len() {
                    break;
                }
                let value = &attrs[4..attr_len];
                match attr_type {
                    IFLA_IFNAME => {
                        iface = std::ffi::CStr::from_bytes_until_nul(value)
                            .ok()
                            .and_then(|name| name.to_str().ok())
                            .map(str::to_owned)
                    }
                    IFLA_ADDRESS if value.len() == 6 => {
                        mac = Some(
                            value
                                .iter()
                                .map(|byte| format!("{byte:02x}"))
                                .collect::<Vec<_>>()
                                .join(":"),
                        )
                    }
                    _ => {}
                }
                let aligned = (attr_len + (NLMSG_ALIGNTO - 1)) & !(NLMSG_ALIGNTO - 1);
                if aligned > attrs.len() {
                    break;
                }
                attrs = &attrs[aligned..];
            }
            events.push(LinkEvent {
                kind,
                ifindex,
                iface,
                mac,
            });
        }
        let aligned = (length + (NLMSG_ALIGNTO - 1)) & !(NLMSG_ALIGNTO - 1);
        if aligned > bytes.len() {
            break;
        }
        bytes = &bytes[aligned..];
    }
    events
}
