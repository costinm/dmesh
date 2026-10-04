//! Moved from `lmesh-wifi/src/radio.rs` (see notes/plans/lmesh-wifi-extraction.md).
#![allow(clippy::too_many_arguments)]
use super::*;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct NlMsgHdr {
    pub nlmsg_len: u32,
    pub nlmsg_type: u16,
    pub nlmsg_flags: u16,
    pub nlmsg_seq: u32,
    pub nlmsg_pid: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct NlMsgErr {
    pub error: i32,
    pub msg: NlMsgHdr,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct IfInfoMsg {
    pub ifi_family: u8,
    pub ifi_pad: u8,
    pub ifi_type: u16,
    pub ifi_index: i32,
    pub ifi_flags: u32,
    pub ifi_change: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct IfAddrMsg {
    pub ifa_family: u8,
    pub ifa_prefixlen: u8,
    pub ifa_flags: u8,
    pub ifa_scope: u8,
    pub ifa_index: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct RtAttrHdr {
    pub rta_len: u16,
    pub rta_type: u16,
}

#[derive(Debug)]
pub struct CommandOutput {
    pub status: Option<i32>,
    pub stdout: String,
    pub stderr: String,
}

pub fn link_local_from_mac(mac: [u8; 6]) -> std::net::Ipv6Addr {
    let mut bytes = [0_u8; 16];
    bytes[0] = 0xfe;
    bytes[1] = 0x80;
    bytes[8] = mac[0] ^ 0x02;
    bytes[9] = mac[1];
    bytes[10] = mac[2];
    bytes[11] = 0xff;
    bytes[12] = 0xfe;
    bytes[13] = mac[3];
    bytes[14] = mac[4];
    bytes[15] = mac[5];
    std::net::Ipv6Addr::from(bytes)
}

pub fn ready_link_local_address(iface: &str) -> Option<std::net::Ipv6Addr> {
    let contents = std::fs::read_to_string("/proc/net/if_inet6").ok()?;
    contents.lines().find_map(|line| {
        let fields = line.split_whitespace().collect::<Vec<_>>();
        if fields.len() != 6 || fields[5] != iface || !fields[0].starts_with("fe80") {
            return None;
        }
        let flags = u32::from_str_radix(fields[4], 16).ok()?;
        if flags & IPV6_ADDR_TENTATIVE != 0 {
            return None;
        }
        let mut bytes = [0_u8; 16];
        for (index, byte) in bytes.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&fields[0][index * 2..index * 2 + 2], 16).ok()?;
        }
        Some(std::net::Ipv6Addr::from(bytes))
    })
}

pub fn wait_for_link_local_address(iface: &str, attempts: usize) -> Option<std::net::Ipv6Addr> {
    for attempt in 0..attempts.max(1) {
        if let Some(address) = ready_link_local_address(iface) {
            return Some(address);
        }
        if attempt + 1 != attempts.max(1) {
            std::thread::sleep(Duration::from_millis(100));
        }
    }
    None
}

/// Keep scoped UDP6 usable after USB/driver resets that leave an administratively
/// up Wi-Fi STA without the normally automatic IPv6 link-local address.
pub fn ensure_link_local_address(iface: &str) -> Result<String> {
    if let Some(address) = wait_for_link_local_address(iface, 10) {
        return Ok(address.to_string());
    }
    let address = link_local_from_mac(iface_mac(iface)?);
    set_ipv6_link_local_address(iface, address).map_err(anyhow::Error::msg)?;
    wait_for_link_local_address(iface, 30)
        .map(|address| address.to_string())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "IPv6 link-local address {address}%{iface} did not become non-tentative"
            )
        })
}

pub fn interface_link_status(iface: &str) -> Value {
    match ifindex(iface) {
        Ok(ifindex) => match get_link_flags(ifindex as i32) {
            Ok(flags) => {
                let mut names = Vec::new();
                if flags & IFF_UP != 0 {
                    names.push("UP");
                }
                if flags & libc::IFF_RUNNING as u32 != 0 {
                    names.push("RUNNING");
                }
                if flags & libc::IFF_LOOPBACK as u32 != 0 {
                    names.push("LOOPBACK");
                }
                json!({
                    "ok": true,
                    "backend": "rtnetlink",
                    "iface": iface,
                    "ifindex": ifindex,
                    // Preserve the established operator/test presentation
                    // while sourcing it directly from RTM_GETLINK.
                    "stdout": format!("{ifindex}: {iface}: <{}>", names.join(",")),
                    "flags": flags,
                })
            }
            Err(error) => {
                json!({"ok": false, "backend": "rtnetlink", "iface": iface, "ifindex": ifindex, "error": error})
            }
        },
        Err(error) => json!({
            "ok": false,
            "backend": "rtnetlink",
            "iface": iface,
            "error": format!("{error:#}"),
        }),
    }
}

pub fn get_link_flags(ifindex: i32) -> std::result::Result<u32, String> {
    let fd = unsafe {
        libc::socket(
            libc::AF_NETLINK,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC,
            libc::NETLINK_ROUTE,
        )
    };
    if fd < 0 {
        return Err(format!(
            "open rtnetlink socket: {}",
            std::io::Error::last_os_error()
        ));
    }
    let header_len = std::mem::size_of::<NlMsgHdr>();
    let info_len = std::mem::size_of::<IfInfoMsg>();
    let header = NlMsgHdr {
        nlmsg_len: (header_len + info_len) as u32,
        nlmsg_type: libc::RTM_GETLINK,
        nlmsg_flags: NLM_F_REQUEST,
        nlmsg_seq: 2,
        nlmsg_pid: 0,
    };
    let mut info: IfInfoMsg = unsafe { std::mem::zeroed() };
    info.ifi_family = libc::AF_UNSPEC as u8;
    info.ifi_index = ifindex;
    let mut request = Vec::with_capacity(header_len + info_len);
    append_struct(&mut request, &header);
    append_struct(&mut request, &info);
    let sent = unsafe {
        libc::send(
            fd,
            request.as_ptr() as *const libc::c_void,
            request.len(),
            0,
        )
    };
    if sent != request.len() as isize {
        let error = if sent < 0 {
            std::io::Error::last_os_error().to_string()
        } else {
            "short RTM_GETLINK write".to_owned()
        };
        unsafe {
            libc::close(fd);
        }
        return Err(error);
    }
    let mut response = [0_u8; 4096];
    let read = unsafe {
        libc::recv(
            fd,
            response.as_mut_ptr() as *mut libc::c_void,
            response.len(),
            0,
        )
    };
    unsafe {
        libc::close(fd);
    }
    if read < 0 {
        return Err(format!(
            "read RTM_GETLINK: {}",
            std::io::Error::last_os_error()
        ));
    }
    let response = &response[..read as usize];
    if response.len() < header_len + info_len {
        return Err("short RTM_GETLINK response".to_owned());
    }
    let header = unsafe { std::ptr::read_unaligned(response.as_ptr() as *const NlMsgHdr) };
    if header.nlmsg_type == NLMSG_ERROR {
        return Err("RTM_GETLINK returned netlink error".to_owned());
    }
    if header.nlmsg_type != libc::RTM_NEWLINK {
        return Err(format!(
            "unexpected RTM_GETLINK response type {}",
            header.nlmsg_type
        ));
    }
    let info =
        unsafe { std::ptr::read_unaligned(response[header_len..].as_ptr() as *const IfInfoMsg) };
    Ok(info.ifi_flags)
}

pub fn list_rtnetlink_interfaces() -> std::result::Result<Vec<Value>, String> {
    let fd = unsafe {
        libc::socket(
            libc::AF_NETLINK,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC,
            libc::NETLINK_ROUTE,
        )
    };
    if fd < 0 {
        return Err(format!(
            "open rtnetlink socket: {}",
            std::io::Error::last_os_error()
        ));
    }
    let header_len = std::mem::size_of::<NlMsgHdr>();
    let info_len = std::mem::size_of::<IfInfoMsg>();
    let header = NlMsgHdr {
        nlmsg_len: (header_len + info_len) as u32,
        nlmsg_type: libc::RTM_GETLINK,
        nlmsg_flags: NLM_F_REQUEST | NLM_F_DUMP,
        nlmsg_seq: 3,
        nlmsg_pid: 0,
    };
    let mut info: IfInfoMsg = unsafe { std::mem::zeroed() };
    info.ifi_family = libc::AF_UNSPEC as u8;
    let mut request = Vec::with_capacity(header_len + info_len);
    append_struct(&mut request, &header);
    append_struct(&mut request, &info);
    let sent = unsafe { libc::send(fd, request.as_ptr().cast(), request.len(), 0) };
    if sent != request.len() as isize {
        let error = if sent < 0 {
            std::io::Error::last_os_error().to_string()
        } else {
            "short RTM_GETLINK dump write".to_owned()
        };
        unsafe {
            libc::close(fd);
        }
        return Err(error);
    }

    let mut interfaces = Vec::new();
    let mut buffer = [0_u8; 8192];
    loop {
        let read = unsafe { libc::recv(fd, buffer.as_mut_ptr().cast(), buffer.len(), 0) };
        if read < 0 {
            let error = std::io::Error::last_os_error().to_string();
            unsafe {
                libc::close(fd);
            }
            return Err(format!("read RTM_GETLINK dump: {error}"));
        }
        let mut bytes = &buffer[..read as usize];
        while bytes.len() >= header_len {
            let message = unsafe { std::ptr::read_unaligned(bytes.as_ptr() as *const NlMsgHdr) };
            let length = message.nlmsg_len as usize;
            if length < header_len || length > bytes.len() {
                unsafe {
                    libc::close(fd);
                }
                return Err("malformed RTM_GETLINK dump message".to_owned());
            }
            match message.nlmsg_type {
                NLMSG_DONE => {
                    unsafe {
                        libc::close(fd);
                    }
                    return Ok(interfaces);
                }
                NLMSG_ERROR => {
                    unsafe {
                        libc::close(fd);
                    }
                    return Err("RTM_GETLINK dump returned netlink error".to_owned());
                }
                kind if kind == libc::RTM_NEWLINK => {
                    if length >= header_len + info_len {
                        let info = unsafe {
                            std::ptr::read_unaligned(
                                bytes[header_len..].as_ptr() as *const IfInfoMsg
                            )
                        };
                        let mut name = None;
                        let mut mac = None;
                        let mut attrs = &bytes[header_len + info_len..length];
                        while attrs.len() >= std::mem::size_of::<RtAttrHdr>() {
                            let attr = unsafe {
                                std::ptr::read_unaligned(attrs.as_ptr() as *const RtAttrHdr)
                            };
                            let attr_len = attr.rta_len as usize;
                            if attr_len < std::mem::size_of::<RtAttrHdr>() || attr_len > attrs.len()
                            {
                                break;
                            }
                            let payload = &attrs[std::mem::size_of::<RtAttrHdr>()..attr_len];
                            match attr.rta_type & NLA_TYPE_MASK {
                                1 if payload.len() == 6 => {
                                    mac = Some(
                                        payload
                                            .iter()
                                            .map(|byte| format!("{byte:02x}"))
                                            .collect::<Vec<_>>()
                                            .join(":"),
                                    )
                                }
                                3 => {
                                    name = std::ffi::CStr::from_bytes_until_nul(payload)
                                        .ok()
                                        .and_then(|name| name.to_str().ok())
                                        .map(str::to_owned)
                                }
                                _ => {}
                            }
                            let aligned = (attr_len + 3) & !3;
                            if aligned > attrs.len() {
                                break;
                            }
                            attrs = &attrs[aligned..];
                        }
                        interfaces.push(json!({"ifindex": info.ifi_index, "iface": name, "mac": mac, "flags": info.ifi_flags}));
                    }
                }
                _ => {}
            }
            let aligned = (length + 3) & !3;
            if aligned > bytes.len() {
                break;
            }
            bytes = &bytes[aligned..];
        }
    }
}

pub fn link_state_result(iface: &str, up: bool) -> Value {
    match set_link_state(iface, up) {
        Ok(output) => json!({
            "ok": true,
            "backend": "rtnetlink",
            "iface": iface,
            "state": if up { "up" } else { "down" },
            "stdout": output.stdout,
        }),
        Err(error) => json!({
            "ok": false,
            "backend": "rtnetlink",
            "iface": iface,
            "state": if up { "up" } else { "down" },
            "error": error,
        }),
    }
}

/// Request an administrative link-up and confirm it through a fresh
/// RTM_GETLINK read. USB Wi-Fi drivers can deliver a delayed or dropped ACK
/// while applying the state transition, so neither an ACK nor a timeout alone
/// is authoritative. Keep recovery bounded and retain every attempt for
/// operator diagnosis.
pub fn link_up_confirmed(iface: &str, attempts: usize) -> Value {
    let attempts = attempts.clamp(1, 3);
    let mut history = Vec::with_capacity(attempts);
    for attempt in 1..=attempts {
        let request = link_state_result(iface, true);
        let observed = ifindex(iface)
            .and_then(|index| get_link_flags(index as i32).map_err(anyhow::Error::msg));
        let up = observed.as_ref().is_ok_and(|flags| flags & IFF_UP != 0);
        history.push(json!({
            "attempt": attempt,
            "request": request,
            "flags": observed.as_ref().ok().copied(),
            "up": up,
            "read_error": observed.as_ref().err().map(|error| error.to_string()),
        }));
        if up {
            return json!({"ok": true, "backend": "rtnetlink", "iface": iface, "state": "up", "attempts": history});
        }
        if attempt != attempts {
            std::thread::sleep(Duration::from_millis(250));
        }
    }
    json!({"ok": false, "backend": "rtnetlink", "iface": iface, "state": "up", "attempts": history})
}

pub fn set_link_up(iface: &str) -> std::result::Result<CommandOutput, String> {
    set_link_state(iface, true)
}

pub fn set_link_state(iface: &str, up: bool) -> std::result::Result<CommandOutput, String> {
    let iface_c = std::ffi::CString::new(iface.as_bytes())
        .map_err(|_| format!("interface name contains NUL byte: {iface:?}"))?;
    let ifindex = unsafe { libc::if_nametoindex(iface_c.as_ptr()) };
    if ifindex == 0 {
        return Err(format!(
            "if_nametoindex({iface}) failed: {}",
            std::io::Error::last_os_error()
        ));
    }

    let fd = unsafe {
        libc::socket(
            libc::AF_NETLINK,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC,
            libc::NETLINK_ROUTE,
        )
    };
    if fd < 0 {
        return Err(format!(
            "failed to open rtnetlink socket: {}",
            std::io::Error::last_os_error()
        ));
    }

    let result = unsafe { send_setlink_state(fd, ifindex as i32, up) };
    unsafe {
        libc::close(fd);
    }
    result.map(|()| CommandOutput {
        status: Some(0),
        stdout: format!(
            "set {iface} {} via rtnetlink",
            if up { "up" } else { "down" }
        ),
        stderr: String::new(),
    })
}

pub fn set_ipv4_address(
    iface: &str,
    address: std::net::Ipv4Addr,
    prefix: u8,
) -> std::result::Result<CommandOutput, String> {
    let ifindex = ifindex(iface).map_err(|error| error.to_string())?;
    let fd = unsafe {
        libc::socket(
            libc::AF_NETLINK,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC,
            libc::NETLINK_ROUTE,
        )
    };
    if fd < 0 {
        return Err(format!(
            "failed to open rtnetlink socket: {}",
            std::io::Error::last_os_error()
        ));
    }

    let result = unsafe { send_setaddr(fd, ifindex, address, prefix) };
    unsafe {
        libc::close(fd);
    }
    result.map(|()| CommandOutput {
        status: Some(0),
        stdout: format!("set {iface} IPv4 address {address}/{prefix} via rtnetlink"),
        stderr: String::new(),
    })
}

pub fn set_ipv6_link_local_address(
    iface: &str,
    address: std::net::Ipv6Addr,
) -> std::result::Result<CommandOutput, String> {
    let ifindex = ifindex(iface).map_err(|error| error.to_string())?;
    let fd = unsafe {
        libc::socket(
            libc::AF_NETLINK,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC,
            libc::NETLINK_ROUTE,
        )
    };
    if fd < 0 {
        return Err(format!(
            "failed to open rtnetlink socket: {}",
            std::io::Error::last_os_error()
        ));
    }
    let result = unsafe { send_setaddr6(fd, ifindex, address) };
    unsafe {
        libc::close(fd);
    }
    result.map(|()| CommandOutput {
        status: Some(0),
        stdout: format!("set {iface} IPv6 link-local {address}/64 via rtnetlink"),
        stderr: String::new(),
    })
}

pub unsafe fn send_setaddr6(
    fd: RawFd,
    ifindex: u32,
    address: std::net::Ipv6Addr,
) -> std::result::Result<(), String> {
    let header_len = std::mem::size_of::<NlMsgHdr>();
    let info_len = std::mem::size_of::<IfAddrMsg>();
    let mut request = Vec::with_capacity(header_len + info_len + 48);
    append_struct(
        &mut request,
        &NlMsgHdr {
            nlmsg_len: 0,
            nlmsg_type: libc::RTM_NEWADDR,
            nlmsg_flags: NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_REPLACE,
            nlmsg_seq: 3,
            nlmsg_pid: 0,
        },
    );
    append_struct(
        &mut request,
        &IfAddrMsg {
            ifa_family: libc::AF_INET6 as u8,
            ifa_prefixlen: 64,
            // This path runs only after the kernel has failed to generate any
            // link-local address and its normal DAD window has elapsed.  The
            // address is the interface's EUI-64 link-local identity, so retain a
            // deterministic usable scoped address instead of an indefinitely
            // tentative one on USB drivers that never emit the DAD completion.
            ifa_flags: libc::IFA_F_NODAD as u8,
            ifa_scope: libc::RT_SCOPE_LINK as u8,
            ifa_index: ifindex,
        },
    );
    let bytes = address.octets();
    append_rt_attr(&mut request, IFA_ADDRESS, &bytes);
    append_rt_attr(&mut request, IFA_LOCAL, &bytes);
    let header_ptr = request.as_mut_ptr() as *mut NlMsgHdr;
    unsafe {
        (*header_ptr).nlmsg_len = request.len() as u32;
    }
    let written = unsafe { libc::send(fd, request.as_ptr().cast(), request.len(), 0) };
    if written != request.len() as isize {
        return Err(if written < 0 {
            format!(
                "failed to send IPv6 RTM_NEWADDR: {}",
                std::io::Error::last_os_error()
            )
        } else {
            "short IPv6 RTM_NEWADDR write".to_owned()
        });
    }
    let mut response = [0_u8; 4096];
    let read = unsafe { libc::recv(fd, response.as_mut_ptr().cast(), response.len(), 0) };
    if read < 0 {
        return Err(format!(
            "read IPv6 RTM_NEWADDR: {}",
            std::io::Error::last_os_error()
        ));
    }
    if (read as usize) < std::mem::size_of::<NlMsgHdr>() {
        return Err("short IPv6 RTM_NEWADDR response".to_owned());
    }
    let header = unsafe { std::ptr::read_unaligned(response.as_ptr() as *const NlMsgHdr) };
    if header.nlmsg_type == NLMSG_ERROR {
        if read as usize >= std::mem::size_of::<NlMsgHdr>() + std::mem::size_of::<NlMsgErr>() {
            let error = unsafe {
                std::ptr::read_unaligned(
                    response[std::mem::size_of::<NlMsgHdr>()..].as_ptr() as *const NlMsgErr
                )
            };
            if error.error != 0 {
                return Err(format!(
                    "IPv6 RTM_NEWADDR failed: {}",
                    std::io::Error::from_raw_os_error(-error.error)
                ));
            }
        }
    }
    Ok(())
}

pub unsafe fn send_setaddr(
    fd: RawFd,
    ifindex: u32,
    address: std::net::Ipv4Addr,
    prefix: u8,
) -> std::result::Result<(), String> {
    let header_len = std::mem::size_of::<NlMsgHdr>();
    let info_len = std::mem::size_of::<IfAddrMsg>();
    let mut request = Vec::with_capacity(header_len + info_len + 16);
    let header = NlMsgHdr {
        nlmsg_len: 0,
        nlmsg_type: libc::RTM_NEWADDR,
        nlmsg_flags: NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_REPLACE,
        nlmsg_seq: 2,
        nlmsg_pid: 0,
    };
    let info = IfAddrMsg {
        ifa_family: libc::AF_INET as u8,
        ifa_prefixlen: prefix,
        ifa_flags: 0,
        ifa_scope: 0,
        ifa_index: ifindex,
    };
    append_struct(&mut request, &header);
    append_struct(&mut request, &info);
    let bytes = address.octets();
    append_rt_attr(&mut request, IFA_ADDRESS, &bytes);
    append_rt_attr(&mut request, IFA_LOCAL, &bytes);
    let ip = u32::from_be_bytes(bytes);
    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - u32::from(prefix))
    };
    append_rt_attr(
        &mut request,
        IFA_BROADCAST,
        &((ip & mask) | !mask).to_be_bytes(),
    );
    let message_len = request.len() as u32;
    let header_ptr = request.as_mut_ptr() as *mut NlMsgHdr;
    unsafe {
        (*header_ptr).nlmsg_len = message_len;
    }

    let written = unsafe {
        libc::send(
            fd,
            request.as_ptr() as *const libc::c_void,
            request.len(),
            0,
        )
    };
    if written < 0 {
        return Err(format!(
            "failed to send RTM_NEWADDR: {}",
            std::io::Error::last_os_error()
        ));
    }
    if written as usize != request.len() {
        return Err(format!(
            "short RTM_NEWADDR write: wrote {written}, expected {}",
            request.len()
        ));
    }
    let mut response = [0u8; 4096];
    let read = unsafe {
        libc::recv(
            fd,
            response.as_mut_ptr() as *mut libc::c_void,
            response.len(),
            0,
        )
    };
    if read < 0 {
        return Err(format!(
            "failed to read RTM_NEWADDR ACK: {}",
            std::io::Error::last_os_error()
        ));
    }
    parse_netlink_ack(&response[..read as usize])
}

pub fn append_rt_attr(out: &mut Vec<u8>, attr_type: u16, payload: &[u8]) {
    let raw_len = std::mem::size_of::<RtAttrHdr>() + payload.len();
    let aligned_len = (raw_len + 3) & !3;
    let header = RtAttrHdr {
        rta_len: raw_len as u16,
        rta_type: attr_type,
    };
    append_struct(out, &header);
    out.extend_from_slice(payload);
    out.resize(out.len() + aligned_len - raw_len, 0);
}

pub unsafe fn send_setlink_state(fd: RawFd, ifindex: i32, up: bool) -> std::result::Result<(), String> {
    let header_len = std::mem::size_of::<NlMsgHdr>();
    let info_len = std::mem::size_of::<IfInfoMsg>();
    let msg_len = header_len + info_len;
    let header = NlMsgHdr {
        nlmsg_len: msg_len as u32,
        nlmsg_type: libc::RTM_NEWLINK,
        nlmsg_flags: NLM_F_REQUEST | NLM_F_ACK,
        nlmsg_seq: 1,
        nlmsg_pid: 0,
    };
    let mut info: IfInfoMsg = unsafe { std::mem::zeroed() };
    info.ifi_family = libc::AF_UNSPEC as u8;
    info.ifi_index = ifindex;
    info.ifi_flags = if up { IFF_UP } else { 0 };
    info.ifi_change = IFF_UP;
    let mut request = Vec::with_capacity(msg_len);
    append_struct(&mut request, &header);
    append_struct(&mut request, &info);

    let written = unsafe {
        libc::send(
            fd,
            request.as_ptr() as *const libc::c_void,
            request.len(),
            0,
        )
    };
    if written < 0 {
        return Err(format!(
            "failed to send RTM_NEWLINK: {}",
            std::io::Error::last_os_error()
        ));
    }
    if written as usize != request.len() {
        return Err(format!(
            "short RTM_NEWLINK write: wrote {written}, expected {}",
            request.len()
        ));
    }

    let mut response = [0u8; 4096];
    let read = unsafe {
        libc::recv(
            fd,
            response.as_mut_ptr() as *mut libc::c_void,
            response.len(),
            0,
        )
    };
    if read < 0 {
        return Err(format!(
            "failed to read RTM_NEWLINK ACK: {}",
            std::io::Error::last_os_error()
        ));
    }
    parse_netlink_ack(&response[..read as usize])
}

pub fn append_struct<T>(out: &mut Vec<u8>, value: &T) {
    let bytes = unsafe {
        std::slice::from_raw_parts(value as *const T as *const u8, std::mem::size_of::<T>())
    };
    out.extend_from_slice(bytes);
}

pub fn parse_netlink_ack(response: &[u8]) -> std::result::Result<(), String> {
    if response.len() < std::mem::size_of::<NlMsgHdr>() {
        return Err("short netlink ACK".to_string());
    }
    let header = unsafe { std::ptr::read_unaligned(response.as_ptr() as *const NlMsgHdr) };
    if header.nlmsg_type != NLMSG_ERROR {
        return Ok(());
    }
    if response.len() < std::mem::size_of::<NlMsgHdr>() + std::mem::size_of::<NlMsgErr>() {
        return Err("short netlink error ACK".to_string());
    }
    let err_offset = std::mem::size_of::<NlMsgHdr>();
    let error = unsafe { std::ptr::read_unaligned(response[err_offset..].as_ptr() as *const i32) };
    if error == 0 {
        Ok(())
    } else {
        let errno = -error;
        Err(format!(
            "RTM_NEWLINK failed: {}",
            std::io::Error::from_raw_os_error(errno)
        ))
    }
}

pub fn ifindex(iface: &str) -> Result<u32> {
    let iface_c = std::ffi::CString::new(iface.as_bytes())
        .map_err(|_| anyhow::anyhow!("interface name contains NUL byte: {iface:?}"))?;
    let ifindex = unsafe { libc::if_nametoindex(iface_c.as_ptr()) };
    if ifindex == 0 {
        bail!(
            "if_nametoindex({iface}) failed: {}",
            std::io::Error::last_os_error()
        );
    }
    Ok(ifindex)
}

pub fn ifname_from_ifindex(ifindex: u32) -> Option<String> {
    let mut buf = [0 as libc::c_char; libc::IF_NAMESIZE];
    let ptr = unsafe { libc::if_indextoname(ifindex, buf.as_mut_ptr()) };
    if ptr.is_null() {
        return None;
    }
    let cstr = unsafe { std::ffi::CStr::from_ptr(buf.as_ptr()) };
    cstr.to_str().ok().map(ToString::to_string)
}

pub fn iface_mac(iface: &str) -> Result<[u8; 6]> {
    let iface_c = std::ffi::CString::new(iface.as_bytes())
        .map_err(|_| anyhow::anyhow!("interface name contains NUL byte: {iface:?}"))?;
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error()).context("failed to open ioctl socket");
    }
    let mut request: libc::ifreq = unsafe { std::mem::zeroed() };
    let name_bytes = iface_c.as_bytes_with_nul();
    if name_bytes.len() > request.ifr_name.len() {
        unsafe {
            libc::close(fd);
        }
        bail!("interface name too long: {iface}");
    }
    for (idx, byte) in name_bytes.iter().enumerate() {
        request.ifr_name[idx] = *byte as libc::c_char;
    }
    let rc = unsafe { libc::ioctl(fd, libc::SIOCGIFHWADDR as libc::Ioctl, &mut request) };
    let error = std::io::Error::last_os_error();
    unsafe {
        libc::close(fd);
    }
    if rc < 0 {
        return Err(error).with_context(|| format!("failed to read hardware address for {iface}"));
    }
    let mut out = [0_u8; 6];
    unsafe {
        let data = request.ifr_ifru.ifru_hwaddr.sa_data;
        for (idx, slot) in out.iter_mut().enumerate() {
            *slot = data[idx] as u8;
        }
    }
    Ok(out)
}

pub fn parse_mac(value: Option<&str>) -> Option<[u8; 6]> {
    let value = value?;
    let compact = value.replace([':', '-'], "");
    if compact.len() != 12 {
        return None;
    }
    let mut out = [0_u8; 6];
    for (idx, slot) in out.iter_mut().enumerate() {
        *slot = u8::from_str_radix(&compact[idx * 2..idx * 2 + 2], 16).ok()?;
    }
    Some(out)
}

pub fn run_command(program: &str, args: &[&str]) -> Value {
    // Deliberately retained as a structured compatibility response for old
    // methods, but never executes a host command. Wi-Fi state is owned by
    // nl80211/rtnetlink; wpa_supplicant is the only permitted child process.
    json!({
        "program": program,
        "args": args,
        "ok": false,
        "error": "host command execution is disabled; use nl80211/rtnetlink",
    })
}
