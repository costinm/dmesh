//! The local IPv6 interfaces discovery uses for scoped multicast and routing.

use std::collections::BTreeMap;
use std::ffi::CStr;
use std::net::{Ipv6Addr, SocketAddr};

/// One up, non-loopback interface with IPv6 addresses.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Interface {
    pub name: String,
    pub index: u32,
    pub addresses: Vec<Ipv6Addr>,
}

impl Interface {
    pub fn link_local(&self) -> Option<Ipv6Addr> {
        self.addresses.iter().copied().find(Ipv6Addr::is_unicast_link_local)
    }
}

/// Every enabled, non-loopback interface with an IPv6 address. Link-local
/// multicast needs a concrete scope: index `0` does not mean "every
/// interface" for `ff02::/16`.
pub fn local_v6_interfaces() -> Vec<Interface> {
    let mut found = BTreeMap::<String, Interface>::new();
    unsafe {
        let mut head = std::ptr::null_mut();
        if libc::getifaddrs(&mut head) != 0 {
            return Vec::new();
        }
        let mut current = head;
        while !current.is_null() {
            let entry = &*current;
            let up = entry.ifa_flags & (libc::IFF_UP as u32) != 0;
            let loopback = entry.ifa_flags & (libc::IFF_LOOPBACK as u32) != 0;
            if up
                && !loopback
                && !entry.ifa_addr.is_null()
                && (*entry.ifa_addr).sa_family as i32 == libc::AF_INET6
            {
                let index = libc::if_nametoindex(entry.ifa_name);
                let address = Ipv6Addr::from(
                    (*(entry.ifa_addr as *const libc::sockaddr_in6)).sin6_addr.s6_addr,
                );
                if index != 0 && !address.is_unspecified() {
                    let name = CStr::from_ptr(entry.ifa_name).to_string_lossy().into_owned();
                    let interface = found.entry(name.clone()).or_insert_with(|| Interface {
                        name,
                        index,
                        addresses: Vec::new(),
                    });
                    if !interface.addresses.contains(&address) {
                        interface.addresses.push(address);
                    }
                }
            }
            current = entry.ifa_next;
        }
        libc::freeifaddrs(head);
    }
    found.into_values().collect()
}

/// The interface indices to join and send IPv6 multicast on.
pub fn multicast_v6_indices() -> Vec<u32> {
    local_v6_interfaces().into_iter().map(|interface| interface.index).collect()
}

/// Whether `peer`'s link-local scope is a live interface. A scope id is a
/// local kernel object id, not a durable fact about the peer: a P2P group can
/// disappear and return with a new id while an observation is still within
/// its lifetime, and the old id must never be used as a path.
pub fn has_live_scope(peer: &SocketAddr) -> bool {
    has_scope_in(peer, local_v6_interfaces().iter().map(|interface| interface.index))
}

pub fn has_scope_in(peer: &SocketAddr, live: impl IntoIterator<Item = u32>) -> bool {
    match peer {
        SocketAddr::V6(address) if address.ip().is_unicast_link_local() => {
            address.scope_id() != 0 && live.into_iter().any(|index| index == address.scope_id())
        }
        _ => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddrV6;

    #[test]
    fn a_link_local_peer_needs_a_live_scope_and_others_do_not() {
        let link_local = |scope| {
            SocketAddr::V6(SocketAddrV6::new("fe80::1".parse().unwrap(), 3336, 0, scope))
        };
        assert!(has_scope_in(&link_local(7), [3, 7]));
        assert!(!has_scope_in(&link_local(9), [3, 7]));
        assert!(!has_scope_in(&link_local(0), [3, 7]));
        assert!(has_scope_in(&"[2001:db8::1]:3336".parse().unwrap(), []));
        assert!(has_scope_in(&"192.0.2.1:3336".parse().unwrap(), []));
    }

    #[test]
    fn interfaces_report_an_index_and_addresses() {
        for interface in local_v6_interfaces() {
            assert!(interface.index != 0 && !interface.addresses.is_empty());
        }
    }
}
