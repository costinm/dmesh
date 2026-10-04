//! Explicit UDP endpoints: `udp://[fe80::1%wlan0]:3337`, `[2001:db8::1]:3336`,
//! `192.0.2.1`.

use std::net::{IpAddr, Ipv6Addr, SocketAddr, SocketAddrV6};

/// What an endpoint that omits its port or its link-local scope gets.
#[derive(Clone, Copy, Debug)]
pub struct EndpointDefaults {
    /// The normal DMesh UDP port.
    pub port: u16,
    /// The scope for an unscoped link-local address: the receiver's configured
    /// ingress interface, if it has one.
    pub scope: Option<u32>,
}

#[derive(Debug, Eq, PartialEq)]
pub enum EndpointError {
    /// A `%interface` scope that names no interface.
    UnknownScope(String),
}

impl std::fmt::Display for EndpointError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownScope(scope) => write!(f, "unknown IPv6 scope interface {scope:?}"),
        }
    }
}

impl std::error::Error for EndpointError {}

/// The index of an interface named by number or by name.
fn scope_index(scope: &str) -> Option<u32> {
    scope.parse::<u32>().ok().or_else(|| {
        std::fs::read_to_string(format!("/sys/class/net/{scope}/ifindex"))
            .ok()
            .and_then(|value| value.trim().parse::<u32>().ok())
    })
}

/// Parse an explicit UDP endpoint. `Ok(None)` means the text is not one (a
/// node name, `mesh://VIP`, a MAC address): the caller tries another route.
/// An interface name in the scope is resolved here and never leaves this node.
pub fn parse_udp_endpoint(
    text: &str,
    defaults: &EndpointDefaults,
) -> Result<Option<SocketAddr>, EndpointError> {
    let value = text.trim();
    if value.is_empty() {
        return Ok(None);
    }
    let value = value.strip_prefix("udp://").unwrap_or(value);
    if let Ok(mut endpoint) = value.parse::<SocketAddr>() {
        if let SocketAddr::V6(address) = &mut endpoint
            && address.ip().is_unicast_link_local()
            && address.scope_id() == 0
        {
            address.set_scope_id(defaults.scope.unwrap_or(0));
        }
        return Ok(Some(endpoint));
    }
    // `[address%scope]:port`, which `SocketAddr` does not read.
    if let Some((bracketed, port)) = value.rsplit_once("]:")
        && let Some(scoped) = bracketed.strip_prefix('[')
        && let Some((address, scope)) = scoped.rsplit_once('%')
        && let (Ok(address), Ok(port)) = (address.parse::<Ipv6Addr>(), port.parse::<u16>())
    {
        let index = scope_index(scope).ok_or_else(|| EndpointError::UnknownScope(scope.to_owned()))?;
        return Ok(Some(SocketAddr::V6(SocketAddrV6::new(address, port, 0, index))));
    }
    // `[address]` and `[address%scope]`, without a port.
    if let Some(inner) = value.strip_prefix('[').and_then(|rest| rest.strip_suffix(']')) {
        let (address, scope) = inner
            .rsplit_once('%')
            .map_or((inner, None), |(address, scope)| (address, Some(scope)));
        if let Ok(address) = address.parse::<Ipv6Addr>() {
            let index = match scope {
                Some(scope) => scope_index(scope)
                    .ok_or_else(|| EndpointError::UnknownScope(scope.to_owned()))?,
                // Only a link-local address has a scope to default.
                None if address.is_unicast_link_local() => defaults.scope.unwrap_or(0),
                None => 0,
            };
            return Ok(Some(SocketAddr::V6(SocketAddrV6::new(
                address,
                defaults.port,
                0,
                index,
            ))));
        }
    }
    if let Ok(address) = value.parse::<IpAddr>() {
        return Ok(Some(SocketAddr::new(address, defaults.port)));
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    const DEFAULTS: EndpointDefaults = EndpointDefaults {
        port: 3336,
        scope: Some(4),
    };

    fn parse(text: &str) -> Option<String> {
        parse_udp_endpoint(text, &DEFAULTS).unwrap().map(|address| address.to_string())
    }

    #[test]
    fn explicit_forms_parse_and_default_the_port_and_scope() {
        assert_eq!(parse("udp://[2001:db8::44]:3336").as_deref(), Some("[2001:db8::44]:3336"));
        assert_eq!(parse("192.0.2.9:1234").as_deref(), Some("192.0.2.9:1234"));
        assert_eq!(parse("192.0.2.9").as_deref(), Some("192.0.2.9:3336"));
        assert_eq!(parse("[2001:db8::1]").as_deref(), Some("[2001:db8::1]:3336"));
        // A scoped link-local address keeps its scope; an unscoped one gets the default.
        assert_eq!(parse("[fe80::1%12]:3337").as_deref(), Some("[fe80::1%12]:3337"));
        assert_eq!(parse("[fe80::1%12]").as_deref(), Some("[fe80::1%12]:3336"));
        assert_eq!(parse("[fe80::1]:3337").as_deref(), Some("[fe80::1%4]:3337"));
    }

    #[test]
    fn names_vips_and_macs_are_not_udp_endpoints() {
        assert_eq!(parse("mesh://fd00::1"), None);
        assert_eq!(parse("kitchen"), None);
        assert_eq!(parse("aa:bb:cc:dd:ee:ff"), None);
        assert_eq!(parse(""), None);
    }

    #[test]
    fn an_unknown_interface_name_is_an_error_not_a_guess() {
        assert_eq!(
            parse_udp_endpoint("[fe80::1%no-such-if0]:3337", &DEFAULTS),
            Err(EndpointError::UnknownScope("no-such-if0".to_owned()))
        );
    }
}
