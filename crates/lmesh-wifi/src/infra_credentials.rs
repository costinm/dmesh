//! Private, boot-time infrastructure STA credentials.
//!
//! DMesh radio topology is derived from the service-owned interface.  This
//! file deliberately contains only the secret material needed for an optional
//! real upstream association; it is not a general Wi-Fi configuration surface.

use anyhow::{Context, Result, bail};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{fs, path::Path};

/// Deployment secret, shared by the lmesh service that owns the selected
/// interface. Future identity key/certificate material belongs in this private
/// file rather than normal lmesh configuration.
pub const INFRA_STA_CREDENTIALS_PATH: &str = "/home/system/etc/lmesh/infra-sta.toml";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CredentialsToml {
    #[serde(default)]
    ssid: Option<String>,
    #[serde(default)]
    password: Option<String>,
    #[serde(default)]
    security: Option<String>,
    #[serde(default)]
    networks: Vec<NetworkToml>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NetworkToml {
    ssid: String,
    password: String,
    #[serde(default)]
    security: Option<String>,
    #[serde(default)]
    default_gateway: Option<String>,
    #[serde(default)]
    ipv4_address: Option<String>,
    #[serde(default)]
    #[serde(alias = "netmask")]
    ipv4_netmask: Option<String>,
    #[serde(default)]
    ipv4_prefix: Option<u8>,
    #[serde(default)]
    ipv6_address: Option<String>,
    #[serde(default)]
    ipv6_prefix: Option<u8>,
    #[serde(default)]
    ipv6_gateway: Option<String>,
}

/// Validated credentials. Do not derive `Debug`, `Serialize`, or `Clone`:
/// those conveniences make accidental secret logging too easy.
pub struct InfrastructureCredentials {
    profiles: Vec<InfrastructureProfile>,
}

pub struct InfrastructureProfile {
    ssid: String,
    password: String,
    security: InfrastructureSecurity,
    default_gateway: Option<std::net::IpAddr>,
    ipv4_address: Option<std::net::Ipv4Addr>,
    ipv4_prefix: Option<u8>,
    ipv6_address: Option<std::net::Ipv6Addr>,
    ipv6_prefix: Option<u8>,
    ipv6_gateway: Option<std::net::Ipv6Addr>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InfrastructureSecurity {
    Wpa2Psk,
    Wpa3Sae,
}

impl InfrastructureSecurity {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Wpa2Psk => "wpa2-psk",
            Self::Wpa3Sae => "wpa3-sae",
        }
    }
}

impl InfrastructureCredentials {
    pub fn ssid(&self) -> &str {
        &self.profiles[0].ssid
    }

    pub fn password(&self) -> &str {
        &self.profiles[0].password
    }

    pub fn find_by_ssid(&self, ssid: &str) -> Option<&InfrastructureProfile> {
        self.profiles.iter().find(|profile| profile.ssid == ssid)
    }

    pub fn redacted_status(&self) -> Value {
        json!({
            "configured": true,
            "networks": self.profiles.iter().map(InfrastructureProfile::redacted_status).collect::<Vec<_>>(),
        })
    }
}

impl InfrastructureProfile {
    pub fn password(&self) -> &str {
        &self.password
    }

    pub const fn security(&self) -> InfrastructureSecurity {
        self.security
    }

    fn redacted_status(&self) -> Value {
        json!({
            "ssid": self.ssid,
            "password_present": true,
            "security": self.security.as_str(),
            "default_gateway": self.default_gateway.is_some(),
            "ipv4_static": self.ipv4_address.is_some(),
            "ipv6_static": self.ipv6_address.is_some(),
        })
    }
}

/// Load the optional private infrastructure STA input.
///
/// A missing file is the ordinary no-upstream case. A present file must contain
/// a non-empty 802.11 SSID and WPA passphrase. Deployment controls access
/// permissions for now; the caller receives I/O/parse context but never a
/// rendered password.
pub fn load_infrastructure_credentials(
    path: impl AsRef<Path>,
) -> Result<Option<InfrastructureCredentials>> {
    let path = path.as_ref();
    let metadata = match fs::metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(error)
                .with_context(|| format!("read credential metadata {}", path.display()));
        }
    };
    if !metadata.is_file() {
        bail!(
            "infrastructure credential path {} is not a regular file",
            path.display()
        );
    }

    let contents = fs::read_to_string(path)
        .with_context(|| format!("read infrastructure credential file {}", path.display()))?;
    let credentials: CredentialsToml = toml::from_str(&contents)
        .with_context(|| format!("parse infrastructure credential file {}", path.display()))?;
    let networks = if credentials.networks.is_empty() {
        vec![NetworkToml {
            ssid: credentials.ssid.ok_or_else(|| {
                anyhow::anyhow!(
                    "infrastructure credential file {} has no network",
                    path.display()
                )
            })?,
            password: credentials.password.ok_or_else(|| {
                anyhow::anyhow!(
                    "infrastructure credential file {} has no password",
                    path.display()
                )
            })?,
            security: credentials.security,
            default_gateway: None,
            ipv4_address: None,
            ipv4_netmask: None,
            ipv4_prefix: None,
            ipv6_address: None,
            ipv6_prefix: None,
            ipv6_gateway: None,
        }]
    } else {
        if credentials.ssid.is_some() || credentials.password.is_some() {
            bail!(
                "infrastructure credential file {} mixes legacy and networks profiles",
                path.display()
            );
        }
        credentials.networks
    };
    let mut profiles = Vec::with_capacity(networks.len());
    let mut ssids = std::collections::HashSet::new();
    for network in networks {
        if network.ssid.is_empty()
            || network.ssid.len() > 32
            || network.ssid.contains('\0')
            || !ssids.insert(network.ssid.clone())
        {
            bail!(
                "infrastructure credential file {} has an invalid or duplicate ssid",
                path.display()
            );
        }
        if !(8..=63).contains(&network.password.len()) || network.password.contains('\0') {
            bail!(
                "infrastructure credential file {} has an invalid WPA password",
                path.display()
            );
        }
        let security = match network.security.as_deref().unwrap_or("wpa2-psk") {
            "wpa2-psk" => InfrastructureSecurity::Wpa2Psk,
            "wpa3-sae" => InfrastructureSecurity::Wpa3Sae,
            _ => bail!("infrastructure credential file {} has unsupported security", path.display()),
        };
        if network.ipv4_netmask.is_some() && network.ipv4_prefix.is_some() {
            bail!(
                "infrastructure credential file {} configures both ipv4_netmask and ipv4_prefix",
                path.display()
            );
        }
        let ipv4_address = network
            .ipv4_address
            .map(|value| value.parse())
            .transpose()
            .context("parse ipv4_address")?;
        let ipv4_prefix = match (network.ipv4_prefix, network.ipv4_netmask) {
            (Some(_), Some(_)) => bail!("ipv4_netmask and ipv4_prefix are mutually exclusive"),
            (Some(prefix), None) if prefix <= 32 => Some(prefix),
            (None, Some(mask)) => {
                Some(netmask_prefix(mask.parse().context("parse ipv4_netmask")?)?)
            }
            (Some(_), None) => bail!("ipv4_prefix exceeds 32"),
            (None, None) => None,
        };
        let ipv6_address = network
            .ipv6_address
            .map(|value| value.parse())
            .transpose()
            .context("parse ipv6_address")?;
        if network.ipv6_prefix.is_some_and(|prefix| prefix > 128) {
            bail!("ipv6_prefix exceeds 128");
        }
        let default_gateway = network
            .default_gateway
            .map(|value| value.parse())
            .transpose()
            .context("parse default_gateway")?;
        let ipv6_gateway = network
            .ipv6_gateway
            .map(|value| value.parse())
            .transpose()
            .context("parse ipv6_gateway")?;
        profiles.push(InfrastructureProfile {
            ssid: network.ssid,
            password: network.password,
            security,
            default_gateway,
            ipv4_address,
            ipv4_prefix,
            ipv6_address,
            ipv6_prefix: network.ipv6_prefix,
            ipv6_gateway,
        });
    }
    Ok(Some(InfrastructureCredentials { profiles }))
}

fn netmask_prefix(mask: std::net::Ipv4Addr) -> Result<u8> {
    let bits = u32::from(mask);
    let prefix = bits.leading_ones() as u8;
    if bits
        != if prefix == 0 {
            0
        } else {
            u32::MAX << (32 - prefix)
        }
    {
        bail!("ipv4_netmask is not contiguous");
    }
    Ok(prefix)
}

/// Load the fixed deployment path. Keep the path out of mutable service
/// configuration so the secret location has one auditable authority.
pub fn load_default_infrastructure_credentials() -> Result<Option<InfrastructureCredentials>> {
    load_infrastructure_credentials(INFRA_STA_CREDENTIALS_PATH)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn write_credentials(path: &Path, contents: &str, mode: u32) {
        fs::write(path, contents).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
        }
    }

    #[test]
    fn missing_credentials_are_optional() {
        let directory = tempfile::tempdir().unwrap();
        assert!(
            load_infrastructure_credentials(directory.path().join("missing"))
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn valid_credentials_are_redacted() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("infra.toml");
        write_credentials(
            &path,
            "ssid = \"upstream\"\npassword = \"correct-pass\"\n",
            0o600,
        );
        let credentials = load_infrastructure_credentials(&path).unwrap().unwrap();
        assert_eq!(credentials.ssid(), "upstream");
        assert_eq!(credentials.password(), "correct-pass");
        let status = credentials.redacted_status().to_string();
        assert!(status.contains("upstream"));
        assert!(!status.contains("correct-pass"));
    }

    #[test]
    fn credentials_do_not_require_a_specific_deployment_mode() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("infra.toml");
        write_credentials(
            &path,
            "ssid = \"upstream\"\npassword = \"correct-pass\"\n",
            0o644,
        );
        let credentials = load_infrastructure_credentials(&path).unwrap().unwrap();
        assert_eq!(credentials.ssid(), "upstream");
    }

    #[test]
    fn unknown_or_invalid_password_fields_are_rejected() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("infra.toml");
        write_credentials(
            &path,
            "ssid = \"upstream\"\npassword = \"short\"\nfuture_key = \"not-yet\"\n",
            0o600,
        );
        assert!(load_infrastructure_credentials(&path).is_err());
    }
}
