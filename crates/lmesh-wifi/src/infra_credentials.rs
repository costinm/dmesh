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
    ssid: String,
    password: String,
}

/// Validated credentials. Do not derive `Debug`, `Serialize`, or `Clone`:
/// those conveniences make accidental secret logging too easy.
pub struct InfrastructureCredentials {
    ssid: String,
    password: String,
}

impl InfrastructureCredentials {
    pub fn ssid(&self) -> &str {
        &self.ssid
    }

    pub fn password(&self) -> &str {
        &self.password
    }

    pub fn redacted_status(&self) -> Value {
        json!({
            "configured": true,
            "ssid": self.ssid,
            "password_present": true,
        })
    }
}

/// Load the optional private infrastructure STA input.
///
/// A missing file is the ordinary no-upstream case. A present file must contain
/// a non-empty 802.11 SSID and WPA passphrase. Deployment controls access
/// permissions for now; the caller receives I/O/parse context but never a
/// rendered password.
pub fn load_infrastructure_credentials(path: impl AsRef<Path>) -> Result<Option<InfrastructureCredentials>> {
    let path = path.as_ref();
    let metadata = match fs::metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error).with_context(|| format!("read credential metadata {}", path.display())),
    };
    if !metadata.is_file() {
        bail!("infrastructure credential path {} is not a regular file", path.display());
    }

    let contents = fs::read_to_string(path)
        .with_context(|| format!("read infrastructure credential file {}", path.display()))?;
    let credentials: CredentialsToml = toml::from_str(&contents)
        .with_context(|| format!("parse infrastructure credential file {}", path.display()))?;
    if credentials.ssid.is_empty() || credentials.ssid.len() > 32 || credentials.ssid.contains('\0') {
        bail!("infrastructure credential file {} has an invalid ssid", path.display());
    }
    if !(8..=63).contains(&credentials.password.len()) || credentials.password.contains('\0') {
        bail!("infrastructure credential file {} has an invalid WPA password", path.display());
    }
    Ok(Some(InfrastructureCredentials {
        ssid: credentials.ssid,
        password: credentials.password,
    }))
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
        assert!(load_infrastructure_credentials(directory.path().join("missing")).unwrap().is_none());
    }

    #[test]
    fn valid_credentials_are_redacted() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("infra.toml");
        write_credentials(&path, "ssid = \"upstream\"\npassword = \"correct-pass\"\n", 0o600);
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
        write_credentials(&path, "ssid = \"upstream\"\npassword = \"correct-pass\"\n", 0o644);
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
