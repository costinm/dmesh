//! Direct wpa_supplicant UDS control.
//!
//! Managed authenticated-STA control is deliberately separate from the
//! nl80211/raw-NAN bearer. This library is not used by raw-NAN or
//! open AP or STA mode - will be used to configure regular WPA STA.

use anyhow::{Context, Result, bail};
use std::fs;
use std::io::Read;
use std::os::unix::{fs::FileTypeExt, net::UnixDatagram};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

/// One P2P group observed from the supplicant event socket.  The interface is
/// deliberately reported rather than derived: wpa_supplicant creates the
/// group VIF and drivers choose its name.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct P2pGroup {
    pub iface: String,
    pub role: P2pRole,
    pub frequency_mhz: Option<u32>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum P2pRole {
    GroupOwner,
    Client,
}

/// Attached, service-owned WPA event socket. It must be separate from the
/// command socket because control replies and asynchronous P2P events can
/// otherwise race each other.
pub struct WpaEventMonitor {
    socket: UnixDatagram,
    local_path: PathBuf,
}

impl WpaEventMonitor {
    pub fn recv(&self, timeout: Duration) -> Result<String> {
        self.socket.set_read_timeout(Some(timeout)).ok();
        let mut response = vec![0u8; 8192];
        let len = self
            .socket
            .recv(&mut response)
            .context("receive WPA event")?;
        Ok(String::from_utf8_lossy(&response[..len]).trim().to_owned())
    }
}

impl Drop for WpaEventMonitor {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.local_path);
    }
}

#[derive(Clone, Debug)]
pub struct WpaClient {
    control: PathBuf,
}

impl WpaClient {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            control: path.into(),
        }
    }
    pub fn control_path(&self) -> &Path {
        &self.control
    }

    pub fn attach_events(&self, timeout: Duration) -> Result<WpaEventMonitor> {
        let local_path = std::env::temp_dir().join(format!(
            "dmesh-wpa-events-{}-{}",
            std::process::id(),
            unique_nonce()
        ));
        let socket = UnixDatagram::bind(&local_path).context("bind WPA event socket")?;
        socket
            .connect(&self.control)
            .with_context(|| format!("connect WPA control {}", self.control.display()))?;
        socket.set_read_timeout(Some(timeout)).ok();
        socket.send(b"ATTACH").context("attach WPA event socket")?;
        let mut response = [0u8; 64];
        let len = socket
            .recv(&mut response)
            .context("receive WPA ATTACH response")?;
        if String::from_utf8_lossy(&response[..len]).trim() != "OK" {
            let _ = fs::remove_file(&local_path);
            bail!("wpa_supplicant rejected ATTACH");
        }
        Ok(WpaEventMonitor { socket, local_path })
    }

    /// Send one direct UDS command and return the textual response.  The
    /// The caller owns the managed authenticated-STA command semantics.
    pub fn command(&self, command: &str, timeout: Duration) -> Result<String> {
        if command.trim().is_empty() {
            bail!("wpa command is empty");
        }
        let socket_path = std::env::temp_dir().join(format!(
            "dmesh-wpa-{}-{}",
            std::process::id(),
            unique_nonce()
        ));
        let socket =
            UnixDatagram::bind(&socket_path).context("bind temporary WPA control socket")?;
        socket.set_read_timeout(Some(timeout)).ok();
        socket
            .connect(&self.control)
            .with_context(|| format!("connect WPA control {}", self.control.display()))?;
        socket
            .send(command.as_bytes())
            .context("send WPA command")?;
        let mut response = vec![0u8; 8192];
        let len = socket.recv(&mut response).context("receive WPA response")?;
        let _ = fs::remove_file(&socket_path);
        Ok(String::from_utf8_lossy(&response[..len]).trim().to_owned())
    }
}

/// One foreground supplicant owned by the containing service. Credentials are
/// delivered only through its local control socket, never through argv or a
/// generated configuration file.
pub struct WpaSupplicant {
    child: Child,
    control: WpaClient,
    control_dir: PathBuf,
    iface: String,
    diagnostics: std::sync::Arc<std::sync::Mutex<String>>,
}

impl WpaSupplicant {
    pub fn start(iface: &str, control_dir: impl Into<PathBuf>, timeout: Duration) -> Result<Self> {
        if iface.is_empty() || iface.as_bytes().contains(&0) {
            bail!("invalid WPA interface name");
        }
        let control_dir = control_dir.into();
        fs::create_dir_all(&control_dir)
            .with_context(|| format!("create WPA control directory {}", control_dir.display()))?;
        terminate_service_owned_supplicants(&control_dir);
        let control_path = control_dir.join(iface);
        let _ = fs::remove_file(&control_path);
        let mut child = Command::new("wpa_supplicant")
            // Some distro builds reject an invocation with no configuration
            // source before they create a transient control socket. /dev/null
            // supplies an empty, non-secret source; the network is still
            // created exclusively through ADD_NETWORK/SET_NETWORK below.
            .args(["-Dnl80211", "-i", iface, "-c", "/dev/null", "-C"])
            .arg(&control_dir)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .context("spawn wpa_supplicant")?;
        let diagnostics = std::sync::Arc::new(std::sync::Mutex::new(String::new()));
        if let Some(stdout) = child.stdout.take() {
            drain_child_output(stdout, diagnostics.clone());
        }
        if let Some(stderr) = child.stderr.take() {
            drain_child_output(stderr, diagnostics.clone());
        }
        let control = WpaClient::new(&control_path);
        let deadline = Instant::now() + timeout;
        while !control_path.exists() {
            if Instant::now() >= deadline {
                let mut child = child;
                let _ = child.kill();
                let status = child.wait().ok().and_then(|status| status.code());
                thread::sleep(Duration::from_millis(25));
                let detail = diagnostics.lock().ok().map(|text| text.clone());
                bail!(
                    "timed out waiting for WPA control socket {} (status={status:?}, output={detail:?})",
                    control_path.display()
                );
            }
            thread::sleep(Duration::from_millis(25));
        }
        let response = match control.command("PING", timeout) {
            Ok(response) => response,
            Err(error) => {
                let mut child = child;
                let _ = child.kill();
                let _ = child.wait();
                let _ = fs::remove_file(&control_path);
                return Err(error).context("PING wpa_supplicant");
            }
        };
        if response != "PONG" {
            let mut child = child;
            let _ = child.kill();
            let _ = child.wait();
            let _ = fs::remove_file(&control_path);
            let detail = diagnostics.lock().ok().map(|text| text.clone());
            bail!("wpa_supplicant PING returned {response:?} (output={detail:?})");
        }
        Ok(Self {
            child,
            control,
            control_dir,
            iface: iface.to_owned(),
            diagnostics,
        })
    }

    pub fn connect_wpa2(&self, ssid: &[u8], passphrase: &str, timeout: Duration) -> Result<()> {
        if ssid.is_empty()
            || ssid.len() > 32
            || !(8..=63).contains(&passphrase.len())
            || passphrase.contains('\0')
        {
            bail!("invalid WPA profile");
        }
        let network = self
            .command_ok("ADD_NETWORK", timeout)
            .context("WPA2 ADD_NETWORK")?;
        let id = network.parse::<u32>().context("parse WPA2 network id")?;
        self.command_ok(&format!("SET_NETWORK {id} ssid {}", hex(ssid)), timeout)
            .context("WPA2 SET_NETWORK ssid")?;
        self.command_ok(&format!("SET_NETWORK {id} key_mgmt WPA-PSK"), timeout)
            .context("WPA2 SET_NETWORK key_mgmt")?;
        self.command_ok(
            &format!("SET_NETWORK {id} psk \"{}\"", escape_wpa(passphrase)),
            timeout,
        )
        .context("WPA2 SET_NETWORK credential")?;
        self.command_ok(&format!("SELECT_NETWORK {id}"), timeout)
            .context("WPA2 SELECT_NETWORK")?;
        let deadline = Instant::now() + timeout;
        loop {
            let status = self
                .control
                .command("STATUS", Duration::from_secs(1))
                .context("WPA2 STATUS")?;
            if status.lines().any(|line| line == "wpa_state=COMPLETED") {
                return Ok(());
            }
            if Instant::now() >= deadline {
                bail!("timed out waiting for WPA association");
            }
            thread::sleep(Duration::from_millis(100));
        }
    }

    /// Connect to a WPA3-Personal SAE network.  SAE is deliberately separate
    /// from WPA2-PSK: PMF is required and callers get an explicit command
    /// failure instead of a security downgrade.
    pub fn connect_wpa3_sae(&self, ssid: &[u8], passphrase: &str, timeout: Duration) -> Result<()> {
        if ssid.is_empty()
            || ssid.len() > 32
            || !(8..=63).contains(&passphrase.len())
            || passphrase.contains('\0')
        {
            bail!("invalid WPA3 SAE profile");
        }
        let network = self
            .command_ok("ADD_NETWORK", timeout)
            .context("WPA3 ADD_NETWORK")?;
        let id = network.parse::<u32>().context("parse WPA3 network id")?;
        self.command_ok(&format!("SET_NETWORK {id} ssid {}", hex(ssid)), timeout)
            .context("WPA3 SET_NETWORK ssid")?;
        self.command_ok(&format!("SET_NETWORK {id} key_mgmt SAE"), timeout)
            .context("WPA3 SET_NETWORK key_mgmt")?;
        self.command_ok(&format!("SET_NETWORK {id} ieee80211w 2"), timeout)
            .context("WPA3 SET_NETWORK PMF")?;
        self.command_ok(&format!("SET_NETWORK {id} sae_pwe 2"), timeout)
            .context("WPA3 SET_NETWORK SAE PWE")?;
        self.command_ok(
            &format!("SET_NETWORK {id} psk \"{}\"", escape_wpa(passphrase)),
            timeout,
        )
        .context("WPA3 SET_NETWORK credential")?;
        self.command_ok(&format!("SELECT_NETWORK {id}"), timeout)
            .context("WPA3 SELECT_NETWORK")?;
        let deadline = Instant::now() + timeout;
        loop {
            let status = self
                .control
                .command("STATUS", Duration::from_secs(1))
                .context("WPA3 STATUS")?;
            if status.lines().any(|line| line == "wpa_state=COMPLETED") {
                return Ok(());
            }
            if Instant::now() >= deadline {
                bail!("timed out waiting for WPA3 SAE association");
            }
            thread::sleep(Duration::from_millis(100));
        }
    }

    pub fn iface(&self) -> &str {
        &self.iface
    }

    pub fn connected_frequency(&self, timeout: Duration) -> Result<u32> {
        let status = self.control.command("STATUS", timeout)?;
        status
            .lines()
            .find_map(|line| line.strip_prefix("freq="))
            .and_then(|value| value.parse::<u32>().ok())
            .filter(|frequency| *frequency > 0)
            .ok_or_else(|| anyhow::anyhow!("wpa_supplicant STATUS has no associated frequency"))
    }

    /// Verify that the running binary accepts P2P control commands without
    /// starting a scan or creating a group. A build without CONFIG_P2P returns
    /// its real command failure here.
    pub fn p2p_capability(&self, timeout: Duration) -> Result<()> {
        self.command_ok("P2P_STOP_FIND", timeout).map(|_| ())
    }

    /// Register a Bonjour/DNS-SD local service. The caller supplies the exact
    /// wire-format query and RDATA generated by the shared raw P2P codec.
    pub fn p2p_service_add_bonjour(
        &self,
        query_hex: &str,
        rdata_hex: &str,
        timeout: Duration,
    ) -> Result<()> {
        validate_hex(query_hex, "P2P Bonjour query")?;
        validate_hex(rdata_hex, "P2P Bonjour RDATA")?;
        self.command_ok(
            &format!("P2P_SERVICE_ADD bonjour {query_hex} {rdata_hex}"),
            timeout,
        )
        .map(|_| ())
    }

    pub fn p2p_service_flush(&self, timeout: Duration) -> Result<()> {
        self.command_ok("P2P_SERVICE_FLUSH", timeout).map(|_| ())
    }

    /// Start a bounded P2P search after service-query registration. This is
    /// intentionally explicit: callers doing passive discovery never call it.
    pub fn p2p_find(&self, timeout_secs: u8, timeout: Duration) -> Result<()> {
        if timeout_secs == 0 || timeout_secs > 120 {
            bail!("P2P find timeout must be 1 through 120 seconds");
        }
        self.command_ok(&format!("P2P_FIND {timeout_secs}"), timeout)
            .map(|_| ())
    }

    pub fn p2p_stop_find(&self, timeout: Duration) -> Result<()> {
        self.command_ok("P2P_STOP_FIND", timeout).map(|_| ())
    }

    /// Create a retained fixed-identity P2P GO profile and wait for the group
    /// event. Credentials are sent only through the local control socket.
    pub fn p2p_start_fixed_go(
        &self,
        ssid: &[u8],
        passphrase: &str,
        frequency_mhz: u32,
        timeout: Duration,
    ) -> Result<P2pGroup> {
        if ssid.is_empty()
            || ssid.len() > 32
            || !(8..=63).contains(&passphrase.len())
            || passphrase.contains('\0')
            || frequency_mhz == 0
        {
            bail!("invalid fixed P2P GO profile");
        }
        let events = self.control.attach_events(timeout)?;
        let network = self.command_ok("ADD_NETWORK", timeout)?;
        let id = network.parse::<u32>().context("parse P2P network id")?;
        self.command_ok(&format!("SET_NETWORK {id} ssid {}", hex(ssid)), timeout)?;
        self.command_ok(&format!("SET_NETWORK {id} mode 3"), timeout)?;
        self.command_ok(&format!("SET_NETWORK {id} disabled 2"), timeout)?;
        self.command_ok(&format!("SET_NETWORK {id} key_mgmt WPA-PSK"), timeout)?;
        self.command_ok(
            &format!("SET_NETWORK {id} psk \"{}\"", escape_wpa(passphrase)),
            timeout,
        )?;
        self.command_ok(
            &format!("P2P_GROUP_ADD persistent={id} freq={frequency_mhz}"),
            timeout,
        )?;
        wait_for_p2p_group(&events, timeout)
    }

    /// Start a conventional infrastructure AP with WPA2-PSK. This is AP mode
    /// (`mode=2`), not a Wi-Fi Direct group; clients see an ordinary secured
    /// SSID and do not need P2P negotiation.
    pub fn start_wpa2_ap(
        &self,
        ssid: &[u8],
        passphrase: &str,
        frequency_mhz: u32,
        timeout: Duration,
    ) -> Result<()> {
        if ssid.is_empty()
            || ssid.len() > 32
            || !(8..=63).contains(&passphrase.len())
            || passphrase.contains('\0')
            || frequency_mhz == 0
        {
            bail!("invalid WPA2 AP profile");
        }
        let events = self.control.attach_events(timeout)?;
        let network = self.command_ok("ADD_NETWORK", timeout)?;
        let id = network.parse::<u32>().context("parse WPA2 AP network id")?;
        self.command_ok(&format!("SET_NETWORK {id} ssid {}", hex(ssid)), timeout)?;
        self.command_ok(&format!("SET_NETWORK {id} mode 2"), timeout)?;
        self.command_ok(&format!("SET_NETWORK {id} key_mgmt WPA-PSK"), timeout)?;
        self.command_ok(&format!("SET_NETWORK {id} proto RSN"), timeout)?;
        self.command_ok(&format!("SET_NETWORK {id} pairwise CCMP"), timeout)?;
        self.command_ok(&format!("SET_NETWORK {id} group CCMP"), timeout)?;
        self.command_ok(
            &format!("SET_NETWORK {id} psk \"{}\"", escape_wpa(passphrase)),
            timeout,
        )?;
        self.command_ok(
            &format!("SET_NETWORK {id} frequency {frequency_mhz}"),
            timeout,
        )?;
        self.command_ok(&format!("SELECT_NETWORK {id}"), timeout)?;
        wait_for_ap_enabled(&events, timeout)
    }

    pub fn p2p_group_remove(&self, iface: &str, timeout: Duration) -> Result<()> {
        if iface.is_empty() || iface.as_bytes().contains(&0) {
            bail!("invalid P2P group interface name");
        }
        self.command_ok(&format!("P2P_GROUP_REMOVE {iface}"), timeout)
            .map(|_| ())
    }

    fn command_ok(&self, command: &str, timeout: Duration) -> Result<String> {
        let response = self.control.command(command, timeout).map_err(|error| {
            // The command text can contain a PSK. Never render it here; the
            // caller adds a fixed, non-secret phase label instead.
            let output = self
                .diagnostics
                .lock()
                .ok()
                .map(|text| redact_child_output(&text))
                .filter(|text| !text.is_empty())
                .unwrap_or_else(|| "no child output".to_owned());
            anyhow::anyhow!("{error}; wpa_supplicant output={output:?}")
        })?;
        if response == "FAIL" {
            bail!("wpa_supplicant rejected command");
        }
        Ok(response)
    }
}

fn redact_child_output(value: &str) -> String {
    let mut safe = String::new();
    for line in value.lines() {
        let lower = line.to_ascii_lowercase();
        if lower.contains("psk")
            || lower.contains("password")
            || lower.contains("passphrase")
            || lower.contains("sae_password")
        {
            continue;
        }
        if !safe.is_empty() {
            safe.push('\n');
        }
        safe.push_str(line);
    }
    safe
}

/// Previous lmesh releases could leave a P2P device child after the parent
/// process was restarted. Its socket names are driver-assigned (`p2p-dev-*`,
/// `p2p-*`), so clean every service-owned local control endpoint before
/// starting the next per-interface child. A failure is intentionally ignored:
/// stale filesystem entries are removed below and the new child still reports
/// its own real startup error.
fn terminate_service_owned_supplicants(control_dir: &Path) {
    let Ok(entries) = fs::read_dir(control_dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if fs::symlink_metadata(&path)
            .map(|metadata| metadata.file_type().is_socket())
            .unwrap_or(false)
        {
            let _ = WpaClient::new(path).command("TERMINATE", Duration::from_secs(1));
        }
    }
    thread::sleep(Duration::from_millis(50));
}

fn wait_for_p2p_group(events: &WpaEventMonitor, timeout: Duration) -> Result<P2pGroup> {
    let deadline = Instant::now() + timeout;
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            bail!("timed out waiting for P2P-GROUP-STARTED");
        }
        let event = events.recv(remaining.min(Duration::from_secs(1)))?;
        if let Some(group) = parse_p2p_group_started(&event) {
            return Ok(group);
        }
        if event.contains("P2P-GROUP-FORMATION-FAILURE") || event.contains("P2P-GO-NEG-FAILURE") {
            bail!("P2P group formation failed: {event}");
        }
    }
}

fn wait_for_ap_enabled(events: &WpaEventMonitor, timeout: Duration) -> Result<()> {
    let deadline = Instant::now() + timeout;
    loop {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .ok_or_else(|| anyhow::anyhow!("timed out waiting for AP-ENABLED"))?;
        let event = events.recv(remaining)?;
        let event = event.trim_start_matches(|character: char| {
            character == '<' || character == '>' || character.is_ascii_digit()
        });
        if event.starts_with("AP-ENABLED") {
            return Ok(());
        }
        // Network-added/selected control events precede AP-ENABLED and are
        // expected while configuring a transient profile. Only an explicit
        // AP disable means the AP state machine rejected the profile.
        if event.starts_with("AP-DISABLED") {
            bail!("WPA2 AP setup failed: {event}");
        }
    }
}

fn parse_p2p_group_started(event: &str) -> Option<P2pGroup> {
    let event = event
        .strip_prefix('<')
        .and_then(|value| value.split_once('>').map(|(_, value)| value))
        .unwrap_or(event);
    let mut parts = event.split_ascii_whitespace();
    if parts.next()? != "P2P-GROUP-STARTED" {
        return None;
    }
    let iface = parts.next()?.to_owned();
    let role = match parts.next()? {
        "GO" => P2pRole::GroupOwner,
        "client" => P2pRole::Client,
        _ => return None,
    };
    let frequency_mhz = parts.find_map(|part| {
        part.strip_prefix("freq=")
            .and_then(|value| value.parse::<u32>().ok())
    });
    Some(P2pGroup {
        iface,
        role,
        frequency_mhz,
    })
}

fn validate_hex(value: &str, name: &str) -> Result<()> {
    if value.is_empty()
        || value.len() % 2 != 0
        || !value.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        bail!("invalid {name}");
    }
    Ok(())
}

fn drain_child_output<R: Read + Send + 'static>(
    mut reader: R,
    diagnostics: std::sync::Arc<std::sync::Mutex<String>>,
) {
    thread::spawn(move || {
        let mut buffer = [0_u8; 512];
        while let Ok(read) = reader.read(&mut buffer) {
            if read == 0 {
                break;
            }
            if let Ok(mut text) = diagnostics.lock() {
                if text.len() < 4096 {
                    let available = 4096 - text.len();
                    text.push_str(
                        &String::from_utf8_lossy(&buffer[..read])
                            .chars()
                            .take(available)
                            .collect::<String>(),
                    );
                }
            }
        }
    });
}

impl Drop for WpaSupplicant {
    fn drop(&mut self) {
        let _ = self.control.command("TERMINATE", Duration::from_secs(1));
        let deadline = Instant::now() + Duration::from_secs(2);
        while Instant::now() < deadline {
            if matches!(self.child.try_wait(), Ok(Some(_))) {
                break;
            }
            thread::sleep(Duration::from_millis(25));
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = fs::remove_file(self.control_dir.join(&self.iface));
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn escape_wpa(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}

fn unique_nonce() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_go_group_event_with_priority_prefix() {
        let group = parse_p2p_group_started(
            "<3>P2P-GROUP-STARTED p2p-wlan1-0 GO ssid=4449524543542d646d657368 freq=2437",
        )
        .expect("GO group event");
        assert_eq!(group.iface, "p2p-wlan1-0");
        assert_eq!(group.role, P2pRole::GroupOwner);
        assert_eq!(group.frequency_mhz, Some(2437));
    }

    #[test]
    fn parses_client_group_event_without_priority_prefix() {
        let group = parse_p2p_group_started("P2P-GROUP-STARTED p2p0 client freq=2437")
            .expect("client group event");
        assert_eq!(group.role, P2pRole::Client);
        assert_eq!(group.frequency_mhz, Some(2437));
    }

    #[test]
    fn rejects_malformed_service_hex() {
        assert!(validate_hex("0", "query").is_err());
        assert!(validate_hex("xz", "query").is_err());
        assert!(validate_hex("aabb", "query").is_ok());
    }
}
