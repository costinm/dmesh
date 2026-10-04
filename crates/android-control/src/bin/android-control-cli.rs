//! `android-control-cli`: host-side ADB control-plane operations.
//!
//! Subcommands:
//!   keys     — show/verify the local adbkey material
//!   pair     — Android 11+ wireless pairing (host:port + code) → stores guid
//!   connect  — `adb connect` a paired device (host:port)
//!   shell    — run a shell command on a connected device
//!   mdns     — browse `_adb-tls-pairing._tcp` / `_adb-tls-connect._tcp`
//!
//! Device identities come from arguments or the paired-device store; nothing
//! is hardcoded.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use android_control::discovery;
use android_control::keys::{default_key_dir, AdbKeys, KnownHosts};

#[derive(Parser)]
#[command(name = "android-control-cli", about = "DMesh ADB control-plane CLI")]
struct Cli {
    /// Key directory (default: $DMESH_ADB_KEY_DIR or ~/.android).
    #[arg(long, global = true)]
    key_dir: Option<PathBuf>,

    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Show local adbkey material (path, pub line prefix, cert subject).
    Keys,
    /// Wireless-pair a device (Android 11+).
    Pair {
        /// Device host (IP).
        host: String,
        /// Pairing port (`_adb-tls-pairing._tcp`).
        #[arg(short, long)]
        port: u16,
        /// Pairing code shown on the device dialog.
        #[arg(short, long)]
        code: String,
        /// Remember the paired device under this guid.
        #[arg(long)]
        guid: Option<String>,
    },
    /// Connect to a device (`adb connect` semantics) and print device banner.
    Connect {
        /// Device host.
        host: String,
        #[arg(short, long)]
        port: u16,
    },
    /// Run a shell command on a device and print output.
    Shell {
        host: String,
        #[arg(short, long)]
        port: u16,
        #[arg(required = true)]
        command: Vec<String>,
    },
    /// List paired devices from the store.
    List,
    /// Forget a paired device.
    Forget {
        guid: String,
    },
    /// Browse mDNS for ADB pairing/connect services (all by default).
    Mdns {
        #[arg(long, default_value_t = 5)]
        timeout_secs: u64,
        /// Which service type(s) to browse. `all` = pairing + connect.
        #[arg(long, value_enum, default_value_t = MdnsKind::All)]
        kind: MdnsKind,
        /// Emit a JSON array instead of one line per service.
        #[arg(long)]
        json: bool,
    },
}

#[derive(Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
enum MdnsKind {
    /// Both `_adb-tls-pairing` and `_adb-tls-connect`.
    All,
    /// Only `_adb-tls-pairing`.
    Pairing,
    /// Only `_adb-tls-connect`.
    Connect,
}

fn known_host(guid: &str, host: &str, port: Option<u16>) -> android_control::keys::KnownHost {
    android_control::keys::KnownHost {
        guid: guid.to_string(),
        host: Some(host.to_string()),
        port,
        pub_pem: None,
    }
}

fn key_dir(cli: &Cli) -> PathBuf {
    cli.key_dir
        .clone()
        .or_else(|| std::env::var_os("DMESH_ADB_KEY_DIR").map(PathBuf::from))
        .unwrap_or_else(default_key_dir)
}

fn run() -> Result<()> {
    let cli = Cli::parse();
    let dir = key_dir(&cli);
    match &cli.cmd {
        Cmd::Keys => {
            let keys = AdbKeys::load_or_create(&dir)?;
            println!("key dir:    {}", dir.display());
            println!("name:       {}", keys.name);
            println!("pub:        {}… ({} bytes b64)", &keys.pub_pem[..16.min(keys.pub_pem.len())], keys.pub_pem.len());
            println!("cert:       {} bytes PEM, {} bytes DER", keys.cert_pem.len(), keys.cert_der.len());
            Ok(())
        }
        Cmd::Pair { host, port, code, guid } => {
            let keys = AdbKeys::load_or_create(&dir)?;
            println!("pairing with {host}:{port} …");
            let res = android_control::pairing::pair_client(host, *port, code, &keys)
                .with_context(|| format!("pair {host}:{port}"))?;
            println!("paired. device guid: {}", res.guid);
            let guid = guid.clone().unwrap_or_else(|| res.guid.clone());
            let mut kh = KnownHosts::load(&dir)?;
            kh.upsert(known_host(&guid, host, Some(*port)))?;
            println!("stored as {guid}");
            Ok(())
        }
        Cmd::Connect { host, port } => {
            let keys = AdbKeys::load_or_create(&dir)?;
            let key_path = dir.join("adbkey");
            let addr: SocketAddr = format!("{host}:{port}").parse()?;
            let mut dev = android_control::adb::AdbDevice::connect(addr, &key_path)
                .with_context(|| format!("connect {addr}"))?;
            let banner = dev.shell("getprop ro.product.model").context("banner shell")?;
            println!("connected {addr}; model: {}", banner.trim());
            let _ = keys;
            Ok(())
        }
        Cmd::Shell { host, port, command } => {
            let _ = AdbKeys::load_or_create(&dir)?;
            let key_path = dir.join("adbkey");
            let addr: SocketAddr = format!("{host}:{port}").parse()?;
            let mut dev =
                android_control::adb::AdbDevice::connect(addr, &key_path)
                    .with_context(|| format!("connect {addr}"))?;
            let cmd = command.join(" ");
            let out = dev.shell(&cmd).context("shell")?;
            print!("{out}");
            if !out.ends_with('\n') {
                println!();
            }
            Ok(())
        }
        Cmd::List => {
            let kh = KnownHosts::load(&dir)?;
            if kh.entries().is_empty() {
                println!("no paired devices in {}", dir.display());
            }
            for e in kh.entries() {
                println!(
                    "{}\t{}\t{}",
                    e.guid,
                    e.host.as_deref().unwrap_or("-"),
                    e.port.map(|p| p.to_string()).unwrap_or_else(|| "-".into())
                );
            }
            Ok(())
        }
        Cmd::Forget { guid } => {
            let mut kh = KnownHosts::load(&dir)?;
            kh.remove(guid)?;
            println!("forgotten {guid}");
            Ok(())
        }
        Cmd::Mdns { timeout_secs, kind, json } => {
            let t = Duration::from_secs(*timeout_secs);
            let found = match kind {
                MdnsKind::All => discovery::browse_all(t)?,
                MdnsKind::Pairing => discovery::browse(discovery::SERVICE_PAIRING, t)?,
                MdnsKind::Connect => discovery::browse(discovery::SERVICE_CONNECT, t)?,
            };
            if *json {
                let arr: Vec<serde_json::Value> = found
                    .iter()
                    .map(|f| {
                        serde_json::json!({
                            "name": f.name,
                            "service_type": f.service_type,
                            "host": f.host,
                            "port": f.port,
                            "addr": f.addr(),
                        })
                    })
                    .collect();
                println!("{}", serde_json::to_string(&arr)?);
            } else if found.is_empty() {
                println!("no ADB services found in {timeout_secs}s");
            } else {
                for f in &found {
                    println!(
                        "{}  {}  {}",
                        f.name,
                        f.addr().unwrap_or_else(|| "?".into()),
                        f.service_type
                    );
                }
            }
            Ok(())
        }
    }
}

fn main() {
    if let Err(e) = run() {
        eprintln!("error: {e:#}");
        std::process::exit(1);
    }
}
