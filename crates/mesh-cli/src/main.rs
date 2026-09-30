//! Generic mesh command client.
//!
//! The binary intentionally has no `mesh-init` or embedded SSH implementation.
//! Explicit RPC endpoints use mesh baseline codecs over UDS, TCP, or HTTP; a
//! bare host falls back to the system OpenSSH client, while `mux://` uses the
//! shared local ControlMaster implementation.

use std::io::Write as _;
use std::os::fd::AsRawFd;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use clap::Parser;
use mesh::catalog::service_catalog_resolver;
use mesh::cbor::{decode_record, decode_stream_frame, encode_record, encode_stream_frame};
use mesh::mux_client::MuxClient;
use mesh::tagged::{TaggedCatalog, TaggedRecord, record_from_argv, to_json};
use serde_json::{Map, Value};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::time::{Duration, timeout};

#[derive(Clone, Parser, Debug)]
#[command(name = "mesh", about = "Generic mesh and SSH-compatible client")]
struct Cli {
    /// OpenSSH ControlMaster socket. Selects native mux mode.
    #[arg(short = 'S')]
    control_path: Option<PathBuf>,
    /// Local port forward, using the OpenSSH `-L` spelling.
    #[arg(short = 'L')]
    local_forward: Vec<String>,
    /// Remote port forward, using the OpenSSH `-R` spelling.
    #[arg(short = 'R')]
    remote_forward: Vec<String>,
    /// Standard input/output forward, using the OpenSSH `-W` spelling.
    #[arg(short = 'W')]
    stdio_forward: Option<String>,
    /// Request a terminal for a mux session.
    #[arg(short = 't')]
    tty: bool,
    /// Do not start a command after establishing forwards.
    #[arg(short = 'N')]
    no_command: bool,
    /// Maximum time to wait for an RPC response or streaming subscription.
    #[arg(long, default_value_t = 9)]
    timeout_sec: u64,
    /// RPC codec: auto (selected by endpoint), cbor, or json-rpc. Environment
    /// `MESH_DEST_FORMAT` supplies the same default.
    #[arg(long, value_parser = ["auto", "cbor", "json-rpc"])]
    rpc_format: Option<String>,
    /// Destination endpoint, host, service name, or URI.
    destination: String,
    /// SSH command for a host/mux endpoint, or COMPONENT METHOD arguments for
    /// an explicit RPC endpoint.
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    arguments: Vec<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DestinationFormat {
    Cbor,
    JsonRpc,
}

impl DestinationFormat {
    fn from_cli(value: Option<&str>, destination: &str, has_numeric_tags: bool) -> Result<Self> {
        let value = value.map(str::to_owned).unwrap_or_else(|| {
            std::env::var("MESH_DEST_FORMAT").unwrap_or_else(|_| "auto".to_owned())
        });
        Self::from_value(&value, destination, has_numeric_tags)
    }

    fn from_value(value: &str, destination: &str, has_numeric_tags: bool) -> Result<Self> {
        match value {
            "auto" if destination.ends_with(".cbor") && has_numeric_tags => Ok(Self::Cbor),
            "auto" if destination.ends_with(".cbor") => {
                anyhow::bail!("tagged-CBOR endpoint requires an installed schema with numeric tags")
            }
            "auto" => Ok(Self::JsonRpc),
            "cbor" if has_numeric_tags => Ok(Self::Cbor),
            "cbor" => anyhow::bail!(
                "MESH_DEST_FORMAT=cbor requires a generated catalog with numeric tags"
            ),
            "json-rpc" => Ok(Self::JsonRpc),
            "mux" => anyhow::bail!("MESH_DEST_FORMAT=mux selects a transport, not an RPC codec"),
            value => {
                anyhow::bail!("unsupported MESH_DEST_FORMAT={value}; use auto, cbor, or json-rpc")
            }
        }
    }
}

#[derive(Debug)]
enum ForwardSpec {
    Tcp {
        listen_host: String,
        listen_port: u32,
        connect_host: String,
        connect_port: u32,
    },
    Unix {
        listen_path: String,
        connect_path: String,
    },
}

fn parse_forward(value: &str, remote: bool) -> Result<ForwardSpec> {
    if value.starts_with('/')
        && let Some((listen_path, connect_path)) = value.split_once(':')
    {
        return Ok(ForwardSpec::Unix {
            listen_path: listen_path.to_owned(),
            connect_path: connect_path.to_owned(),
        });
    }
    let parts: Vec<_> = value.split(':').collect();
    let (listen_host, listen_port, connect_host, connect_port) = match parts.as_slice() {
        [port, host, target_port] => (
            if remote { "0.0.0.0" } else { "127.0.0.1" },
            port.parse()?,
            *host,
            target_port.parse()?,
        ),
        [bind, port, host, target_port] => (*bind, port.parse()?, *host, target_port.parse()?),
        _ => anyhow::bail!("invalid forward specification {value}"),
    };
    Ok(ForwardSpec::Tcp {
        listen_host: listen_host.to_owned(),
        listen_port,
        connect_host: connect_host.to_owned(),
        connect_port,
    })
}

fn is_rpc_endpoint(destination: &str) -> bool {
    destination.starts_with('/')
        || destination.starts_with("./")
        || destination.starts_with("unix://")
        || destination.starts_with("tcp://")
        || destination.starts_with("http://")
        || destination.starts_with("https://")
}

fn unix_path(destination: &str) -> Option<&str> {
    destination.strip_prefix("unix://").or_else(|| {
        (destination.starts_with('/') || destination.starts_with("./")).then_some(destination)
    })
}

fn tcp_address(destination: &str) -> Option<&str> {
    destination.strip_prefix("tcp://")
}

/// Resolve a logical service name through the common mesh-init service format.
///
/// `MESH_SERVICE_DIR` may name either one TOML file or a directory containing
/// `<service>.toml`. This is deliberately separate from the old SSH config
/// parser: the CLI only understands common `mesh::config` service definitions.
fn service_address(service: &str) -> Result<Option<String>> {
    if let Some((section, _)) = service_mesh_config(service)? {
        return Ok(Some(section.address.unwrap_or_else(|| {
            format!(
                "unix://{}",
                mesh::paths::resolve_service_socket(service).display()
            )
        })));
    }
    if let Some((endpoint, namespace)) = service.split_once('.')
        && !endpoint.is_empty()
        && !namespace.is_empty()
        && !endpoint.contains('.')
        && !namespace.contains('.')
        && endpoint
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        && namespace
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Ok(Some(format!(
            "unix:///run/mesh/{namespace}/{endpoint}.sock"
        )));
    }
    // A conventional mesh-init service without a [Mesh] section still owns
    // the standard per-service control socket.  This lets `mesh lmesh ...`
    // select the local service without conflating it with an SSH host.
    if service_config_candidates(service)
        .into_iter()
        .any(|path| path.is_file())
    {
        return Ok(Some(format!(
            "unix://{}",
            mesh::paths::resolve_service_socket(service).display()
        )));
    }
    if mesh::paths::service_socket_candidates(service)
        .into_iter()
        .any(|path| path.exists())
    {
        return Ok(Some(format!(
            "unix://{}",
            mesh::paths::resolve_service_socket(service).display()
        )));
    }
    Ok(None)
}

fn service_config_candidates(service: &str) -> Vec<PathBuf> {
    if let Some(source) = std::env::var_os("MESH_SERVICE_DIR").map(PathBuf::from) {
        return vec![if source.is_dir() {
            source.join(format!("{service}.toml"))
        } else {
            source
        }];
    }
    vec![
        PathBuf::from(format!("/home/system/etc/mesh-init/{service}.toml")),
        PathBuf::from(format!("etc/mesh-init/{service}.toml")),
    ]
}

fn service_mesh_config(service: &str) -> Result<Option<(mesh::config::MeshSection, PathBuf)>> {
    for path in service_config_candidates(service).into_iter().rev() {
        if !path.is_file() {
            continue;
        }
        let config = mesh::config::parse_service(
            &std::fs::read_to_string(&path)
                .with_context(|| format!("read service definition {}", path.display()))?,
            Some(service),
        )
        .with_context(|| format!("parse service definition {}", path.display()))?;
        if let Some(section) = config.mesh {
            return Ok(Some((section, path)));
        }
    }
    Ok(None)
}

fn print_local_help(destination: &str, command: Option<&str>) -> Result<()> {
    let mut resolved = None;
    let mut lookup_error = None;
    for component in catalog_components(destination) {
        match service_catalog_resolver().resolve(&component) {
            Some(Ok(candidate)) => {
                resolved = Some(candidate);
                break;
            }
            Some(Err(error)) => lookup_error = Some(error),
            None => continue,
        }
    }
    let resolved = resolved
        .ok_or_else(|| lookup_error.unwrap_or_else(|| anyhow::anyhow!("missing catalog")))
        .with_context(|| format!("no installed tools catalog for {destination}"))?;
    let value = resolved.tools.as_ref();
    let tools = value
        .as_array()
        .or_else(|| value.get("tools").and_then(Value::as_array))
        .context("tools catalog must be an array or contain a tools array")?;
    if let Some(command) = command {
        let tool = tools
            .iter()
            .find(|tool| tool.get("name").and_then(Value::as_str) == Some(command))
            .with_context(|| format!("unknown command {command}"))?;
        let mut stdout = std::io::stdout().lock();
        if let Err(error) = writeln!(stdout, "{}", serde_json::to_string_pretty(tool)?)
            && error.kind() != std::io::ErrorKind::BrokenPipe
        {
            return Err(error.into());
        }
        return Ok(());
    }
    let mut stdout = std::io::stdout().lock();
    for tool in tools {
        let Some(name) = tool.get("name").and_then(Value::as_str) else {
            continue;
        };
        let summary = tool
            .get("description")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .lines()
            .next()
            .unwrap_or_default();
        if let Err(error) = writeln!(stdout, "{name:<20} {summary}") {
            if error.kind() == std::io::ErrorKind::BrokenPipe {
                return Ok(());
            }
            return Err(error.into());
        }
    }
    Ok(())
}

/// Logical component candidates for a destination's tools catalog.
///
/// Catalog lookup is tied to the logical service/component name, not the
/// transport, so an installed catalog stays available after transport
/// resolution. An explicit UDS endpoint maps back to its conventional service
/// identity: a conventional `mesh.sock*` control socket names the service
/// after its directory (`/run/mesh/lmesh/mesh.sock.cbor` -> `lmesh`), while a
/// named endpoint socket `/run/mesh/<namespace>/<endpoint>.sock*` suggests
/// `<endpoint>.<namespace>` and the method component `<namespace>`. A
/// destination that is already a bare logical name is its own component; a
/// raw path itself never is, so it contributes no candidate.
fn catalog_components(destination: &str) -> Vec<String> {
    let Some(path) = unix_path(destination) else {
        return vec![destination.to_owned()];
    };
    let mut components = Vec::new();
    let path = std::path::Path::new(path);
    if let (Some(parent), Some(file)) = (path.parent(), path.file_name().and_then(|n| n.to_str()))
        && let Some(service) = parent.file_name().and_then(|n| n.to_str())
    {
        if file == "mesh.sock" || file.starts_with("mesh.sock.") {
            components.push(service.to_owned());
        } else if let Some(endpoint) = file
            .strip_suffix(".sock.cbor")
            .or_else(|| file.strip_suffix(".sock"))
        {
            components.push(format!("{endpoint}.{service}"));
            components.push(service.to_owned());
        }
    }
    components
}

/// Resolve the destination's optional tools catalog.
///
/// Derived conventional service names are tried in order; a resolver error is
/// retained only when no candidate resolves, so an explicit UDS path that maps
/// to no installed catalog keeps the documented name-based encoding.
fn catalog(destination: &str) -> Result<Option<Arc<TaggedCatalog>>> {
    let mut lookup_error = None;
    for component in catalog_components(destination) {
        match service_catalog_resolver().resolve(&component) {
            Some(Ok(resolved)) => return Ok(Some(resolved.catalog.clone())),
            Some(Err(error)) => lookup_error = Some(error),
            None => {}
        }
    }
    match lookup_error {
        Some(error) => Err(error),
        None => Ok(None),
    }
}

async fn rpc_seqpacket(
    path: &str,
    record: TaggedRecord,
    catalog: Option<&TaggedCatalog>,
) -> Result<()> {
    let socket = mesh::seqpacket::UnixSeqpacket::connect(path).await?;
    socket.send_cbor_record(&record, &[]).await?;
    let (response, fds) = socket
        .recv_cbor_record()
        .await?
        .context("tagged-CBOR endpoint closed without a response")?;
    if !fds.is_empty() {
        anyhow::bail!("unexpected file descriptors in mesh CLI response")
    }
    println!(
        "{}",
        serde_json::to_string_pretty(&to_json(&response, catalog))?
    );
    Ok(())
}

async fn rpc_http(
    destination: &str,
    record: &TaggedRecord,
    catalog: Option<&TaggedCatalog>,
) -> Result<()> {
    let response = reqwest::Client::new()
        .post(destination)
        .json(&json_rpc_request(record, catalog))
        .send()
        .await
        .with_context(|| format!("send JSON-RPC request to {destination}"))?;
    let status = response.status();
    let bytes = response.bytes().await?;
    if !status.is_success() {
        anyhow::bail!(
            "HTTP gateway returned {status}: {}",
            String::from_utf8_lossy(&bytes)
        )
    }
    let value: Value = serde_json::from_slice(&bytes).context("decode HTTP JSON response")?;
    println!("{}", serde_json::to_string_pretty(&value)?);
    Ok(())
}

async fn rpc<S>(
    stream: S,
    record: TaggedRecord,
    catalog: Option<&TaggedCatalog>,
    format: DestinationFormat,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (read, mut write) = tokio::io::split(stream);
    match format {
        DestinationFormat::JsonRpc => {
            write
                .write_all(serde_json::to_string(&json_rpc_request(&record, catalog))?.as_bytes())
                .await?;
            write.write_all(b"\n").await?;
        }
        DestinationFormat::Cbor => {
            write
                .write_all(&encode_stream_frame(&encode_record(&record)?)?)
                .await?
        }
    }
    write.flush().await?;
    let is_subscribe = record.method.text().ends_with("subscribe")
        || record.component.text().ends_with("subscribe");
    let mut reader = BufReader::new(read);

    if is_subscribe {
        let mut line = String::new();
        while reader.read_line(&mut line).await? > 0 {
            let trimmed = line.trim();
            if !trimmed.is_empty() {
                if trimmed.starts_with('{') || trimmed.starts_with('[') {
                    if let Ok(value) = serde_json::from_str::<Value>(trimmed) {
                        println!("{}", serde_json::to_string_pretty(&value)?);
                    } else {
                        println!("{trimmed}");
                    }
                } else {
                    println!("{trimmed}");
                }
            }
            line.clear();
        }
        return Ok(());
    }

    drop(write);
    let first = reader
        .fill_buf()
        .await?
        .first()
        .copied()
        .context("empty RPC response")?;
    if first == 0 {
        let mut header = [0_u8; 4];
        reader.read_exact(&mut header).await?;
        let len = u32::from_be_bytes(header) as usize;
        let mut frame = Vec::with_capacity(len + 4);
        frame.extend_from_slice(&header);
        frame.resize(len + 4, 0);
        reader.read_exact(&mut frame[4..]).await?;
        println!(
            "{}",
            serde_json::to_string_pretty(&to_json(
                &decode_record(decode_stream_frame(&frame)?)?,
                catalog
            ))?
        );
    } else {
        let mut line = String::new();
        reader.read_line(&mut line).await?;
        if line.trim_start().starts_with('{') || line.trim_start().starts_with('[') {
            let value: Value = serde_json::from_str(line.trim())?;
            println!("{}", serde_json::to_string_pretty(&value)?);
        } else {
            print!("{line}");
        }
    }
    Ok(())
}

/// The explicit JSON gateway spelling is real JSON-RPC, not the older flat
/// JSONL dialect. Its payload comes from the same tagged request as CBOR.
fn json_rpc_request(record: &TaggedRecord, catalog: Option<&TaggedCatalog>) -> Value {
    let mut flat = to_json(record, catalog);
    let object = flat
        .as_object_mut()
        .expect("tagged record JSON adapter always returns an object");
    let method = object
        .remove("method")
        .expect("tagged record JSON adapter always includes method");
    let id = object.remove("id").unwrap_or(Value::Null);
    let mut request = Map::new();
    request.insert("jsonrpc".to_owned(), Value::String("2.0".to_owned()));
    request.insert("id".to_owned(), id);
    request.insert("method".to_owned(), method);
    request.insert("params".to_owned(), Value::Object(std::mem::take(object)));
    Value::Object(request)
}

async fn rpc_destination(cli: &Cli, catalog_destination: &str) -> Result<()> {
    if !cli.local_forward.is_empty()
        || !cli.remote_forward.is_empty()
        || cli.stdio_forward.is_some()
        || cli.no_command
    {
        anyhow::bail!("SSH forwarding flags require a session/mux endpoint");
    }
    if cli.arguments.is_empty() {
        anyhow::bail!(
            "mesh does not provide a text interactive RPC mode; use a command or a manual gateway client"
        );
    }
    // Service-name resolution may already have replaced `cli.destination`
    // with a Unix address. Catalog lookup stays tied to the logical service
    // name so its installed catalog remains available after transport resolution.
    let catalog = catalog(catalog_destination)?;
    let mut record = record_from_argv(&cli.arguments, catalog.as_deref())?;
    // CLI invocations are request/reply exchanges. One-way events are emitted
    // by service code, not fabricated by a command-line client.
    record.id = Some(Value::from(1_u64));
    let format = DestinationFormat::from_cli(
        cli.rpc_format.as_deref(),
        &cli.destination,
        matches!(
            (&record.component, &record.method),
            (
                mesh::tagged::NameOrTag::Tag(_),
                mesh::tagged::NameOrTag::Tag(_)
            )
        ),
    )?;
    if cli.destination.starts_with("http://") || cli.destination.starts_with("https://") {
        if format != DestinationFormat::JsonRpc {
            anyhow::bail!("HTTP RPC currently uses JSON-RPC encoding")
        }
        timeout(
            Duration::from_secs(cli.timeout_sec),
            rpc_http(&cli.destination, &record, catalog.as_deref()),
        )
        .await
        .context("mesh HTTP RPC timed out")??;
        return Ok(());
    }
    if format == DestinationFormat::Cbor
        && let Some(path) = unix_path(&cli.destination)
        && cli.destination.ends_with(".cbor")
    {
        timeout(
            Duration::from_secs(cli.timeout_sec),
            rpc_seqpacket(path, record, catalog.as_deref()),
        )
        .await
        .context("mesh RPC timed out")??;
        return Ok(());
    }
    let stream = connect_rpc(&cli.destination).await?;
    timeout(
        Duration::from_secs(cli.timeout_sec),
        rpc(stream, record, catalog.as_deref(), format),
    )
    .await
    .context("mesh RPC timed out")??;
    Ok(())
}

async fn connect_rpc(destination: &str) -> Result<Box<dyn AsyncReadWrite>> {
    if let Some(path) = unix_path(destination) {
        return Ok(Box::new(tokio::net::UnixStream::connect(path).await?));
    }
    if let Some(address) = tcp_address(destination) {
        return Ok(Box::new(tokio::net::TcpStream::connect(address).await?));
    }
    unreachable!()
}

trait AsyncReadWrite: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T> AsyncReadWrite for T where T: AsyncRead + AsyncWrite + Unpin + Send {}

async fn mux_destination(cli: &Cli, path: PathBuf) -> Result<()> {
    let mut client = MuxClient::connect(&path).await?;
    for value in &cli.local_forward {
        match parse_forward(value, false)? {
            ForwardSpec::Tcp {
                listen_host,
                listen_port,
                connect_host,
                connect_port,
            } => {
                client
                    .open_local_forward(&listen_host, listen_port, &connect_host, connect_port)
                    .await?;
            }
            ForwardSpec::Unix {
                listen_path,
                connect_path,
            } => {
                client
                    .open_local_forward(&listen_path, u32::MAX - 1, &connect_path, u32::MAX - 1)
                    .await?;
            }
        }
    }
    for value in &cli.remote_forward {
        match parse_forward(value, true)? {
            ForwardSpec::Tcp {
                listen_host,
                listen_port,
                connect_host,
                connect_port,
            } => {
                client
                    .open_remote_forward(&listen_host, listen_port, &connect_host, connect_port)
                    .await?;
            }
            ForwardSpec::Unix {
                listen_path,
                connect_path,
            } => {
                client
                    .open_remote_forward(&listen_path, u32::MAX - 1, &connect_path, u32::MAX - 1)
                    .await?;
            }
        }
    }
    if let Some(value) = &cli.stdio_forward {
        let (host, port) = value.split_once(':').context("-W expects host:port")?;
        client.open_stdio_forward(host, port.parse()?).await?;
        return Ok(());
    }
    if cli.no_command {
        return Ok(());
    }
    let command = cli.arguments.join(" ");
    let (_, exit_code) = client
        .new_session(
            &command,
            cli.tty || command.is_empty(),
            std::io::stdin().as_raw_fd(),
            std::io::stdout().as_raw_fd(),
            std::io::stderr().as_raw_fd(),
        )
        .await?;
    std::process::exit(exit_code as i32);
}

fn external_ssh() -> Result<()> {
    let binary = std::env::var_os("MESH_SSH_COMMAND").unwrap_or_else(|| "/usr/bin/ssh".into());
    let status = std::process::Command::new(&binary)
        .args(std::env::args_os().skip(1))
        .status()
        .with_context(|| format!("run external OpenSSH {:?}", binary))?;
    std::process::exit(status.code().unwrap_or(1));
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};

    #[test]
    fn bare_named_rpc_argument_is_a_top_level_field() {
        let arguments = vec![
            "mesh-init".to_owned(),
            "stop".to_owned(),
            "name=demo".to_owned(),
        ];
        let record = record_from_argv(&arguments, None).unwrap();
        assert_eq!(
            to_json(&record, None),
            json!({"method": "mesh-init.stop", "name": "demo"})
        );
    }

    #[test]
    fn positional_rpc_argument_is_rejected_without_a_catalog() {
        let arguments = vec![
            "mesh-init".to_owned(),
            "start".to_owned(),
            "radio".to_owned(),
        ];
        assert!(record_from_argv(&arguments, None).is_err());
    }

    #[test]
    fn dotted_rpc_method_preserves_named_fields() {
        let arguments = vec![
            "esp.serial.command".to_owned(),
            "port=lora2".to_owned(),
            "command=status".to_owned(),
        ];
        let record = record_from_argv(&arguments, None).unwrap();
        assert_eq!(record.component.text(), "esp");
        assert_eq!(record.method.text(), "serial.command");
        assert_eq!(
            to_json(&record, None),
            json!({"method": "esp.serial.command", "port": "lora2", "command": "status"})
        );
    }

    #[test]
    fn dotted_rpc_method_accepts_no_parameters() {
        let arguments = vec!["usb.serial.forward.list".to_owned()];
        let record = record_from_argv(&arguments, None).unwrap();
        assert_eq!(
            to_json(&record, None),
            json!({"method": "usb.serial.forward.list"})
        );
    }

    #[test]
    fn json_rpc_gateway_uses_the_common_tagged_request() {
        let arguments = vec![
            "esp.serial.command".to_owned(),
            "port=lora3".to_owned(),
            "command=status".to_owned(),
        ];
        let mut record = record_from_argv(&arguments, None).unwrap();
        record.id = Some(json!(12));
        assert_eq!(
            json_rpc_request(&record, None),
            json!({
                "jsonrpc": "2.0",
                "id": 12,
                "method": "esp.serial.command",
                "params": {"port": "lora3", "command": "status"}
            })
        );
    }

    #[test]
    fn automatic_codec_follows_endpoint_instead_of_catalog_presence() {
        assert_eq!(
            DestinationFormat::from_value("auto", "unix:///run/mesh/demo.sock.cbor", true).unwrap(),
            DestinationFormat::Cbor
        );
        assert_eq!(
            DestinationFormat::from_value("auto", "unix:///run/mesh/demo.sock", true).unwrap(),
            DestinationFormat::JsonRpc
        );
        assert!(
            DestinationFormat::from_value("auto", "unix:///run/mesh/demo.sock.cbor", false)
                .is_err()
        );
        assert!(DestinationFormat::from_value("cbor", "unused", false).is_err());
    }

    #[test]
    fn explicit_cli_codec_overrides_environment_selection() {
        assert_eq!(
            DestinationFormat::from_cli(Some("json-rpc"), "unused", true).unwrap(),
            DestinationFormat::JsonRpc
        );
    }

    #[tokio::test]
    async fn rpc_uses_json_rpc_on_wire_without_numeric_schema() {
        let (client, server) = tokio::io::duplex(4096);
        let server_task = tokio::spawn(async move {
            let (read, mut write) = tokio::io::split(server);
            let mut line = String::new();
            BufReader::new(read).read_line(&mut line).await.unwrap();
            let request: Value = serde_json::from_str(&line).unwrap();
            assert_eq!(request["jsonrpc"], "2.0");
            assert_eq!(request["method"], "mesh.status");
            assert_eq!(request["params"]["verbose"], true);
            write
                .write_all(b"{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"ok\":true}}\n")
                .await
                .unwrap();
        });
        let record = TaggedRecord {
            component: mesh::tagged::NameOrTag::Name("mesh".to_owned()),
            method: mesh::tagged::NameOrTag::Name("status".to_owned()),
            id: Some(json!(1)),
            env: [(
                mesh::tagged::NameOrTag::Name("verbose".to_owned()),
                json!(true),
            )]
            .into_iter()
            .collect(),
            ..Default::default()
        };
        rpc(client, record, None, DestinationFormat::JsonRpc)
            .await
            .unwrap();
        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn rpc_uses_tagged_cbor_on_wire_with_numeric_schema() {
        let catalog = TaggedCatalog::from_tools_json(&json!([{
            "name": "mesh.status",
            "x-component-index": 1,
            "x-method-index": 2,
            "inputSchema": {"properties": {
                "verbose": {"x-protobuf-index": 3}
            }}
        }]))
        .unwrap();
        let mut record = catalog
            .parse_argv("mesh.status", &["verbose=true".to_owned()])
            .unwrap();
        record.id = Some(json!(1));
        let (client, mut server) = tokio::io::duplex(4096);
        let server_task = tokio::spawn(async move {
            let mut header = [0_u8; 4];
            server.read_exact(&mut header).await.unwrap();
            let mut frame = vec![0_u8; u32::from_be_bytes(header) as usize + 4];
            frame[..4].copy_from_slice(&header);
            server.read_exact(&mut frame[4..]).await.unwrap();
            let request = decode_record(decode_stream_frame(&frame).unwrap()).unwrap();
            assert_eq!(request.component, mesh::tagged::NameOrTag::Tag(1));
            assert_eq!(request.method, mesh::tagged::NameOrTag::Tag(2));
            assert_eq!(
                request.env.get(&mesh::tagged::NameOrTag::Tag(3)),
                Some(&json!(true))
            );
            server
                .write_all(
                    &encode_stream_frame(
                        &encode_record(&TaggedRecord {
                            id: Some(json!(1)),
                            result: Some(json!({"ok": true})),
                            ..Default::default()
                        })
                        .unwrap(),
                    )
                    .unwrap(),
                )
                .await
                .unwrap();
        });
        rpc(client, record, Some(&catalog), DestinationFormat::Cbor)
            .await
            .unwrap();
        server_task.await.unwrap();
    }

    #[test]
    fn explicit_socket_destinations_map_to_conventional_components() {
        // Conventional control socket: the directory owns the component.
        assert_eq!(
            catalog_components("/run/mesh/lmesh/mesh.sock.cbor"),
            ["lmesh"]
        );
        assert_eq!(
            catalog_components("unix:///run/mesh/lmesh/mesh.sock"),
            ["lmesh"]
        );
        // Named activation socket under a namespace directory.
        assert_eq!(
            catalog_components("/run/mesh/example/demo.sock.cbor"),
            ["demo.example", "example"]
        );
        // A bare logical service name is its own component candidate.
        assert_eq!(catalog_components("demo.example"), ["demo.example"]);
        // Only conventional socket names map back to components; an arbitrary
        // UDS path contributes none and keeps the name-based encoding.
        assert_eq!(
            catalog_components("/var/run/custom/gateway.socket"),
            Vec::<String>::new()
        );
    }

    #[test]
    fn explicit_socket_catalog_derives_the_service_component() {
        let dir = tempfile::tempdir().unwrap();
        let tools = json!({"tools": [{
            "name": "wifi.interface.list",
            "x-component-index": 5,
            "x-method-index": 30
        }]});
        let schema_dir = dir.path().join("lmesh");
        std::fs::create_dir_all(&schema_dir).unwrap();
        std::fs::write(
            schema_dir.join("tools.json"),
            serde_json::to_string(&tools).unwrap(),
        )
        .unwrap();
        // MESH_SCHEMA_DIR is checked before installed package locations.
        let previous = std::env::var_os("MESH_SCHEMA_DIR");
        unsafe { std::env::set_var("MESH_SCHEMA_DIR", dir.path()) };
        let resolved = catalog("/run/mesh/lmesh/mesh.sock.cbor").unwrap();
        assert!(resolved.is_some());
        match previous {
            Some(previous) => unsafe { std::env::set_var("MESH_SCHEMA_DIR", previous) },
            None => unsafe { std::env::remove_var("MESH_SCHEMA_DIR") },
        }
    }

    #[test]
    fn unconventional_socket_catalog_stays_optional() {
        let dir = tempfile::tempdir().unwrap();
        let previous = std::env::var_os("MESH_SCHEMA_DIR");
        unsafe { std::env::set_var("MESH_SCHEMA_DIR", dir.path()) };
        let resolved = catalog("/var/run/custom/gateway.socket").unwrap();
        assert!(resolved.is_none());
        match previous {
            Some(previous) => unsafe { std::env::set_var("MESH_SCHEMA_DIR", previous) },
            None => unsafe { std::env::remove_var("MESH_SCHEMA_DIR") },
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let mut cli = Cli::parse();
    let catalog_destination = cli.destination.clone();
    if !is_rpc_endpoint(&cli.destination)
        && cli.arguments.first().map(String::as_str) == Some("help")
    {
        return print_local_help(&cli.destination, cli.arguments.get(1).map(String::as_str));
    }
    if !is_rpc_endpoint(&cli.destination)
        && !cli.destination.starts_with("mux://")
        && let Some(address) = service_address(&cli.destination)?
    {
        // The logical destination selects a service endpoint.  RPC components
        // remain command arguments, so a catalog-backed call reads naturally
        // as `mesh lmesh esp serial.command ...`.
        cli.destination = address;
    }
    if is_rpc_endpoint(&cli.destination) {
        return rpc_destination(&cli, &catalog_destination).await;
    }
    if let Some(path) = cli.destination.strip_prefix("mux://") {
        return mux_destination(&cli, PathBuf::from(path)).await;
    }
    if let Some(path) = &cli.control_path {
        return mux_destination(&cli, path.clone()).await;
    }
    external_ssh()
}
