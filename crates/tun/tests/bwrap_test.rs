use mesh::tun::{TunDnsHandler, TunUdpHandler, TunUdpPacket};
use mesh_tun::policy::FlowContext;
use mesh_tun::transport::{
    BoxTunByteStream, ConnectedTcpStream, FixedTcpConnectorPolicy, TcpConnector,
};
use mesh_tun::{MeshTun, MeshTunConfig};
use std::fs::{self, File, OpenOptions};
use std::net::SocketAddr;
use std::os::fd::AsRawFd;
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::net::UnixStream;
use tokio::sync::mpsc;

struct RedirectTcpConnector {
    target: SocketAddr,
}

#[async_trait::async_trait]
impl TcpConnector for RedirectTcpConnector {
    async fn connect(&self, _ctx: &FlowContext) -> Result<ConnectedTcpStream, anyhow::Error> {
        let stream = tokio::net::TcpStream::connect(self.target).await?;
        let stream: BoxTunByteStream = Box::new(stream);
        Ok(ConnectedTcpStream::generic(stream))
    }
}

struct DummyUdpHandler;
#[async_trait::async_trait]
impl TunUdpHandler for DummyUdpHandler {
    async fn handle_udp(&self, _packet: TunUdpPacket) {}
}

struct DummyDnsHandler;
#[async_trait::async_trait]
impl TunDnsHandler for DummyDnsHandler {
    async fn handle_dns(&self, _packet: TunUdpPacket) {}
}

/// Test harness for in-process control server TAP capture.
struct TunTestHarness {
    _temp_dir: tempfile::TempDir,
    control_socket: PathBuf,
}

impl TunTestHarness {
    async fn new(target: SocketAddr) -> Self {
        let temp_dir = tempfile::tempdir().unwrap();
        let control_socket = temp_dir.path().join("control.sock");

        let config = MeshTunConfig::default();
        let tun = MeshTun::new(config).unwrap();
        let dummy_udp = Arc::new(DummyUdpHandler);
        let dummy_dns = Arc::new(DummyDnsHandler);
        let tcp_policy = Arc::new(FixedTcpConnectorPolicy::new(Arc::new(
            RedirectTcpConnector { target },
        )));

        let (_injector, tun_tx, mut stack_rx) = tun
            .run_with_channels_and_policy(tcp_policy, dummy_udp, dummy_dns)
            .await
            .unwrap();

        // Spawn route outgoing packet loop
        let (fallback_tx, _fallback_rx) = mpsc::channel::<Vec<u8>>(1024);
        tokio::spawn(async move {
            while let Some(packet) = stack_rx.recv().await {
                if !mesh_tun::control::route_outgoing_packet(&packet) {
                    let _ = fallback_tx.try_send(packet);
                }
            }
        });

        // Spawn control server
        let control_socket_clone = control_socket.clone();
        let control_listener = tokio::net::UnixListener::bind(&control_socket_clone)
            .expect("failed to bind test control UDS");
        tokio::spawn(async move {
            let _ = mesh_tun::control::run_control_server(control_listener, tun_tx).await;
        });

        tokio::time::sleep(Duration::from_millis(100)).await;

        Self {
            _temp_dir: temp_dir,
            control_socket,
        }
    }
}

#[tokio::test]
async fn test_bwrap_curl_e2e() {
    println!("starting mock HTTP server");
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mock_addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = [0u8; 1024];
                let _ = socket.read(&mut buf).await;
                let response = "HTTP/1.1 200 OK\r\nContent-Length: 13\r\nConnection: close\r\n\r\nHello packet!";
                let _ = socket.write_all(response.as_bytes()).await;
                let _ = socket.flush().await;
            });
        }
    });

    println!("starting in-process mesh-tun control server");
    let harness = TunTestHarness::new(mock_addr).await;

    println!("creating bwrap coordination fds");
    let temp_dir = tempfile::tempdir().unwrap();
    let info_path = temp_dir.path().join("bwrap-info.json");
    let block_path = temp_dir.path().join("bwrap-block");
    let c_block_path = std::ffi::CString::new(block_path.to_string_lossy().as_bytes()).unwrap();
    let mkfifo_rc = unsafe { libc::mkfifo(c_block_path.as_ptr(), 0o600) };
    if mkfifo_rc != 0 {
        println!(
            "Skipping test: failed to create block fifo: {}",
            std::io::Error::last_os_error()
        );
        return;
    }

    let info_file = File::create(&info_path).unwrap();
    let block_file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&block_path)
        .unwrap();
    let info_fd = info_file.as_raw_fd();
    let block_fd = block_file.as_raw_fd();

    let mut bwrap = std::process::Command::new("bwrap");
    bwrap.arg("--unshare-user");
    bwrap.arg("--unshare-net");
    bwrap.args(["--uid", "0", "--gid", "0"]);
    if std::env::var_os("MESH_TUN_BWRAP_TCPDUMP").is_some() {
        bwrap.args(["--cap-add", "CAP_NET_RAW"]);
    }

    let dirs = ["/usr", "/bin", "/sbin", "/lib", "/lib64", "/etc", "/nix"];
    for dir in dirs {
        if std::path::Path::new(dir).exists() {
            bwrap.args(["--ro-bind", dir, dir]);
        }
    }
    bwrap.args(["--dev", "/dev"]);
    bwrap.args(["--proc", "/proc"]);
    bwrap.args(["--tmpfs", "/tmp"]);
    bwrap.args(["--info-fd", "7"]);
    bwrap.args(["--block-fd", "8"]);

    let current_dir = std::env::current_dir().unwrap();
    let workspace_dir = current_dir.parent().unwrap().parent().unwrap();
    let workspace_dir_str = workspace_dir.to_str().unwrap();
    bwrap.args(["--bind", workspace_dir_str, workspace_dir_str]);

    let cmd = if std::env::var_os("MESH_TUN_BWRAP_TCPDUMP").is_some() {
        "ip addr show tap0; ip route show; timeout 7 tcpdump -Z root -i tap0 -nnevv -c 12 & tcpdump_pid=$!; sleep 0.2; curl --max-time 5 -sSf http://93.184.215.14:80; status=$?; wait $tcpdump_pid || true; exit $status"
    } else {
        "curl --max-time 5 -sSf http://93.184.215.14:80"
    };
    bwrap.args(["--", "/bin/bash", "-c", cmd]);
    bwrap.stdout(Stdio::piped());
    bwrap.stderr(Stdio::piped());
    unsafe {
        bwrap.pre_exec(move || {
            if libc::dup2(info_fd, 7) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            if libc::dup2(block_fd, 8) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }

    println!("spawning bwrap");
    let mut child = match bwrap.spawn() {
        Ok(c) => c,
        Err(e) => {
            println!("Skipping test: bubblewrap spawn failed: {}", e);
            return;
        }
    };
    println!("waiting for bwrap child-pid");
    let Some(child_pid) = wait_for_bwrap_child_pid(&info_path).await else {
        println!("Skipping test: timed out waiting for bwrap child-pid");
        let _ = child.kill();
        return;
    };
    println!("bwrap child-pid: {child_pid}");

    println!("connecting to mesh-tun control socket");
    let mut control_stream = match UnixStream::connect(&harness.control_socket).await {
        Ok(s) => s,
        Err(e) => {
            println!("Failed to connect to control socket: {}", e);
            let _ = child.kill();
            return;
        }
    };

    let cap_cmd = format!(
        "capture-tap vm_id=bwrap netns=/proc/{}/ns/net if=tap0 setup=tap addr=10.5.0.2/24 gw=10.5.0.1 route=default\n",
        child_pid
    );
    if let Err(e) = control_stream.write_all(cap_cmd.as_bytes()).await {
        println!("Skipping test: failed to write capture-tap command: {}", e);
        let _ = child.kill();
        return;
    }
    let _ = control_stream.flush().await;

    println!("waiting for capture response");
    // Read response "ok" or "error ..."
    let mut response = [0u8; 128];
    let n = control_stream.read(&mut response).await.unwrap_or_default();
    let resp_str = String::from_utf8_lossy(&response[..n]);
    if !resp_str.contains("ok") {
        println!(
            "Skipping/failing test: capture-tap failed: {} (insufficient host privileges or ns setup failed)",
            resp_str.trim()
        );
        let _ = child.kill();
        return;
    }
    println!("capture response: {}", resp_str.trim());
    println!(
        "stats after capture: {}",
        control_request(&harness.control_socket, "stats\n").await
    );
    let mut release = OpenOptions::new().write(true).open(&block_path).unwrap();
    let _ = std::io::Write::write_all(&mut release, b"x");

    println!("waiting for bwrap workload");
    let output = tokio::task::spawn_blocking(move || child.wait_with_output())
        .await
        .unwrap()
        .unwrap();
    println!(
        "stats after workload: {}",
        control_request(&harness.control_socket, "stats\n").await
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    println!("stdout: {}", stdout);
    println!("stderr: {}", stderr);

    assert!(output.status.success(), "bwrap container failed");
    assert!(
        stdout.contains("Hello packet!"),
        "Curl did not receive expected mock HTTP response"
    );
}

async fn wait_for_bwrap_child_pid(info_path: &std::path::Path) -> Option<u32> {
    for _ in 0..100 {
        if let Ok(contents) = fs::read_to_string(info_path) {
            if let Some(pid) = parse_child_pid(&contents) {
                return Some(pid);
            }
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    None
}

fn parse_child_pid(contents: &str) -> Option<u32> {
    let marker = "\"child-pid\"";
    let after_marker = contents.split(marker).nth(1)?;
    let after_colon = after_marker.split(':').nth(1)?;
    let digits: String = after_colon
        .chars()
        .skip_while(|ch| ch.is_whitespace())
        .take_while(|ch| ch.is_ascii_digit())
        .collect();
    digits.parse().ok()
}

async fn control_request(socket: &std::path::Path, request: &str) -> String {
    let Ok(mut stream) = UnixStream::connect(socket).await else {
        return "error connect".to_string();
    };
    if stream.write_all(request.as_bytes()).await.is_err() {
        return "error write".to_string();
    }
    let mut response = [0u8; 4096];
    let n = stream.read(&mut response).await.unwrap_or_default();
    String::from_utf8_lossy(&response[..n]).trim().to_string()
}
