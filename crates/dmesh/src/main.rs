//! DMesh — Single-node mesh launcher.
//!
//! Starts a mesh node with SSH server, HTTP server, and all available
//! features (process monitor, 9p export, SFTP, etc.).
//!
//! Usage:
//!   dmesh --base-dir /path/to/data --ssh-port 15022 --http-port 8080
//!
//! Java/Android bindings live in `java/rust/src/main/java`.

use std::env;

fn main() {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let args: Vec<String> = env::args().collect();

    let mut base_dir = env::var("SSH_BASEDIR").unwrap_or_else(|_| dirs_or_default("HOME"));
    let mut ssh_port: i32 = env::var("SSH_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(15022);
    let mut http_port: i32 = env::var("HTTP_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(8080);

    // Parse CLI args (override env vars)
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--base-dir" | "-d" => {
                i += 1;
                if i < args.len() {
                    base_dir = args[i].clone();
                }
            }
            "--ssh-port" | "-s" => {
                i += 1;
                if i < args.len() {
                    ssh_port = args[i].parse().unwrap_or(ssh_port);
                }
            }
            "--http-port" | "-h" => {
                i += 1;
                if i < args.len() {
                    http_port = args[i].parse().unwrap_or(http_port);
                }
            }
            "--help" => {
                eprintln!("Usage: dmesh [OPTIONS]");
                eprintln!();
                eprintln!("Options:");
                eprintln!(
                    "  -d, --base-dir <DIR>    Base directory (default: $SSH_BASEDIR or $HOME)"
                );
                eprintln!(
                    "  -s, --ssh-port <PORT>   SSH server port (default: $SSH_PORT or 15022)"
                );
                eprintln!(
                    "  -h, --http-port <PORT>  HTTP server port (default: $HTTP_PORT or 8080)"
                );
                eprintln!();
                eprintln!("See also:");
                eprintln!("  Java/Android: com.github.costinm.dmeshnative.MeshNode");
                std::process::exit(0);
            }
            _ => {
                eprintln!("Unknown argument: {}", args[i]);
                std::process::exit(1);
            }
        }
        i += 1;
    }

    log::info!(
        "Starting dmesh node: base_dir={}, ssh_port={}, http_port={}",
        base_dir,
        ssh_port,
        http_port
    );

    match dmesh::mesh_common::start_mesh(&base_dir, ssh_port, http_port) {
        Ok(handle) => {
            log::info!("DMesh node started successfully");
            log::info!(
                "Public key: {}",
                dmesh::mesh_common::mesh_get_public_key(&handle)
            );

            // Block until Ctrl+C
            let (tx, rx) = std::sync::mpsc::channel();
            ctrlc_or_wait(tx);
            let _ = rx.recv();

            log::info!("Shutting down...");
            dmesh::mesh_common::stop_mesh(handle);
        }
        Err(e) => {
            log::error!("Failed to start mesh node: {}", e);
            std::process::exit(1);
        }
    }
}

fn dirs_or_default(var: &str) -> String {
    env::var(var).unwrap_or_else(|_| ".".to_string())
}

fn ctrlc_or_wait(tx: std::sync::mpsc::Sender<()>) {
    // Wait for Ctrl-C or indefinitely
    std::thread::spawn(move || loop {
        std::thread::park();
    });
    // Try to install Ctrl-C handler; if that fails, just block forever
    let _ = std::thread::Builder::new()
        .name("signal".to_string())
        .spawn(move || {
            // Simple signal handling: wait for SIGINT/SIGTERM
            #[cfg(unix)]
            {
                use std::sync::atomic::{AtomicBool, Ordering};
                static STOP: AtomicBool = AtomicBool::new(false);
                unsafe {
                    libc::signal(
                        libc::SIGINT,
                        handle_signal as *const () as libc::sighandler_t,
                    );
                    libc::signal(
                        libc::SIGTERM,
                        handle_signal as *const () as libc::sighandler_t,
                    );
                }
                extern "C" fn handle_signal(_: libc::c_int) {
                    STOP.store(true, Ordering::SeqCst);
                }
                while !STOP.load(Ordering::SeqCst) {
                    std::thread::sleep(std::time::Duration::from_millis(100));
                }
                let _ = tx.send(());
            }
            #[cfg(not(unix))]
            {
                // On non-unix, just block forever
                std::thread::park();
            }
        });
}
