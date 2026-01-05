/// dmesh is a binary intended for Android as a shell command or system service.
/// It should be packaged in an apex - or manually copied on a dev phone.
/// 
use log::{info, error};
use dmesh::mesh::http::{get_port_from_env, H2Server};
use clap::Parser;
use std::process;
use std::sync::Arc;
use dmesh::echo_service;
use dmesh::pmon;
use dmesh::lmesh::LocalDiscovery;
use ctrlc;
use dmesh::pmon::proc::ProcMon;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
enum Command {
    /// Run the mesh server (SSH and HTTP)
    Mesh,
    /// Run the UDS echo server
    Uds {
        /// Socket path for the UDS server
        #[arg(short, long, default_value = "/tmp/uds_echo.socket")]
        socket: std::path::PathBuf,
        
        /// Buffer size for read/write operations
        #[arg(short, long, default_value_t = 4096)]
        buffer_size: usize,
    },
    /// Run the UDS echo client
    UdsClient {
        /// Socket path for the UDS server
        #[arg(short, long, default_value = "/tmp/uds_echo.socket")]
        socket: std::path::PathBuf,
        
        /// Number of iterations for benchmarking
        #[arg(short, long, default_value_t = 100)]
        iterations: usize,
        
        /// Message size for benchmarking
        #[arg(short, long, default_value_t = 100)]
        message_size: usize,
        
        /// Run in benchmark mode
        #[arg(short, long, default_value_t = false)]
        benchmark: bool,
    },
    /// Run the PMON process monitor
    Pmon {
        /// Monitoring interval in seconds
        #[arg(short, long, default_value_t = 5)]
        interval: u64,
        
        /// Timeout in seconds (0 for no timeout)
        #[arg(short, long, default_value_t = 0)]
        timeout: u64,
        
        /// Processes to monitor
        #[arg(short, long, value_delimiter = ',')]
        processes: Vec<String>,
        
        /// Verbose output
        #[arg(short, long, default_value_t = false)]
        verbose: bool,
    },
    /// List existing processes
    Ps,
    /// List existing processes and watch PSI
    PsWatch,
}

/// Main mesh server. Will listen on SSH and HTTP ports and provide
/// basic functionality.
///
///
#[tokio::main]
async fn main() {
    env_logger::init();

    let command = Command::parse();
    
    match command {
        Command::Mesh => {
            // Initialize the logger

            // Get port numbers from environment variables or use defaults
            let http_port = get_port_from_env("HTTP_PORT", 5228);

            // Create and start ProcMon
            let proc_mon = match ProcMon::new() {
                Ok(pm) => Arc::new(pm),
                Err(e) => {
                    error!("Failed to create ProcMon: {}", e);
                    process::exit(1);
                }
            };
            
            // Set callback for new processes
            proc_mon.set_callback(|p: pmon::proc::ProcessInfo| {
                info!("New process: pid={}, ppid={}, comm={}", p.pid, p.ppid, p.comm);
            });
            
            // Start ProcMon monitoring
            if let Err(e) = proc_mon.listen(true) {
                error!("Failed to enable ProcMon listening: {}", e);
            }
            
            // if let Err(e) = proc_mon.start(true, false) {
            //     error!("Failed to start ProcMon: {}", e);
            // }
            
        
            // Create and start LocalDiscovery service
            let mut local_discovery = match LocalDiscovery::new(None).await {
                Ok(ld) => ld,
                Err(e) => {
                    error!("Failed to create LocalDiscovery: {}", e);
                    process::exit(1);
                }
            };

            info!("LocalDiscovery created with public key: {}", local_discovery.public_key_b64());

            // Start LocalDiscovery in a separate task
            if let Err(e) = local_discovery.start().await {
                error!("Failed to start LocalDiscovery: {}", e);
                process::exit(1);
            }

            // Spawn a task to periodically announce
            tokio::spawn(async move {
                loop {
                    tokio::time::sleep(tokio::time::Duration::from_secs(10)).await;
                    if let Err(e) = local_discovery.announce().await {
                        error!("Failed to send announcement: {}", e);
                    } else {
                        info!("Sent discovery announcement");
                    }
                }
            });

            // Get base directory from environment or use home directory as default
            let base_dir = std::env::var("HOME")
                .map(std::path::PathBuf::from)
                .unwrap_or_else(|_| std::path::PathBuf::from("/tmp"));


            // Create H2Server and register the /_ps handler
            let mut h2_server = H2Server::new(http_port, base_dir);
            
            // Register the /_ps handler
            let proc_mon_clone = Arc::clone(&proc_mon);
            h2_server.add_handler(
                "/_ps".to_string(),
                Arc::new(move |req| {
                    let proc_mon = Arc::clone(&proc_mon_clone);
                    Box::pin(pmon::lib::handle_ps_request(req, proc_mon))
                })
            );

            println!("Starting servers...");

            // Run both servers concurrently
            tokio::select! {
                http_result = h2_server.run() => {
                    if let Err(e) = http_result {
                        error!("HTTP/2 server failed: {}", e);
                    }
                }
            }
        },
        Command::Uds { socket, buffer_size } => {
            // Run UDS echo server
            let args = echo_service::uds::Args {
                socket,
                buffer_size,
            };
            if let Err(e) = echo_service::uds::run_server(args) {
                eprintln!("UDS server failed: {}", e);
                process::exit(1);
            }
        },
        Command::UdsClient { socket, iterations, message_size, benchmark } => {
            // Run UDS echo client
            let args = echo_service::uds_client::Args {
                socket,
                iterations,
                message_size,
                benchmark,
            };
            if let Err(e) = echo_service::uds_client::run_client(&args) {
                eprintln!("UDS client failed: {}", e);
                process::exit(1);
            }
        },
        Command::Pmon { interval, timeout, processes, verbose } => {
            // Run PMON process monitor
            // Set up Ctrl-C handler
            let running = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));
            let running_clone = running.clone();
            
            ctrlc::set_handler(move || {
                println!("Received Ctrl-C, shutting down...");
                running_clone.store(false, std::sync::atomic::Ordering::SeqCst);
                process::exit(0);
            }).expect("Error setting Ctrl-C handler");
            
            // Run PMON process monitor
            if let Err(e) = pmon::lib::pmon_main(interval, timeout, processes, verbose).await {
                eprintln!("PMON failed: {}", e);
                process::exit(1);
            }
            
            // Block the main thread until exit
            loop {
                // Sleep to avoid busy waiting
                tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
                // Check if we should exit (though Ctrl-C handler will exit directly)
                if !running.load(std::sync::atomic::Ordering::SeqCst) {
                    break;
                }
            }
        }
        Command::Ps => {
            // Create a new ProcMon instance
            let proc_mon = ProcMon::new().expect("Failed to create ProcMon");
            
            // Read existing processes
            proc_mon.read_existing_processes(false);
            
            // Print all processes
            let processes = proc_mon.get_all_processes();
            println!("PID\tPPID\tCOMM");
            for (pid, process_info) in processes.iter() {
                println!("{}\t{}\t{}", pid, process_info.ppid, process_info.comm);
            }
        }
        Command::PsWatch => {
            // Create a new ProcMon instance
            let proc_mon = ProcMon::new().expect("Failed to create ProcMon");
            
            // Read existing processes and start PSI watching
            proc_mon.read_existing_processes(true);
            
            // Print all processes
            let processes = proc_mon.get_all_processes();
            println!("PID\tPPID\tCOMM\tCGROUP");
            for (pid, process_info) in processes.iter() {
                let cgroup = process_info.cgroup_path.as_ref().map(|s| s.as_str()).unwrap_or("None");
                println!("{}\t{}\t{}\t{}", pid, process_info.ppid, process_info.comm, cgroup);
            }
            
            println!("Monitoring PSI pressure events. Press Ctrl+C to stop.");
            
            // Set up Ctrl-C handler
            let running = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));
            let running_clone = running.clone();
            
            ctrlc::set_handler(move || {
                println!("Received Ctrl-C, shutting down...");
                running_clone.store(false, std::sync::atomic::Ordering::SeqCst);
                process::exit(0);
            }).expect("Error setting Ctrl-C handler");
            
            // Keep the main thread alive while monitoring
            while running.load(std::sync::atomic::Ordering::SeqCst) {
                std::thread::sleep(std::time::Duration::from_secs(1));
            }
        }
    }
}
