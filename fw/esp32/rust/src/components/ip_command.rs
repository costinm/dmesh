//! Temporary Main-owned TCP command ingress for an active STA maintenance session.
//!
//! The wire payload is the existing compact-CBOR command packet, framed as a
//! big-endian u32 length followed by the packet.  The TCP worker never touches
//! the command registry; Main serializes dispatch through `poll`.

use std::collections::VecDeque;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::atomic::{AtomicBool, AtomicU16, Ordering};
use std::sync::mpsc::{sync_channel, SyncSender};
use std::sync::{Mutex, OnceLock};
use std::thread;
use std::time::Duration;

use crate::commands::CommandRegistry;

const MAX_PACKET: usize = 4096;
const QUEUE_LIMIT: usize = 8;
/// Main may be in its normal low-power housekeeping wait when the reverse
/// connection receives a request. This must cover that cadence and the
/// bounded STA control session, not merely a LAN round-trip.
const DISPATCH_TIMEOUT: Duration = Duration::from_secs(30);

struct Pending {
    payload: Vec<u8>,
    reply: SyncSender<Vec<u8>>,
}

static RUNNING: AtomicBool = AtomicBool::new(false);
static PORT: AtomicU16 = AtomicU16::new(0);
static PENDING: OnceLock<Mutex<VecDeque<Pending>>> = OnceLock::new();

fn pending() -> &'static Mutex<VecDeque<Pending>> {
    PENDING.get_or_init(|| Mutex::new(VecDeque::new()))
}

/// Starts the reverse control connection for the current IP maintenance
/// session.  A station cannot be assumed to accept host-initiated traffic:
/// AP client isolation is common, while its outbound flash connection is
/// already proven.  Main therefore connects back to lmesh on the same host.
pub fn start(host: &str, port: u16) -> anyhow::Result<()> {
    if RUNNING.load(Ordering::Acquire) {
        if PORT.load(Ordering::Acquire) == port {
            return Ok(());
        }
        anyhow::bail!("maintenance TCP listener already active on {}", PORT.load(Ordering::Acquire));
    }
    let host = host.to_owned();
    PORT.store(port, Ordering::Release);
    RUNNING.store(true, Ordering::Release);
    thread::spawn(move || {
        while RUNNING.load(Ordering::Acquire) {
            match TcpStream::connect((host.as_str(), port)) {
                Ok(stream) => handle(stream),
                Err(_) => thread::sleep(Duration::from_millis(250)),
            }
        }
        RUNNING.store(false, Ordering::Release);
    });
    Ok(())
}

/// Ends the listener with the STA maintenance session.  The worker observes
/// this flag between nonblocking accepts, so the port can be reused by a
/// later session without leaving an IP control surface on during NAN duty.
pub fn stop() {
    RUNNING.store(false, Ordering::Release);
    PORT.store(0, Ordering::Release);
    if let Ok(mut queue) = pending().lock() {
        queue.clear();
    }
}

pub fn poll(registry: &mut CommandRegistry) {
    let request = pending().lock().ok().and_then(|mut queue| queue.pop_front());
    if let Some(request) = request {
        let response = crate::transports::dispatch_binary_packet(registry, &request.payload);
        let _ = request.reply.send(response);
    }
}

fn handle(mut stream: TcpStream) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(3)));
    let mut length = [0_u8; 4];
    if stream.read_exact(&mut length).is_err() { return; }
    let length = u32::from_be_bytes(length) as usize;
    if length == 0 || length > MAX_PACKET { return; }
    let mut payload = vec![0_u8; length];
    if stream.read_exact(&mut payload).is_err() { return; }
    let (reply, response) = sync_channel(1);
    {
        let Ok(mut queue) = pending().lock() else { return; };
        if queue.len() >= QUEUE_LIMIT { return; }
        queue.push_back(Pending { payload, reply });
    }
    let Ok(response) = response.recv_timeout(DISPATCH_TIMEOUT) else { return; };
    let Ok(length) = u32::try_from(response.len()) else { return; };
    let _ = stream.write_all(&length.to_be_bytes());
    let _ = stream.write_all(&response);
}
