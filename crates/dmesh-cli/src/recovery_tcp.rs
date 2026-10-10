//! Recovery2 v1: an exact-length TCP upload and a terminal response plus FIN.
use std::{
    io::{Read, Write},
    net::{Ipv6Addr, SocketAddr, SocketAddrV6, TcpStream, UdpSocket},
    time::{Duration, Instant},
};

pub(crate) const PORT: u16 = 3340;
#[derive(Debug, PartialEq)]
pub(crate) enum Reply {
    Progress(u32, u32),
    Ok { length: u32, dry: bool },
    Error(String),
}
pub(crate) fn encode_header(target: u8, dry: bool, length: u32) -> [u8; 16] {
    let mut h = [0; 16];
    h[..4].copy_from_slice(b"DMR2");
    h[4] = 1;
    h[5] = if dry { 2 } else { 0 };
    h[6] = target;
    h[8..12].copy_from_slice(&length.to_le_bytes());
    h
}
pub(crate) fn parse_line(line: &str) -> Result<Reply, String> {
    let mut words = line.split_whitespace();
    let number = |s: Option<&str>| {
        s.and_then(|s| s.parse::<u32>().ok())
            .ok_or("invalid Recovery2 counter".to_owned())
    };
    match words.next() {
        Some("P") => {
            let a = number(words.next())?;
            let b = number(words.next())?;
            if words.next().is_some() || b > a {
                return Err("invalid progress".into());
            }
            Ok(Reply::Progress(a, b))
        }
        Some("OK") => {
            let length = number(words.next())?;
            let mut dry = false;
            for word in words {
                if word == "dry" {
                    dry = true
                } else if !word.contains('=') {
                    return Err("invalid terminal response".into());
                }
            }
            Ok(Reply::Ok { length, dry })
        }
        Some("ERR") => Ok(Reply::Error(line.trim().to_owned())),
        _ => Err("unknown Recovery2 response".into()),
    }
}
pub(crate) fn validate_image(image: &[u8], cpu: u8) -> Result<(), String> {
    let chip = match cpu {
        0 => 0,
        9 => 9,
        13 => 13,
        _ => return Err("unknown image CPU".into()),
    };
    if image.len() < 4096
        || image.len() > 0x2b0000
        || image[0] != 0xe9
        || u16::from_le_bytes([image[12], image[13]]) != chip
    {
        return Err("Recovery2 image size/magic/chip mismatch".into());
    }
    Ok(())
}
pub(crate) fn tcp_address(peer: SocketAddr) -> SocketAddr {
    let mut peer = peer;
    peer.set_port(PORT);
    peer
}
pub(crate) fn wait_beacon(
    expected: SocketAddr,
    timeout: Duration,
) -> Result<(SocketAddr, u8), String> {
    let SocketAddr::V6(expected) = expected else {
        return Err("Recovery2 discovery requires scoped IPv6".into());
    };
    let socket = UdpSocket::bind((Ipv6Addr::UNSPECIFIED, PORT))
        .map_err(|e| format!("Recovery2 beacon bind: {e}"))?;
    let group = "ff02::5227".parse::<Ipv6Addr>().unwrap();
    socket
        .join_multicast_v6(&group, expected.scope_id())
        .map_err(|e| format!("Recovery2 beacon join: {e}"))?;
    socket
        .set_read_timeout(Some(Duration::from_millis(250)))
        .map_err(|e| e.to_string())?;
    let deadline = Instant::now() + timeout;
    let mut bytes = [0; 256];
    while Instant::now() < deadline {
        if let Ok((n, SocketAddr::V6(source))) = socket.recv_from(&mut bytes) {
            if source.ip() == expected.ip()
                && source.scope_id() == expected.scope_id()
                && source.port() == PORT
            {
                if let Ok(cpu) = parse_beacon(&bytes[..n]) {
                    return Ok((
                        SocketAddr::V6(SocketAddrV6::new(*source.ip(), PORT, 0, source.scope_id())),
                        cpu,
                    ));
                }
            }
        }
    }
    Err("Recovery2 beacon timeout".into())
}
fn parse_beacon(bytes: &[u8]) -> Result<u8, String> {
    let text = std::str::from_utf8(bytes).map_err(|e| e.to_string())?;
    if bytes.len() > 200
        || text.split_whitespace().next() != Some("dmesh-recovery2")
        || !text.split_whitespace().any(|s| s == "v=1")
        || !text.split_whitespace().any(|s| s == "port=3340")
    {
        return Err("invalid Recovery2 beacon".into());
    }
    text.split_whitespace()
        .find_map(|s| match s {
            "chip=esp32" => Some(0),
            "chip=esp32s3" => Some(9),
            "chip=esp32c6" => Some(13),
            _ => None,
        })
        .ok_or("missing Recovery2 chip".into())
}
fn pacing_bytes_per_second(mbps: &str) -> Result<libc::c_ulong, String> {
    mbps.parse::<u64>().ok().filter(|n| *n > 0)
        .and_then(|n| n.checked_mul(125_000))
        .and_then(|n| libc::c_ulong::try_from(n).ok())
        .ok_or_else(|| "DMESH_RECOVERY2_PACING_MBPS must be a positive integer Mbps rate that fits the socket option".into())
}
fn tune_socket(stream: &TcpStream) -> Result<(), String> {
    let pacing = std::env::var("DMESH_RECOVERY2_PACING_MBPS").ok();
    let congestion = std::env::var("DMESH_RECOVERY2_CONGESTION").ok();
    if pacing.is_none() && congestion.is_none() { return Ok(()); }
    #[cfg(target_os = "linux")]
    {
        use std::os::fd::AsRawFd;
        let set = |level, option, value: *const libc::c_void, length| {
            // Only synchronous copies of live scalar/C-string storage.
            if unsafe { libc::setsockopt(stream.as_raw_fd(), level, option, value, length) } == 0 {
                Ok(())
            } else { Err(std::io::Error::last_os_error().to_string()) }
        };
        if let Some(ref mbps) = pacing {
            let rate = pacing_bytes_per_second(mbps)?;
            set(libc::SOL_SOCKET, libc::SO_MAX_PACING_RATE, (&rate as *const libc::c_ulong).cast(),
                std::mem::size_of_val(&rate) as libc::socklen_t)
                .map_err(|e| format!("Recovery2 SO_MAX_PACING_RATE: {e}"))?;
        }
        if let Some(ref name) = congestion {
            let name = std::ffi::CString::new(name.as_str()).map_err(|_| "invalid TCP congestion algorithm")?;
            set(libc::IPPROTO_TCP, libc::TCP_CONGESTION, name.as_ptr().cast(),
                name.as_bytes_with_nul().len() as libc::socklen_t)
                .map_err(|e| format!("Recovery2 TCP_CONGESTION: {e}"))?;
        }
        println!("recovery_tcp tuning pacing_mbps={} congestion={}",
            pacing.as_deref().unwrap_or("default"), congestion.as_deref().unwrap_or("default"));
        Ok(())
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = stream;
        Err("Recovery2 TCP tuning is supported only on Linux".into())
    }
}
fn exchange(peer: SocketAddr, image: &[u8], target: u8, dry: bool) -> Result<(), String> {
    let timeout = Duration::from_secs(
        std::env::var("DMESH_RECOVERY2_TIMEOUT_SECS")
            .ok()
            .and_then(|s| s.parse().ok())
            .filter(|n| *n > 0)
            .unwrap_or(90),
    );
    let started = Instant::now();
    let deadline = started + timeout;
    let mut stream = TcpStream::connect_timeout(&peer, Duration::from_secs(10))
        .map_err(|e| format!("Recovery2 TCP connect: {e}"))?;
    tune_socket(&stream)?;
    stream
        .set_write_timeout(Some(Duration::from_secs(10)))
        .map_err(|e| e.to_string())?;
    let mut reader = stream.try_clone().map_err(|e| e.to_string())?;
    let length = u32::try_from(image.len()).map_err(|e| e.to_string())?;
    std::thread::scope(|scope| {
        let receive = scope.spawn(move || -> Result<(), String> {
            let result = (|| {
                let mut line = Vec::new();
                let mut terminal = false;
                loop {
                    let remaining = deadline
                        .checked_duration_since(Instant::now())
                        .filter(|d| !d.is_zero())
                        .ok_or("Recovery2 response deadline")?;
                    reader
                        .set_read_timeout(Some(remaining))
                        .map_err(|e| e.to_string())?;
                    let mut byte = [0];
                    let n = reader.read(&mut byte).map_err(|e| e.to_string())?;
                    if n == 0 {
                        return if terminal && line.is_empty() {
                            Ok(())
                        } else {
                            Err("Recovery2 EOF without terminal response".into())
                        };
                    };
                    if terminal {
                        return Err("data after Recovery2 terminal response".into());
                    }
                    if byte[0] != b'\n' {
                        line.push(byte[0]);
                        if line.len() > 256 {
                            return Err("Recovery2 response too long".into());
                        }
                        continue;
                    }
                    let text = std::str::from_utf8(&line).map_err(|e| e.to_string())?;
                    println!("recovery_tcp {text}");
                    match parse_line(text)? {
                        Reply::Progress(received, _) if received <= length => {}
                        Reply::Progress(..) => {
                            return Err("Recovery2 progress exceeds length".into());
                        }
                        Reply::Ok { length: n, dry: d } if n == length && d == dry => {
                            terminal = true
                        }
                        Reply::Ok { .. } => {
                            return Err("Recovery2 terminal length/dry mismatch".into());
                        }
                        Reply::Error(e) => return Err(e),
                    }
                    line.clear();
                }
            })();
            if result.is_err() {
                let _ = reader.shutdown(std::net::Shutdown::Both);
            }
            result
        });
        let write = (|| -> std::io::Result<()> {
            stream.write_all(&encode_header(target, dry, length))?;
            stream.write_all(image)?;
            stream.shutdown(std::net::Shutdown::Write)
        })();
        if write.is_err() {
            let _ = stream.shutdown(std::net::Shutdown::Both);
        }
        let result = receive.join().map_err(|_| "Recovery2 reader panicked")?;
        write.map_err(|e| e.to_string())?;
        result
    })?;
    println!(
        "dmesh_flash_timing stage=recovery_tcp bytes={} host_ms={} mbps={:.3} dry={dry}",
        image.len(),
        started.elapsed().as_millis(),
        image.len() as f64 * 8.0 / started.elapsed().as_secs_f64() / 1e6
    );
    Ok(())
}
pub(crate) fn upload(peer: SocketAddr, image: &[u8], cpu: u8, dry: bool) -> Result<(), String> {
    validate_image(image, cpu)?;
    crate::flash_log::image("recovery2_tcp", None, image);
    let started = Instant::now();
    let result = exchange(tcp_address(peer), image, 0, dry);
    crate::flash_log::transfer(started.elapsed(), result.is_ok());
    result
}
pub(crate) fn reboot(peer: SocketAddr) -> Result<(), String> {
    exchange(tcp_address(peer), &[], 255, false)
}

#[cfg(test)]
mod tests {
    #[test]
    fn pacing_rate_units_and_validation() {
        assert_eq!(super::pacing_bytes_per_second("4").unwrap(), 500_000);
        assert_eq!(super::pacing_bytes_per_second("8").unwrap(), 1_000_000);
        for value in ["0", "-1", "NaN", "4.5", "18446744073709551615"] {
            assert!(super::pacing_bytes_per_second(value).is_err());
        }
    }
    use super::*;
    #[test]
    fn image_header_checks_do_not_hash_payload() {
        let mut image = vec![0; 4096];
        image[0] = 0xe9;
        image[12] = 13;
        assert!(validate_image(&image, 13).is_ok());
        assert!(validate_image(&image, 9).is_err());
        assert!(validate_image(&image[..4095], 13).is_err());
        image[3000] ^= 0xff;
        assert!(validate_image(&image, 13).is_ok());
    }
    #[test]
    fn loopback_rejects_wrong_length_error_and_trailing_data() {
        for response in [
            b"OK 4095 dry\n".as_slice(),
            b"ERR 6 truncated\n",
            b"OK 4096 dry\nextra",
        ] {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let addr = listener.local_addr().unwrap();
            let server = std::thread::spawn(move || {
                let (mut stream, _) = listener.accept().unwrap();
                let mut input = Vec::new();
                stream.read_to_end(&mut input).unwrap();
                stream.write_all(response).unwrap();
            });
            assert!(exchange(addr, &[0; 4096], 0, true).is_err());
            server.join().unwrap();
        }
    }
    #[test]
    fn header_and_lines() {
        assert_eq!(
            &encode_header(0, true, 0x12345678)[..12],
            b"DMR2\x01\x02\x00\x00\x78\x56\x34\x12"
        );
        assert_eq!(
            parse_line("OK 4096 ms=3 erase_ms=1 write_ms=2 dry").unwrap(),
            Reply::Ok {
                length: 4096,
                dry: true
            }
        );
        assert!(parse_line("P 10 11").is_err());
        assert_eq!(
            parse_beacon(b"dmesh-recovery2 v=1 port=3340 main=erased chip=esp32c6").unwrap(),
            13
        );
    }
    #[test]
    fn loopback_upload_requires_response_and_fin() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            let mut h = [0; 16];
            s.read_exact(&mut h).unwrap();
            assert_eq!(h, encode_header(0, true, 4096));
            let mut b = Vec::new();
            s.read_to_end(&mut b).unwrap();
            assert_eq!(b.len(), 4096);
            s.write_all(b"P 4096 0\nOK 4096 ms=1 dry\n").unwrap();
        });
        exchange(addr, &[0; 4096], 0, true).unwrap();
        server.join().unwrap();
    }
    #[test]
    fn loopback_rejects_missing_terminal() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            let mut b = Vec::new();
            s.read_to_end(&mut b).unwrap();
            s.write_all(b"P 4096 0\n").unwrap();
        });
        assert!(exchange(addr, &[0; 4096], 0, true).is_err());
        server.join().unwrap();
    }
}
