//! Host flash orchestration.
//!
//! Protocol framing, signed-object verification, stream flow control, and
//! durable flash semantics live in dmesh-server. This module coordinates a
//! host platform's discovery, NAN wake, Recovery handoff, object stream, and
//! post-reboot health gates.

use crate::client::fresh_request_id;
use crate::{
    client::{
        catalog_udp6_peer, catalog_vip6_inventory, direct_discovery_announce,
        discover_and_nan_activate, ensure_stream_success, exchange_udp_stream_record,
        firmware_identity, flash_target_matches, flash_target_matches_announce, hex_encode,
        multicast_discover_peers, parse_mac, run_udp_service_client, submit_nan_wake_to_all,
    },
    device::resolve_catalog_target,
    schema::encode_stream_command_with_id,
};
use dmesh_server::announce;
use std::{
    env,
    net::{Ipv6Addr, SocketAddr},
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

pub(crate) fn flash_upload_object(
    object: dmesh_server::verified_object::GetRequest<'_>,
    source: Option<&Path>,
) -> Result<(Vec<u8>, Vec<u8>, PathBuf), String> {
    let artifact_root = env::var_os("DMESH_OBJECT_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("target/flash"));
    let server = dmesh_server::ObjectServer::new(dmesh_server::ServerConfig {
        artifact_root,
        ..dmesh_server::ServerConfig::default()
    });
    if let Some(source) = source {
        let source = source.to_path_buf();
        let (manifest, image) = server
            .response_file(object, &source)
            .map_err(|error| format!("object.flash artifact: {error}"))?;
        Ok((manifest, image, source))
    } else {
        let (manifest, image) = server
            .response_object(object)
            .map_err(|error| format!("object.flash artifact: {error}"))?;
        Ok((manifest, image, server.config.artifact_root.clone()))
    }
}

pub(crate) fn flash_upload_success(response: &[u8]) -> Result<(), String> {
    if response == b"ok" {
        println!("SUCCESS object.flash complete");
        return Ok(());
    }
    let record = dmesh_server::tagged::decode(response)
        .ok_or("object.flash completed without an `ok` result")?;
    let result = record
        .result
        .ok_or("object.flash terminal response was not successful")?;
    let mut decoder = dmesh_server::cbor::Decoder::new(result);
    if decoder.text_ref() != Some(&b"flash complete"[..]) || !decoder.is_finished() {
        return Err("object.flash terminal response was not `flash complete`".into());
    }
    println!("SUCCESS object.flash complete");
    Ok(())
}

/// Bound the operator-side wait. This is only a
/// diagnostic/client deadline; QUIC loss recovery and the firmware receiver's
/// idle timeout remain transport-owned and handler-owned respectively.
pub(crate) fn object_upload_timeout() -> Duration {
    Duration::from_secs(
        env::var("DMESH_OBJECT_UPLOAD_TIMEOUT_SECS")
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .filter(|value| *value != 0)
            .unwrap_or(60),
    )
}

/// Flash selection is a stable signed identity, optionally with a temporary
/// radio MAC only for waking an otherwise unreachable device.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct FlashTarget {
    pub(crate) description: String,
    pub(crate) node: Option<String>,
    pub(crate) mac: Option<[u8; 6]>,
    /// Catalogued direct UDP6 bearer. This is only an optimization before
    /// multicast discovery; the signed announce remains the identity check.
    pub(crate) known_peer: Option<SocketAddr>,
}

fn resolve_flash_target(value: &str) -> Result<FlashTarget, String> {
    if let Some(mac) = parse_mac(value) {
        return Ok(FlashTarget {
            description: value.to_owned(),
            node: None,
            mac: Some(mac),
            known_peer: None,
        });
    }
    if let Ok(vip6) = value.parse::<Ipv6Addr>() {
        if vip6.octets()[0] != 0xfc {
            return Err(format!("flash target VIP6 must use fc00::/8, got {vip6}"));
        }
        return Ok(FlashTarget {
            description: value.to_owned(),
            node: Some(hex_encode(&vip6.octets()[8..])),
            mac: None,
            known_peer: resolve_catalog_target(value)?
                .as_ref()
                .map(catalog_udp6_peer)
                .transpose()?
                .flatten(),
        });
    }
    if value.len() == 16 && value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Ok(FlashTarget {
            description: value.to_owned(),
            node: Some(value.to_ascii_lowercase()),
            mac: None,
            known_peer: None,
        });
    }
    let host = catalog_vip6_inventory()?
        .into_iter()
        .find(|host| host.name.eq_ignore_ascii_case(value))
        .ok_or_else(|| {
            format!("unknown flash hostname {value:?}; add vip6 to the shared device catalog")
        })?;
    let profile = resolve_catalog_target(value)?
        .ok_or_else(|| format!("catalog device {value:?} has no VIP6 profile"))?;
    Ok(FlashTarget {
        description: format!("{} ({})", host.name, host.vip6),
        node: Some(host.node),
        mac: host.mac,
        known_peer: catalog_udp6_peer(&profile)?,
    })
}

/// Flash one Main image without requiring an operator to stitch together the
/// discovery, NAN wake, Recovery handoff, and verified-object steps.  The
/// target is its catalogued VIP6 identity (or a compatibility raw node ID),
/// with a NAN MAC accepted only as a temporary explicit wake selector. A legacy
/// generic ESP announce is deliberately refused for writes: it cannot select
/// a safe CPU artifact.
pub(crate) fn run_automated_flash(arguments: &[String]) -> Result<(), String> {
    let started = Instant::now();
    let result = run_automated_flash_timed(arguments, started);
    if let Err(error) = &result {
        println!(
            "dmesh_flash_timing stage=failed elapsed_ms={} error={error}",
            started.elapsed().as_millis()
        );
    }
    result
}

fn report_flash_step(step: &str, started: Instant, step_started: Instant) {
    println!(
        "dmesh_flash_timing stage={step} step_ms={} elapsed_ms={}",
        step_started.elapsed().as_millis(),
        started.elapsed().as_millis()
    );
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum AutomatedFlashImage {
    Main,
    Recovery,
    Stage2,
    Module(String),
}

impl AutomatedFlashImage {
    pub(crate) fn target(&self) -> u8 {
        match self {
            Self::Main => 6,
            Self::Recovery => 3,
            Self::Stage2 => 2,
            Self::Module(_) => 7,
        }
    }

    pub(crate) fn label(&self) -> &str {
        match self {
            Self::Main => "main",
            Self::Recovery => "recovery",
            Self::Stage2 => "stage2",
            Self::Module(name) => name,
        }
    }
}

pub(crate) struct AutomatedFlashOptions<'a> {
    pub(crate) target: &'a str,
    pub(crate) image: AutomatedFlashImage,
    pub(crate) source: Option<&'a str>,
}

pub(crate) fn parse_automated_flash_options(
    arguments: &[String],
) -> Result<AutomatedFlashOptions<'_>, String> {
    let target = arguments.first().ok_or(
        "usage: dmesh-cli flash TARGET [--target main|recovery|stage2|MODULE] [--file IMAGE]",
    )?;
    let mut selected = "main";
    let mut source = None;
    let mut index = 1;
    while index < arguments.len() {
        let value = arguments
            .get(index + 1)
            .ok_or_else(|| format!("missing value for {}", arguments[index]))?;
        match arguments[index].as_str() {
            "--target" => selected = value,
            "--file" => source = Some(value.as_str()),
            option => return Err(format!("unknown flash option {option:?}")),
        }
        index += 2;
    }
    let image = match selected {
        "main" => AutomatedFlashImage::Main,
        "recovery" => AutomatedFlashImage::Recovery,
        "stage" | "stage2" => AutomatedFlashImage::Stage2,
        value
            if !value.is_empty()
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-')) =>
        {
            AutomatedFlashImage::Module(value.to_owned())
        }
        value => return Err(format!("invalid flash target {value:?}")),
    };
    Ok(AutomatedFlashOptions {
        target,
        image,
        source,
    })
}

fn run_automated_flash_timed(arguments: &[String], started: Instant) -> Result<(), String> {
    let options = parse_automated_flash_options(arguments)?;
    let source = options.source;
    let target = resolve_flash_target(options.target)?;
    println!(
        "dmesh_flash_timing stage=start target={} image={} elapsed_ms=0",
        target.description,
        options.image.label()
    );
    // A catalogued scoped UDP6 bearer is the fastest safe way to reach a
    // target that has just accepted NAN wakeup.  Multicast cannot be used as
    // an activity test: a newly associated device may answer a unicast stream
    // before it sends its next periodic presence.  Require the same signed
    // direct discovery response used by all catalog service calls.
    let direct_probe_started = Instant::now();
    let mut selected = target.known_peer.and_then(|peer| {
        direct_discovery_announce(peer)
            .ok()
            .filter(|(_, announce)| flash_target_matches_announce(announce, &target))
            .map(|(_, announce)| (peer, announce))
    });
    println!(
        "dmesh_flash_gate direct_target_ready={}",
        selected.is_some()
    );
    report_flash_step("direct_target_probe", started, direct_probe_started);

    let discovery_started = Instant::now();
    let peers = if selected.is_none() {
        multicast_discover_peers()?
    } else {
        Vec::new()
    };
    let target_peer = peers
        .iter()
        .find(|peer| flash_target_matches(peer, &target));
    if selected.is_none() {
        selected = target_peer.map(|peer| (peer.peer, peer.announce));
    }
    // An absent multicast target was reached only by the bounded NAN wake
    // path below. Preserve its battery-oriented personality after a verified
    // update instead of silently converting an installed sleepy device into
    // an always-on STA node.
    let mut was_sleepy = selected.is_none();
    println!("dmesh_flash_gate target_found={}", selected.is_some());
    report_flash_step("initial_discovery", started, discovery_started);

    if selected.is_none() {
        let wake_started = Instant::now();
        selected = Some(discover_and_nan_activate(&target)?);
        report_flash_step("target_nan_activation", started, wake_started);
    }

    let (peer, announce) = selected
        .or_else(|| target_peer.map(|peer| (peer.peer, peer.announce)))
        .ok_or_else(|| format!("target_wake_timeout target={}", target.description))?;
    let cpu = announce::flash_cpu_for_device_class(announce.device_class).ok_or_else(|| {
        format!("target_cpu_unknown device_class={}; flash a concrete-family Main over a controlled path first", announce.device_class)
    })?;
    let target_ready_started = Instant::now();
    let initial_identity = match firmware_identity(peer) {
        Ok(identity) => identity,
        Err(initial_error) if target.mac.is_some() => {
            // A DW-only target can answer one multicast discovery request
            // while its receive lease is open, then disappear before the
            // first unicast QUIC stream. Treat that as sleepy evidence, not
            // as an active UDP endpoint. Wake through every controller and
            // require the normal direct identity response before flashing.
            was_sleepy = true;
            println!(
                "dmesh_flash_gate target_udp_ready=false peer={peer} error={initial_error}; nan_wake_retry=true"
            );
            let wake_started = Instant::now();
            let accepted = submit_nan_wake_to_all(&peers, &target)?;
            println!("dmesh_flash_gate nan_wake_observers={accepted}");
            report_flash_step("nan_wake_retry", started, wake_started);

            let deadline = Instant::now() + Duration::from_secs(45);
            loop {
                match firmware_identity(peer) {
                    Ok(identity) => break identity,
                    Err(_) if Instant::now() < deadline => {
                        std::thread::sleep(Duration::from_millis(500));
                    }
                    Err(error) => {
                        return Err(format!(
                            "target_wake_timeout target={}; NAN wake was accepted but UDP identity did not return: {error}",
                            target.description
                        ));
                    }
                }
            }
        }
        Err(error) => return Err(error),
    };
    let started_in_recovery = announce.recovery;
    println!(
        "dmesh_flash_gate target_udp_ready=true peer={peer} cpu={cpu} recovery={started_in_recovery}"
    );
    report_flash_step("target_udp_ready", started, target_ready_started);

    // Main owns in-place Recovery, Stage2, and module updates. Unlike a Main
    // image replacement these targets must not hand off to Recovery or reboot
    // the device. Discovery and NAN wake above remain identical for every
    // image kind.
    if options.image != AutomatedFlashImage::Main {
        if started_in_recovery {
            return Err(format!(
                "flash target {} requires Main's flash service, but {} is running Recovery",
                options.image.label(),
                target.description
            ));
        }
        if matches!(options.image, AutomatedFlashImage::Module(_)) {
            let stop_started = Instant::now();
            let stop = encode_stream_command_with_id("module.stop", fresh_request_id())
                .map_err(|error| error.to_string())?;
            ensure_stream_success(exchange_udp_stream_record(peer, &stop)?, "module.stop")?;
            report_flash_step("module_stop", started, stop_started);
        }
        let mut upload = vec![
            format!("udp://{peer}"),
            "object.flash".to_owned(),
            format!("cpu={cpu}"),
            format!("target={}", options.image.target()),
        ];
        if let AutomatedFlashImage::Module(name) = &options.image {
            upload.push(format!("name={name}"));
        }
        if options.image == AutomatedFlashImage::Stage2 {
            // Classic ESP32 maps its second-stage boot image at 0x1000;
            // ESP32-S3/C6 map it at zero. The firmware sink bounds both to
            // the pre-partition-table boot region.
            upload.push(format!("address={}", if cpu == 0 { 0x1000 } else { 0 }));
        }
        if let Some(source) = source {
            upload.push("--file".to_owned());
            upload.push(source.to_owned());
        }
        println!(
            "dmesh_flash_action write=true dry_run=false peer={peer} cpu={cpu} target={} image={} artifact={}",
            options.image.target(),
            options.image.label(),
            source.unwrap_or("catalog")
        );
        let object_flash_started = Instant::now();
        run_udp_service_client(&upload)?;
        println!(
            "dmesh_flash_gate object_committed=true peer={peer} image={}",
            options.image.label()
        );
        report_flash_step("object_flash", started, object_flash_started);

        let health_started = Instant::now();
        let status = encode_stream_command_with_id("status", fresh_request_id())
            .map_err(|error| error.to_string())?;
        ensure_stream_success(exchange_udp_stream_record(peer, &status)?, "Main status")?;
        println!("dmesh_flash_gate main_healthy=true peer={peer}");
        report_flash_step("main_health", started, health_started);
        restore_sleepy_after_flash(peer, was_sleepy, started)?;
        println!(
            "dmesh_flash_timing stage=complete target={} image={} elapsed_ms={}",
            target.description,
            options.image.label(),
            started.elapsed().as_millis()
        );
        return Ok(());
    }

    let recovery_peer = if started_in_recovery {
        // Crash-loop boot health and explicit repair can enter Recovery before
        // the operator starts this command. Its signed multicast response is
        // sufficient to skip a Main-only boot.recovery request.
        println!("dmesh_flash_recovery_evidence source=initial_announce");
        report_flash_step("recovery_detection", started, target_ready_started);
        peer
    } else {
        let recovery_request_started = Instant::now();
        let recovery = encode_stream_command_with_id("boot.recovery", fresh_request_id())
            .map_err(|error| error.to_string())?;
        ensure_stream_success(
            exchange_udp_stream_record(peer, &recovery)?,
            "boot.recovery",
        )?;
        println!("dmesh_flash_gate recovery_requested=true peer={peer}");
        report_flash_step("recovery_request", started, recovery_request_started);

        // Recovery reuses the target identity and endpoint. Prefer its fresh
        // signed multicast marker, but a bridged WLAN can suppress link-local
        // multicast even when Recovery has submitted it. In that case a direct
        // image identity different from the pre-handoff Main remains evidence
        // that this exact endpoint changed images.
        let recovery_wait_started = Instant::now();
        let deadline = Instant::now() + Duration::from_secs(75);
        loop {
            if Instant::now() >= deadline {
                return Err(
                    "recovery_seen=false timeout waiting for signed Recovery announce or changed direct identity"
                        .into(),
                );
            }
            let candidates = multicast_discover_peers()?;
            if let Some(candidate) = candidates.into_iter().find(|candidate| {
                candidate.node == hex_encode(announce.device_id())
                    && candidate.announce.device_class == announce.device_class
                    && candidate.announce.recovery
            }) {
                println!("dmesh_flash_recovery_evidence source=multicast_marker");
                report_flash_step("recovery_wait", started, recovery_wait_started);
                break candidate.peer;
            }
            if firmware_identity(peer).is_ok_and(|identity| identity != initial_identity) {
                println!("dmesh_flash_recovery_evidence source=direct_identity");
                report_flash_step("recovery_wait", started, recovery_wait_started);
                break peer;
            }
        }
    };
    println!("dmesh_flash_gate recovery_seen=true peer={recovery_peer}");
    // A Main update is allowed to change the application ELF hash, including
    // when the requested image differs from the Main that initiated this
    // handoff. The pre-handoff Main identity therefore cannot be the expected
    // post-update identity. Capture Recovery's running-image identity instead:
    // the final gate must prove that this endpoint left Recovery, then require
    // a normal Main status response. This also accepts an idempotent reflash
    // of the same Main image.
    let recovery_identity = firmware_identity(recovery_peer)?;
    let mut upload = vec![
        format!("udp://{recovery_peer}"),
        "object.flash".to_owned(),
        format!("cpu={cpu}"),
        "target=6".to_owned(),
    ];
    if let Some(source) = source {
        upload.push("--file".to_owned());
        upload.push(source.to_owned());
    }
    println!(
        "dmesh_flash_action write=true dry_run=false peer={recovery_peer} cpu={cpu} target=6 artifact={}",
        source.unwrap_or("catalog")
    );
    let object_flash_started = Instant::now();
    run_udp_service_client(&upload)?;
    println!("dmesh_flash_gate object_committed=true peer={recovery_peer}");
    report_flash_step("object_flash", started, object_flash_started);

    let main_health_started = Instant::now();
    let deadline = Instant::now() + Duration::from_secs(75);
    loop {
        if Instant::now() >= deadline {
            return Err("main_healthy=false timeout waiting for Main status".into());
        }
        let candidates = multicast_discover_peers()?;
        let multicast_peer = candidates.into_iter().find(|candidate| {
            candidate.node == hex_encode(announce.device_id())
                && candidate.announce.device_class == announce.device_class
                && !candidate.announce.recovery
        });
        // A bridge may suppress receiver-visible link-local multicast even
        // though the target can still answer direct UDP6. Recovery uses this
        // same fallback above. The Recovery identity makes the final check
        // safe: status alone must not mistake the still-running Recovery for
        // the returned Main image, while a changed Main image need not equal
        // the Main identity that initiated the update.
        let health_peer = multicast_peer
            .map(|candidate| candidate.peer)
            .unwrap_or(peer);
        let identity_matches_main =
            firmware_identity(health_peer).is_ok_and(|identity| identity != recovery_identity);
        if identity_matches_main {
            let status = encode_stream_command_with_id("status", fresh_request_id())
                .map_err(|error| error.to_string())?;
            if ensure_stream_success(
                exchange_udp_stream_record(health_peer, &status)?,
                "Main status",
            )
            .is_ok()
            {
                println!("dmesh_flash_gate main_healthy=true peer={health_peer}");
                report_flash_step("main_health", started, main_health_started);
                restore_sleepy_after_flash(health_peer, was_sleepy, started)?;
                println!(
                    "dmesh_flash_timing stage=complete target={} elapsed_ms={}",
                    target.description,
                    started.elapsed().as_millis()
                );
                return Ok(());
            }
        }
    }
}

fn restore_sleepy_after_flash(
    peer: SocketAddr,
    was_sleepy: bool,
    started: Instant,
) -> Result<(), String> {
    if !was_sleepy {
        return Ok(());
    }
    let restore_started = Instant::now();
    let restore = encode_stream_command_with_id(
        "transport.set mode=nan now=2 nan_dw_interval=8 ap=0",
        fresh_request_id(),
    )
    .map_err(|error| error.to_string())?;
    // A successful profile replacement can tear down STA before its response
    // arrives. Prove the stronger peer-visible condition instead: the signed
    // target must disappear from UDP multicast after the one submission.
    let restore_reply = exchange_udp_stream_record(peer, &restore)
        .and_then(|response| ensure_stream_success(response, "sleepy profile restore"));
    // Main keeps the just-used UDP bearer alive long enough to return the
    // correlated transport reply and settle its radio epoch. An immediate
    // multicast probe therefore observes the old active endpoint even when
    // the requested NAN-only profile has already committed. A DW node may
    // also answer a multicast discovery packet during its brief radio window,
    // so multicast presence cannot establish that the STA/UDP control path
    // remained active. After the handoff, require the stronger inverse: a
    // normal unicast QUIC identity stream must no longer be reachable.
    std::thread::sleep(Duration::from_secs(6));
    if firmware_identity(peer).is_ok() {
        return Err(format!(
            "sleepy_profile_restore=false target still accepted a unicast UDP identity stream{}",
            restore_reply
                .err()
                .map(|error| format!("; reply={error}"))
                .unwrap_or_default()
        ));
    }
    println!("dmesh_flash_gate sleepy_profile_restored=true peer={peer} unicast_udp_absent=true");
    report_flash_step("sleepy_profile_restore", started, restore_started);
    Ok(())
}
