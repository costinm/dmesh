//! Main-only credential writes. The shared worker supplies trusted ingress
//! provenance; the request's own `kind` field is never authorization.

use alloc::vec::Vec;
use dmesh_server::{provision, tagged::{self, Name, Record}};
use dmesh_server::registry::CallContext;

/// The request's association runs over the wired UART, by the node's own record of its bearer;
/// the request's `kind` field is never consulted.
fn over_uart(context: CallContext) -> bool {
    context.bearer.is_some_and(|bearer| bearer.as_str() == "uart0")
}

/// The request's association runs over the BLE L2CAP channel.
fn over_ble_coc(context: CallContext) -> bool {
    context.bearer.is_some_and(|bearer| bearer.as_str() == "ble")
}

pub fn register() {
    assert!(dmesh_server::registry::register(
        dmesh_server::registry::methods::PROVISION_INSTALL,
        dmesh_server::registry::SyncCtxFn(handle),
    ));
    assert!(dmesh_server::registry::register(
        dmesh_server::registry::methods::PROVISION_UNPAIR,
        dmesh_server::registry::SyncCtxFn(handle_unpair),
    ));
}

/// `provision.unpair`: forget the secret and the control-plane root, and every
/// BLE bond. Wired UART/USB only: that host could reflash the device anyway, so
/// it needs no proof of the current secret. Never over a radio bearer, whatever
/// the request claims.
fn handle_unpair(record: Record<'_>, context: CallContext) -> Option<Vec<u8>> {
    if record.component != Some(Name::Tag(provision::COMPONENT)) { return None; }
    let id = record.id?;
    let unpaired = over_uart(context)
        && provision::is_unpair(record)
        && dmesh_fw_transport::main_runtime::clear_pairing()
        && dmesh_ble::clear_bonds();
    let mut wire = [0; 64];
    let len = tagged::encode_numeric_response(
        provision::COMPONENT, provision::UNPAIR, id,
        if unpaired { &[0xf5] } else { &[0xf4] }, &mut wire,
    )?;
    Some(Vec::from(&wire[..len]))
}

fn handle(record: Record<'_>, context: CallContext) -> Option<Vec<u8>> {
    if record.component != Some(Name::Tag(provision::COMPONENT)) { return None; }
    let id = record.id?;
    // Wired UART/USB may set or replace the secret. BLE may only pair a device
    // that has none (install_pairing enforces that and the open pairing
    // window). Anything else is refused.
    let replace = if over_uart(context) {
        Some(true)
    } else if over_ble_coc(context) {
        // Plain CoC, not encrypted: the pairing window and the absence of a secret are the
        // gates, and the secret is installed over this link once (see API.md, `companion`).
        Some(false)
    } else {
        None
    };
    let installed = replace.is_some_and(|replace| {
        provision::decode_install(record).is_some_and(|request| {
            dmesh_fw_transport::main_runtime::install_pairing(
                request.name, request.root_public_key, request.secret, replace,
            )
        })
    });
    let mut wire = [0; 64];
    let len = tagged::encode_numeric_response(
        provision::COMPONENT, provision::INSTALL, id,
        if installed { &[0xf5] } else { &[0xf4] }, &mut wire,
    )?;
    Some(Vec::from(&wire[..len]))
}
