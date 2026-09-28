//! Main-only credential writes. The shared worker supplies trusted ingress
//! provenance; the request's own `kind` field is never authorization.

use alloc::vec::Vec;
use dmesh_server::{provision, tagged::{self, Name, Record}};
use dmesh_fw_transport::shared_ingress_esp::{self, IngressKind};

pub fn register() {
    assert!(dmesh_server::services::register_tagged_component(
        provision::COMPONENT, handle,
    ));
}

fn handle(record: Record<'_>) -> Option<Vec<u8>> {
    if record.component != Some(Name::Tag(provision::COMPONENT)) { return None; }
    let id = record.id?;
    let allowed = match shared_ingress_esp::active_pairing_bearer() {
        Some(IngressKind::Uart) => true,
        Some(IngressKind::BleCoc) => dmesh_ble::coc_encrypted(),
        _ => false,
    };
    let installed = allowed && provision::decode_install(record).is_some_and(|request| {
        dmesh_fw_transport::main_runtime::install_pairing(
            request.name, request.root_public_key, request.secret,
        )
    });
    let mut wire = [0; 64];
    let len = tagged::encode_numeric_response(
        provision::COMPONENT, provision::INSTALL, id,
        if installed { &[0xf5] } else { &[0xf4] }, &mut wire,
    )?;
    Some(Vec::from(&wire[..len]))
}
