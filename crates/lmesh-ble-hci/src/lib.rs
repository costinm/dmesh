//! Linux BLE for DMesh: an L2CAP CoC packet bearer and the Linux side of the
//! common `companion` handlers.
//!
//! This crate defines no API of its own. Method and field numbers belong to
//! `API.md` and arrive as the generated types in `dmesh_server::platform_api`;
//! the wire protocol for BLE discovery lives with the other radios. BlueZ owns
//! pairing consent and bonds.

mod coc;
mod coc_bearer;
mod companion;
mod mgmt;

pub use coc_bearer::CocBearer;
pub use companion::BleCompanion;
