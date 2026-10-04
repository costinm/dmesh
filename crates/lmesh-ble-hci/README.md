# Linux BLE

`lmesh-ble-hci` is the Linux BLE adapter. It defines no API: method and field
numbers are in the [root API](../../API.md) and arrive as the generated types
in `dmesh_server::platform_api`. Its whole public surface is two types:

- `CocBearer`: a QUIC-lite packet bearer over one L2CAP CoC. `connect` requests
  an encrypted link and checks the negotiated security level; BlueZ's agent
  handles user consent and bond persistence. The bearer adds no cryptography of
  its own. Each CoC SDU carries one complete opaque QUIC-lite packet with no
  extra length prefix.
- `BleCompanion`: the Linux half of `companion.pair` and `companion.unpair` for
  `kind=ble`. It attaches the CoC to the daemon's running QUIC node as an
  ordinary bearer and pairs over an ordinary association, using the shared
  exchange in `dmesh_server::companion_pair`. The device refuses a BLE pairing
  when it already has a secret.

Not implemented: `unpair` over BLE only releases the channel; it does not reset
the device or remove the BlueZ bond (a wired unpair resets the device, including
its BLE bonds).

Raw HCI scan and advertising, and the JSON `ble.*` scan helpers, were removed:
`ble.*` is an Android and firmware API, and BLE discovery belongs with the
shared radio protocol.

Bluetooth link security and the DMesh shared control secret are separate.
