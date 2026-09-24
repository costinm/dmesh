# lmesh Wi-Fi API

`lmesh` is the Linux mesh daemon and owns the selected Wi-Fi interface, raw-NAN
monitor, BLE adapter, local control socket, and HTTP admin endpoint. Its radio
implementation currently lives in the internal `lmesh-wifi` library; the
public Wi-Fi request reference is [root API](../../API.md); adapter details are in
[the radio README](../lmesh-wifi/README.md).

The supervised service template is [lmesh.toml](mesh-init/lmesh.toml). Select
the host interface there. The daemon uses `/run/mesh/lmesh/mesh.sock.cbor`, HTTP
port 18981, and UDP port 3336.
