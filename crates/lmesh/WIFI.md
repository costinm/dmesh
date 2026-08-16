# lmesh Wi-Fi API pointer

The authoritative Wi-Fi library API, ownership policy, request names, startup
behavior, and tuning notes live in [`lmesh-wifi/API.md`](../lmesh-wifi/API.md).

`lmesh` is the experimental superset: it embeds `lmesh-wifi`, normally owns
`wlan1`, and retains canary-only discovery, signature, and BLE HCI work. It
must not duplicate or redefine the Wi-Fi API here; update `lmesh-wifi/API.md`
when the shared library contract changes.
