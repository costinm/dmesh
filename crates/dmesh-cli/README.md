# dmesh-cli

`dmesh-cli` is the direct host client for a QUIC-lite device session. It opens
an explicit UART, UDP endpoint, or named device profile, then uses the common
stream handlers for service discovery, commands, log watch, and IPERF.

It does not create or use a managed UART forward. `dmesh-cli` owns the UART
L2 implementation and is the only operator CLI.

```sh
cargo run -p dmesh-cli -- /dev/serial/by-id/DEVICE --services
cargo run -p dmesh-cli -- e6 --service log-watch --log-records 16
cargo run -p dmesh-cli -- udp://10.78.0.101:3339 --udp-probe
```
