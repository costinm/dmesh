# dmesh-cli

`dmesh-cli` is the direct host client for a QUIC-lite device session. It opens
an explicit UART, UDP endpoint, or named device profile, then uses the common
stream handlers for service discovery, commands, log watch, and PROBE.

It does not create or use a managed UART forward. `dmesh-cli` owns the UART
L2 implementation and is the only operator CLI.

```sh
cargo run -p dmesh-cli -- /dev/serial/by-id/DEVICE services
cargo run -p dmesh-cli -- e6 log-watch records=16
cargo run -p dmesh-cli -- e7 check
# Schema commands are normal tagged QUIC streams, never direct records.
cargo run -p dmesh-cli -- e7 settings.get key=name
cargo run -p dmesh-cli -- e7 telemetry.nan_metrics
cargo run -p dmesh-cli -- e7 radio.snapshot
cargo run -p dmesh-cli -- e7 radio.scan
```

Schema methods after the target are normal tagged QUIC streams, including
settings, telemetry, and raw-Wi-Fi control/injection. The CLI prints the
correlated tagged response so each operator command is also a stream-handler
check. Direct `--msg` remains restricted to `transport.set`.
