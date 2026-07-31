# Recovery design

## Responsibilities

Recovery has exactly four jobs:

1. read the bootloader request and trust root;
2. select AP or STA and a TCP client/server role;
3. verify and apply independently signed firmware records;
4. clear the request and reboot into Main after successful EOF.

It does not perform update policy, version selection, discovery, scheduling,
rollback policy, or product initialization.

## Link and transport selection

Recovery should not depend on HTTP unless the size and interoperability probe
shows that HTTP is necessary. The primary transport is a small framed TCP
stream with no headers, redirects, chunked encoding, DNS, or filesystem. It
can carry either signed records or the explicitly permitted unsigned bootstrap
image stream.

HTTP is an optional adapter behind the same stream interface. It is retained
only if its code and RAM cost are small enough, or if host integration requires
ordinary HTTP serving. Both transports feed the same bounded update core, so
transport choice cannot bypass block verification.

Network and TCP roles are selected independently from the request:

```text
SSID present          -> STA joins configured AP
SSID absent           -> open AP ESP32S3_8_BOOT_XXXX at 192.168.4.1
remote server present -> Recovery is a TCP client
remote server absent  -> Recovery starts a TCP server
password present      -> use the configured protected STA network
password absent       -> STA credentials are open; AP mode is always open
```

An SSID is not a trust decision. With a trust key present, every TCP/HTTP
block must still carry a valid signature. With no trust key, only the explicit
bootstrap path may accept unsigned input.

## Bootstrap mode

For initial E5 provisioning and development, Recovery supports an explicit
unsigned bootstrap path:

```text
SSID present + key present    -> STA + signed TCP/HTTP stream
SSID absent + key present     -> AP + signed TCP/HTTP stream
SSID present + no key         -> STA + unsigned bootstrap stream
SSID absent + no key          -> AP + unsigned bootstrap stream
```

The missing-key condition is the gate. A bad, malformed, or failed key read is
not treated as missing; Recovery must fail closed unless it can positively
establish that the trust-key entry is absent. A provisioned key permanently
disables unsigned bootstrap input until the device is deliberately
reprovisioned.

Bootstrap mode is intended to install the first signed Main/Recovery images on
an otherwise empty factory device. It must be visibly logged as `bootstrap`,
accept only one bounded connection at a time, enforce a maximum image/record
size, and shut down after one successful image or a short idle timeout. AP
mode must not advertise, bridge, route, or expose the normal mesh services.

The initial TCP test protocol is deliberately simpler than the signed update
protocol: a versioned, length-delimited stream targeted to one explicitly
named partition. Signed mode carries independently signed blocks. Bootstrap
mode carries an unsigned complete image but uses the same bounded partition
writer. It is a test provisioning transport, not a reusable update format.

The host tool must select the target partition and send a complete image; the
Recovery writer still enforces partition bounds and flash errors. The protocol
must reject oversized frames, partial frames, extra trailing data, and a
second client after the session has started.

Bootstrap writes do not establish trust. The host provisioning sequence is:

1. start Recovery with an empty NVS trust-key entry;
2. configure an SSID for STA provisioning, or leave it absent for AP
   provisioning;
3. configure a remote server address for TCP client mode, or leave it absent
   for TCP server mode;
4. install the initial signed-capable Recovery and Main images;
5. provision the trust key in NVS;
6. reboot and verify that unsigned `bootstrap` input is no longer available.

The implementation must include a negative test proving that the same unsigned
TCP stream is rejected once the key exists.

## Shared core

The reusable `core` library is the important interface. It owns:

- bounded request parsing and validation;
- the signed-record parser;
- canonical record bytes used for signature verification;
- the configured public-key algorithm;
- FirmwareBlock validation;
- sector erase tracking;
- partition bounds and overflow checks;
- verified flash writes;
- request completion/failure state transitions.

The core is compiled as a small C static library with no ESP-IDF application
runtime dependency. It can be linked by both Recovery and Main. Platform
adapters are supplied by the caller, so Main can use the same implementation
to flash a newer Recovery image without importing Wi-Fi or Recovery's entry
point.

## Record format

Version 1 uses definite-length canonical CBOR records. Each record contains a
version, type, payload, and signature. The signature covers the canonical
encoding of the version, type, and payload, excluding the signature field.

The initial payload is a FirmwareBlock for the `main` or `recovery` target,
with a partition-relative offset and one bounded flash block. Records are
verified before any erase or write. Gaps are allowed; a sector is erased at
most once per update session.

The initial target algorithm is ECDSA P-256 using the smallest ESP-IDF-native
verification path found during the size probe. The envelope version reserves
future algorithm changes without changing the update state machine.

## Update paths

### Main to Recovery

Main uses the shared core with a transport it controls:

1. obtain a signed Recovery stream;
2. select the Recovery partition as the destination;
3. verify each block;
4. erase/write only after verification;
5. finish and reboot.

Main does not use `esp_ota_set_boot_partition()` and does not require an
`otadata` partition. The second-stage bootloader continues to select the
appropriate image on the next reset.

Bootstrap writes use a separate Recovery application adapter and must not
weaken the shared signed-update core. The unsigned path is compiled/configured
as a clearly named test feature so production builds can omit it.

### Recovery to Main

Recovery uses the same core with its TCP or optional HTTP stream adapter and writes Main. On
success it clears the Recovery request and reboots. The bootloader then sees
no recovery condition and loads Main.

## Failure behavior

Any HTTP, parsing, signature, bounds, erase, or write error stops the update.
The request remains set, Recovery remains observable over serial, and the
next reset retries Recovery. A partially written Main is not selected by
policy; the bootloader's selection policy remains the authority.

Bootstrap failures stop the TCP session and leave the trust key absent; they do
not silently fall through to signed mode or accept a second unauthenticated
client without a new explicit bootstrap start.

## Size and E5 constraints

The first implementation is for the classic ESP32 E5 board only. It must not
enable the existing LoRa, BLE, NAN, or mesh application components. The size
acceptance gate is the measured release binary plus explicit headroom, not a
preselected partition size.

No flash operation is authorized until the E5 bootloader, Recovery app, Main
image, and partition table all fit in a measured release layout.
