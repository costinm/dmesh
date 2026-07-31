# Recovery implementation plan

## Phase 1: shared ABI and host tests

- Define the bootloader-readable NVS request keys and version constants.
- Define the C callback interfaces for streams, keys, partitions, logging, and
  reboot state.
- Implement canonical record encoding/decoding and ECDSA P-256 test vectors.
- Add host tests for malformed records, invalid signatures, offset overflow,
  gaps, repeated sectors, and failed writes.

## Phase 2: second-stage bootloader

- Fork the ESP-IDF bootloader project into `fw/boot`.
- Add E5 GPIO configuration and three-second hold detection.
- Add NVS request reads through `nvs_bootloader_read()`.
- Add RTC-retained rapid-reset state and Main healthy-start acknowledgement.
- Select and load Recovery or Main through the ESP-IDF bootloader loader.
- Build without `otadata` and without application networking components.

## Phase 3: Recovery application

- Create the minimal ESP-IDF application under `fw/recovery/app`.
- Add network-role selection: STA when SSID is present, otherwise AP.
- Add transport-role selection: TCP client when a remote server address is
  present, otherwise TCP server.
- Implement the minimal framed TCP stream first; measure an optional HTTP
  adapter separately and retain it only if its code/RAM cost is justified.
- Link the shared core and provide ESP-IDF flash/NVS/reboot adapters.
- Implement serial logs for every boot, request, record, write, and failure
  transition.
- Build a signed Main update stream and verify it against host test vectors.
- Add the `bootstrap` test feature:
  - enter only when the trust-key entry is positively absent;
  - select STA/AP from SSID presence;
  - select TCP client/server from remote server presence;
  - accept a length-delimited unsigned test image for an explicit partition;
  - stop after one image, timeout, or failure;
  - make the feature removable from production builds.
- Add tests proving missing-key bootstrap succeeds and present-key bootstrap is
  rejected.

## Phase 4: Main integration

- Add the shared core to Main's build without adding Recovery's Wi-Fi app.
- Add request creation and Main healthy-start acknowledgement.
- Add an optional Main-controlled Recovery image update path.
- Keep Main's product behavior separate from the shared updater.

## Phase 5: size and E5 validation

- Build optimized bootloader and Recovery images.
- Record map/component sizes and finalize the partition CSV.
- Verify no LoRa profile or unrelated mesh component is linked.
- Perform build-only and host tests first.
- Flash E5 only after the layout and recovery failure tests are reviewed.
