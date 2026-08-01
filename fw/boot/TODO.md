# Second-stage boot TODOs

These are deferred until the recovery flow is stable and tested on the fleet.

- Define and test production secure-boot provisioning for the signed
  second-stage bootloader, Recovery, and Main images.
- Enable and validate flash encryption, including encrypted Recovery NVS and
  any protected key material.
- Lock down JTAG through the appropriate chip eFuses after development access
  is no longer required.
- Restrict UART/USB download mode and document the irreversible eFuse
  provisioning sequence and recovery implications.
- Run a final physical-access test after lockdown: rejected unsigned images,
  inaccessible flash contents, disabled debug access, and a working signed
  Recovery update path.

## Future: block-hash-assisted flash and common framing

- Reserve the last flash sector of each updatable partition for a compact block
  hash table. The usable image area must exclude this sector, and the table
  format must record the block size, image length, hash algorithm, truncation
  length, generation, and per-block digests. Evaluate truncated SHA-256 (or a
  stronger compact digest) so the table fits without a Merkle tree; add an
  overflow/format decision for partitions whose image has too many blocks.
- Change the raw TCP flash handshake to be device-first: the device sends its
  current hash sector, the host sends a signed replacement hash sector, and
  then sends only blocks whose hashes differ, using the existing read/write
  verification and failure semantics. The device writes the new hash sector
  only after every changed block has been written successfully.
- Reuse the same hash-sector verification in the second-stage bootloader so it
  can cheaply verify Recovery and Main before handoff, and decide how to
  represent an interrupted update without routine NVS writes.
- Evaluate a minimal second-stage implementation of the same differential
  protocol. It must remain optional and bounded; the normal path continues to
  use Main/Recovery for network flashing.
- Evaluate moving the second-stage, Recovery, and Main control/data channels to
  PPP framing for one shared escaping, packet-boundary, and diagnostic model.
  Compare code size, RAM, bootloader dependencies, and interoperability with
  the current raw `DRS1` TCP stream before changing the working transport.

These items are future optimization and consistency work. They do not block
the current full-image raw-TCP flash path, remote-device updates, or the
initial/emergency USB path.
