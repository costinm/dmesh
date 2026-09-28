# Integration tests

Scripts and Python entry points in this directory exercise a component's
production packaging (`target/dist/opt/ssh-mesh/bin` after
`scripts/build.sh`, or `result-sshm/bin` after `nix build .#sshm`) against a
mesh-init controlled runtime, in three shapes:

1. `root` - a bwrap namespace (mapped root; `scripts/start_bwrap.sh`).
2. `subuid` - `unshare --map-auto` with the user's `/etc/subuid` ranges
   (`scripts/start_bwrap.sh --user`). Skipped (`77`) when the environment
   cannot map subuids.
3. `podman` - a container (podman or docker, from the Dockerfile's netshoot
   target) running mesh-init as PID 1; the ssh check runs from the host
   against the published loopback ports (`scripts/start_podman.sh`).

The helpers mount the staged binaries, the certificate/config staging dir and
the mesh-init service config, all under `$TMPDIR` (default `target/tmp`),
keep `/tmp` clean, and tear everything down when the command exits.

## Run

```bash
# release tree first
scripts/build.sh rust

# bwrap (mapped root), and the subuid variant when the kernel allows it
python3 tests/test_cert_terminal_mesh_init.py --case all

# container flows (podman by default, or ENGINE=docker)
python3 tests/test_cert_terminal_mesh_init.py --case podman --engine podman
ENGINE=docker python3 tests/test_cert_terminal_mesh_init.py --case podman

# via the focused test runner
scripts/build.sh test cert_terminal_mesh_init
```

The tests keep the scratch dir on failures for debugging:
`SSH_MESH_TEST_KEEP=1 python3 tests/test_cert_terminal_mesh_init.py`.

## What the tests check

1. mesh-init binds the ssh listener from the service `[[Socket.Listen]]`
   entry and transfers it (systemd-style activation: fd 3 + `LISTEN_FDS` with
   the fd name `ssh`) to ssh-mesh, either at daemon start (bwrap) or on the
   first connection (containers).
2. A CA-signed certificate login (`alice@test.m` for the bwrap cases, `root`
   for the container case, matching the image's packaged ssh-mesh service)
   execs `id -u` through mesh-init's tagged-CBOR terminal delegation and
   resolves to the home directory's owner.
3. A plain authorized-key login (`alice`, or `root` inside the container)
   behaves the same.

The test spans the mesh-init to ssh-mesh delegation path (`cert_terminal_for_user`
and `send_start_terminal_to_mesh_init_blocking` in `crates/ssh-mesh/src/sshd.rs`).

## Manual commands

The tests stage a scratch dir `certs/` with:

- `alice` (ECDSA private key), `alice.pub`, `alice-cert.pub`
  (CA-signed, principal `alice@test.m`);
- `ca/` and `server-ssh/id_ecdsa` (the SSH server identity shared with
  ssh-mesh's `SSH_BASEDIR`), plus `server-ssh/authorized_cas` and
  `ssh-mesh-config/users/alice/authorized_keys`.

Manual run with the bwrap helper (after cargo build, the helper finds the
release binaries under `target/x86_64-unknown-linux-musl/release` itself; use
`--app-dir` to mount a different package tree at /opt/ssh-mesh, with its
`bin/` and `etc/mesh-init/` directories as-is):

```bash
source env.sh
scripts/start_bwrap.sh \
  --mount "<certs-dir>:/certs" \
  --mesh-init-config "<certs-dir>/mesh-init-etc" \
  -- /bin/bash
```

or equivalently from a self-contained staging dir (bin + etc/mesh-init):

```bash
scripts/start_bwrap.sh --app-dir <app-tree> -- /bin/bash
```

Manual run with the podman helper (same mounts and identity: after
`scripts/build.sh` the staged tree is used; with `nix build .#sshm` the
binaries can come from `result-sshm/bin`):

```bash
scripts/start_podman.sh \
  --mount "<certs-dir>:/certs" \
  --mesh-init-config "<certs-dir>/mesh-init-etc" \
  -- /bin/bash
```

Then, from the host namespace:

```bash
ssh -i <certs-dir>/alice -o CertificateFile=<certs-dir>/alice-cert.pub \
    -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
    -o LogLevel=ERROR -o BatchMode=yes \
    -p <SSH_PORT> -l alice@test.m 127.0.0.1 id -u
```

## ssh options

The tests run non-interactive ssh with these options:

| Option | Purpose |
|---|---|
| `-o StrictHostKeyChecking=no` | Accept the freshly-staged host key (no known_hosts) |
| `-o UserKnownHostsFile=/dev/null` | Do not persist the host key across runs |
| `-o BatchMode=yes` | Fail instead of prompting for a password |
| `-o ConnectTimeout=10` | Bound the socket connect time |
| `-o LogLevel=ERROR` | Only log errors; keep the output to the result alone |
| `-i <key>` | Private key / identity for both certificate and plain logins |
| `-o CertificateFile=<cert>` | The user's SSH certificate, signed by the test CA with principal `alice@test.m` (`-n alice@test.m`). |

Use the same options in manual commands: pending the exact ssh client
version, `BatchMode` and `ConnectTimeout` keep the automated runs robust
(cert + `id -u` and no password prompts). After removing
`CertificateFile`, the same command exercises the plain authorized-key
login path (`alice` in the bwrap flow, `root` in the container flow) via the
`ssh-mesh-config/users/<login>/authorized_keys` entries.
