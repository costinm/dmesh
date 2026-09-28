#!/usr/bin/env python3
"""Cert + terminal delegation test, using scripts/start_bwrap.sh.

Verifies the ssh-mesh <-> mesh-init SSH terminal contract end to end:

1. mesh-init binds the ssh listener declared by the service's
   ``[[Socket.Listen]]`` and transfers it to ssh-mesh at activation
   (systemd-style fd 3 + ``LISTEN_FDS``, fd name ``ssh``).
2. A CA-signed certificate login (``alice@test.m``) and a plain
   authorized-key login (``alice``) both delegate through mesh-init's
   tagged-CBOR ``start_terminal`` and run with the home directory owner's
   uid (``tests/cert_terminal_inner.py`` holds the assertion logic).

Binaries are not built: the runtime comes from the release tree staged by
``scripts/build.sh`` (``target/dist/opt/ssh-mesh/bin``), a plain cargo
release dir, or ``SSH_MESH_TEST_BIN`` (which may select a Nix result path).
Missing binaries lead to an exit status of 77.

Usage:
    python3 tests/test_cert_terminal_mesh_init.py [--case root|subuid|all]

Environment:
    SSH_MESH_TEST_BIN    directory with ssh-mesh, mesh-init, mesh (overrides)
    SSH_MESH_TEST_KEEP   keep the scratch dir for debugging
"""

import argparse
import atexit
import logging
import os
import pathlib
import shutil
import stat
import socket
import subprocess
import sys
import tempfile
import time

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
START_BWRAP = REPO_ROOT / "scripts" / "start_bwrap.sh"
START_PODMAN = REPO_ROOT / "scripts" / "start_podman.sh"
INNER = REPO_ROOT / "tests" / "cert_terminal_inner.py"
BIN_NAMES = ("ssh-mesh", "mesh-init", "mesh")

# Fixed paths inside the bwrap namespace (sources are staged under the
# scratch dir and are bind-mounted by start_bwrap.sh at these locations).
BIN_DIR_IN_NS = "/opt/ssh-mesh/bin"
CERTS_DIR_IN_NS = "/certs"
# Fixed container-internal listener ports of the packaged ssh-mesh defaults.
CONTAINER_PORTS = (15022, 15080)
SSH_CONFIG_DIR_IN_NS = "/certs/ssh-mesh-config"
SSH_SERVER_DIR_IN_NS = "/certs/server-ssh"
ALICE_HOME_IN_NS = "/home/alice"

# Mapped identities inside the two namespaces. The sub-uid values map 1:1
# from the /etc/subuid range of the invoking user (build:100000:65536); 1234
# is a leftover from mapped-ns testing and would not be chown-able by the
# subuid namespace either.
ROOT_HOME_UID = 0
SUBUID_REGULAR_UID = 100001
SUBUID_ALICE_UID = 100002

# Identity of the alice home: mapped-root case uses the mapped owner, subuid
# case uses the subuid range for the alice identity.
ROOT_CASE_HOME_UID = ROOT_HOME_UID

# The test's own namespace (network is not isolated, so ssh runs from the
# host against the socket-activated ssh-mesh listener).
def free_port():
    """Bind 0.0.0.0:0 to pick a free host port; mesh-init binds them in-ns and
    ssh checks them from the host."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("0.0.0.0", 0))
        return sock.getsockname()[1]


def test_ports(case):
    """Fresh pair of free host ports; mesh-init owns them inside the ns."""
    ssh_port = free_port()
    http_port = free_port()
    while http_port == ssh_port:
        http_port = free_port()
    return ssh_port, http_port


def find_bin_dir(pathlib_path):
    candidates = []
    if "SSH_MESH_TEST_BIN" in os.environ:
        candidates.append(pathlib_path(os.environ["SSH_MESH_TEST_BIN"]))
    candidates.append(REPO_ROOT / "target/dist/opt/ssh-mesh/bin")
    candidates.append(REPO_ROOT / "target/x86_64-unknown-linux-musl/release")
    candidates.append(REPO_ROOT / "result-sshm/bin")
    for candidate in candidates:
        if all(
            (candidate / name).is_file() and os.access(candidate / name, os.X_OK)
            for name in BIN_NAMES
        ):
            return candidate.resolve()
    rendered = ", ".join(str(candidate) for candidate in candidates)
    print(
        f"SKIP: no release binaries with {BIN_NAMES} under {rendered}; "
        "run `scripts/build.sh rust` or set SSH_MESH_TEST_BIN"
    )
    sys.exit(77)


def require_commands(*commands):
    missing = [command for command in commands if shutil.which(command) is None]
    if missing:
        print(f"SKIP: required commands missing: {', '.join(missing)}")
        sys.exit(77)


def require_engine(engine):
    """A container runtime must both exist and accept commands (the docker
    daemon may be off even if the CLI is installed)."""
    if shutil.which(engine) is None:
        print(f"SKIP: container engine {engine} not installed")
        sys.exit(77)
    probe = subprocess.run([engine, "info"], capture_output=True)
    if probe.returncode != 0:
        stderr = probe.stderr.decode(errors="replace").strip().splitlines()
        hint = stderr[-1] if stderr else f"exit {probe.returncode}"
        print(
            f"SKIP: container engine {engine} not reachable: {hint}"
        )
        sys.exit(77)


def prepare_artifacts(scratch):
    """CA, CA-signed alice key/cert, sshd key, authorized_keys."""
    logging.info("Preparing certificates and sshd config in %s", scratch)
    cert = scratch / "certs"
    server = cert / "server-ssh"
    admin_keys = cert / "ssh-mesh-config" / "users" / "alice"
    for directory in (server, admin_keys):
        directory.mkdir(parents=True, exist_ok=True)
    ca = cert / "ca"
    alice = cert / "alice"
    for target in (ca, alice, server / "id_ecdsa"):
        subprocess.run(
            ["ssh-keygen", "-q", "-t", "ecdsa", "-N", "", "-f", str(target)],
            check=True,
        )
    subprocess.run(
        [
            "ssh-keygen", "-q",
            "-s", str(ca),
            "-I", "alice-test",
            "-n", "alice@test.m",
            "-V", "-1h:+1h",
            f"{alice}.pub",
        ],
        check=True,
    )
    (server / "authorized_cas").write_text((cert / "ca.pub").read_text())
    shutil.copy(alice.with_suffix(".pub"), admin_keys / "authorized_keys")
    # sshd refuses keys with loose ownership; only private key files get
    # 0600; the certificates, public keys, and authorized_keys stay 0644.
    for path in cert.rglob("*"):
        if path.is_dir():
            os.chmod(str(path), 0o755)
        elif path.name in ("ca", "alice", "id_ecdsa"):
            os.chmod(str(path), 0o600)
        else:
            os.chmod(str(path), 0o644)
    return cert


def write_service_config(scratch_root, ssh_port, http_port, exec_start=None):
    """ssh-mesh service config consumed via MESH_INIT_DIR.

    exec_start defaults to the sandbox path of the ssh-mesh binary; the
    container flow leaves it unset (mesh-init runs the image's packaged
    default at /opt/ssh-mesh/bin/ssh-mesh).
    """
    mesh_init_etc = scratch_root / "mesh-init-etc"
    mesh_init_etc.mkdir(parents=True, exist_ok=True)
    if exec_start is None:
        exec_start = "/opt/ssh-mesh/bin/ssh-mesh"
    service_toml = f"""[Service]
Type = "exec"
ExecStart = "{exec_start}"

[Socket]
Accept = false

[[Socket.Listen]]
Type = "stream"
Address = "0.0.0.0:{ssh_port}"
Name = "ssh"

[[Socket.Listen]]
Type = "stream"
Address = "0.0.0.0:{http_port}"
Name = "http"

[Environment]
RUST_LOG = "info"
SSH_BASEDIR = "{SSH_SERVER_DIR_IN_NS}"
SSH_MESH_CONFIG = "{SSH_CONFIG_DIR_IN_NS}"
SSH_MESH_HOME_ROOT = "/home"
MESH_INIT_SOCK = "/run/mesh/mesh-init/mesh.sock"
MESH_INIT_SEQPACKET_SOCK = "/run/mesh/mesh-init/mesh.sock.cbor"
"""
    (mesh_init_etc / "ssh-mesh.toml").write_text(service_toml, encoding="utf-8")
    return mesh_init_etc


def run_case(case, bin_dir, scratch_root, engine=None):
    """One namespace per call. `case` is `root`, `subuid`, or `podman`."""
    logging.info("%s: preparing artifacts under %s", case, scratch_root)
    certs = prepare_artifacts(scratch_root)
    user_spec = ""
    expected_uid = ROOT_CASE_HOME_UID
    if case == "subuid":
        user_spec = f"{SUBUID_REGULAR_UID}:{SUBUID_REGULAR_UID}"
        expected_uid = SUBUID_ALICE_UID

    container_mode = case == "podman"
    if container_mode:
        require_engine(engine)
        ssh_port, http_port = CONTAINER_PORTS
    else:
        ssh_port, http_port = test_ports(case)

    mesh_init_etc = write_service_config(
        scratch_root,
        ssh_port,
        http_port,
        exec_start=None if container_mode else f"{BIN_DIR_IN_NS}/ssh-mesh",
    )

    # Built per case: the inner worker runs from the mounted certs dir, so the
    # sandbox mounts only /certs and /opt (target/dist tree) plus
    # --mesh-init-config.
    shutil.copy(INNER, certs / "inner.py")
    os.chmod(str(certs / "inner.py"), 0o755)
    # The container case runs the check from the host: the inner worker's
    # arguments point at the container-internal ports; the ssh calls use
    # these values in the host namespace.


    if container_mode:
        # The container flow uses the Dockerfile image (mesh-init PID 1, the
        # packaged ssh-mesh defaults); the inner check runs inside the
        # container via the helper's `podman exec`, against the container's
        # own loopback ports. Same in-namespace flow as the bwrap case.
        helper = START_PODMAN
        extra = ["--engine", engine]
    else:
        helper = START_BWRAP
        extra = ["--user", user_spec] if user_spec else []

    # After `--` runs verbatim inside the namespace: no quoting/escaping of
    # the inner worker's arguments. --app-dir is omitted so the helper finds
    # the cargo release tree in target/ (or the installed /opt/ssh-mesh).
    argv = [
        "bash", str(helper),
        *extra,
        "--mount", f"{certs}:{CERTS_DIR_IN_NS}",
        "--mesh-init-config", str(mesh_init_etc),
        "--",
        "python3", str((pathlib.Path(CERTS_DIR_IN_NS) / "inner.py")),
        "--ssh-port", str(ssh_port),
        "--expected-uid", str(expected_uid),
    ]
    logging.info("%s: helper --exec inner", case)
    result = subprocess.run(
        argv, capture_output=True, text=True, timeout=120
    )
    if result.returncode != 0:
        logging.error("%s: helper exit code %s", case, result.returncode)
        if result.stdout:
            print(result.stdout)
        if result.stderr:
            print(result.stderr)
        return result.returncode or 1
    ok = result.returncode == 0 and result.stdout.count("PASS") >= 2
    return 0 if ok else (result.returncode or 3)


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--case", default="all", choices=("all", "root", "subuid", "podman"))
    parser.add_argument("--engine", default=os.environ.get("ENGINE", "podman"))
    return parser.parse_args()


def main():
    args = parse_args()
    cases = ["root", "subuid", "podman"] if args.case == "all" else [args.case]
    bin_dir = find_bin_dir(pathlib.Path)
    require_commands("bash", "ssh", "ssh-keygen", "bwrap")

    keep = os.environ.get("SSH_MESH_TEST_KEEP")
    # Keep all execution and temp files under target/tmp (repo-local), not /tmp.
    runtime_root = pathlib.Path(os.environ.get("TMPDIR", str(REPO_ROOT / "target/tmp")))
    runtime_root.mkdir(parents=True, exist_ok=True)
    scratch_root = pathlib.Path(tempfile.mkdtemp(
        prefix="ssh-mesh-cert-terminal-test.", dir=str(runtime_root),
    ))
    if keep:
        print(f"keeping scratch dir: {scratch_root}")
    else:
        atexit.register(shutil.rmtree, str(scratch_root), ignore_errors=True)

    # The subuid case requires a kernel/unshare that can map the /etc/subuid
    # range (setpriv to 100000..165535); if that is unavailable (namespaced
    # environments), only the mapped-root case runs. This keeps the CI safe
    # from regressions without gating the root-case assertion.
    if "subuid" in cases:
        result = subprocess.run(
            [
                "/usr/bin/unshare",
                "--user",
                "--map-auto",
                "--setuid", "0",
                "--setgid", "0",
                "--", "setpriv", "--reuid", str(SUBUID_REGULAR_UID),
                "--regid", str(SUBUID_REGULAR_UID),
                "--clear-groups", "--", "id", "-u",
            ],
            capture_output=True,
        )
        subuid_ready = result.returncode == 0
        if not subuid_ready:
            stderr = result.stderr.decode(errors="replace")
            print(
                "SKIP: subuid case unavailable in this environment "
                f"({stderr.strip().splitlines()[-1] if stderr.strip() else result.returncode})"
            )
            cases = [name for name in cases if name != "subuid"]

    failed = []
    for case_name in cases:
        scratch = scratch_root / case_name
        scratch.mkdir(parents=True, exist_ok=True)
        status = run_case(case_name, bin_dir, scratch, engine=args.engine)
        if status == 0:
            print(f"PASS: case {case_name}")
        else:
            failed.append(case_name)
    if failed:
        print(f"FAIL: cases {failed}")
        return 1
    if not cases:
        return 77
    print("all cert terminal cases passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
