#!/usr/bin/env python3
"""Regenerate the discovery family without regenerating unrelated platform APIs.

The full harness currently references the retired firmware abi/API.md transport
source. This subset generator consumes the same root API.md and mesh-api-gen;
it preserves other families until that separate transport migration is resolved.
"""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import sys

check = '--check' in sys.argv

def output(path, text):
    if check:
        if path.read_text() != text:
            raise SystemExit(f'{path} is stale; regenerate the discovery API')
    else:
        path.write_text(text)

root = Path(__file__).resolve().parent.parent
source = (root / 'API.md').read_text()
source = '# `discovery` API (6)' + source.split('# `discovery` API (6)', 1)[1].split('# `telemetry` API (7)', 1)[0]
generator = os.environ.get('DMESH_API_GEN')
if not generator:
    candidate = Path(os.environ.get('DMESH_SSH_MESH_DIR', '/ws/rust/ssh-mesh')) / 'target/x86_64-unknown-linux-musl/debug/mesh-api-gen'
    if candidate.is_file():
        generator = str(candidate)
if not generator:
    generator = shutil.which('mesh-api-gen')
if not generator:
    raise SystemExit('mesh-api-gen is required; source env.sh or set DMESH_API_GEN')
(root / 'target').mkdir(exist_ok=True)
with tempfile.TemporaryDirectory(dir=root / 'target', prefix='discovery-api-') as temp:
    directory = Path(temp)
    (directory / 'API.md').write_text(source)
    subprocess.run([generator, '--api', str(directory / 'API.md'), '--out-tools', str(directory / 'tools.json')],
                   check=True)
    generated = json.loads((directory / 'tools.json').read_text())
    by_name = {tool['name']: tool for tool in generated}
    for relative in ['crates/lmesh/resources/tools.json']:
        path = root / relative
        catalog = json.loads(path.read_text())
        tools = catalog['tools'] if isinstance(catalog, dict) else catalog
        for old in tools:
            if old['name'] in by_name:
                old.update(by_name[old['name']])
        output(path, json.dumps(catalog, indent=2) + '\n')
    cbor_args = [generator, '--api', str(directory / 'API.md'),
                 '--out-api-cbor-dir', str(root / 'android/app-dmesh/src/main/assets/schemas')]
    if check:
        cbor_args.insert(1, '--check')
    subprocess.run(cbor_args, check=True)
