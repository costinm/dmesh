#!/usr/bin/env python3
"""Regenerate the discovery family without regenerating unrelated platform APIs.

The full harness currently references the retired firmware abi/API.md transport
source. This subset generator consumes the same root API.md and mesh-api-gen;
it preserves other families until that separate transport migration is resolved.
"""
import json
import os
from pathlib import Path
import re
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
    subprocess.run([generator, '--api', str(directory / 'API.md'), '--out-tools', str(directory / 'tools.json'),
                    '--out-rust', str(directory / 'types.rs'), '--rust-tags'], check=True)
    generated = json.loads((directory / 'tools.json').read_text())
    by_name = {tool['name']: tool for tool in generated}
    for relative in ['crates/lmesh/resources/tools.json', 'crates/dmesh-server/platform/tools.json']:
        path = root / relative
        catalog = json.loads(path.read_text())
        tools = catalog['tools'] if isinstance(catalog, dict) else catalog
        for old in tools:
            if old['name'] in by_name:
                old.update(by_name[old['name']])
        output(path, json.dumps(catalog, indent=2) + '\n')
    # Generated request/response structs for this contiguous family are one
    # prefix in platform_api.rs; replace that generated family as a whole.
    path = root / 'crates/dmesh-server/src/platform_api.rs'
    old = path.read_text()
    new = (directory / 'types.rs').read_text()
    names = set(re.findall(r'pub struct (\w+)', new))
    matches = list(re.finditer(r'pub struct (\w+)', old))
    first = next(m.start() for m in matches if m[1] in names)
    following = next((m.start() for m in matches if m.start() > first and m[1] not in names), len(old))
    start = old.rfind('///', 0, first)
    end = old.rfind('///', first, following) if following < len(old) else following
    # Locate the first type's documentation before its derive attribute.
    new_first = re.search(r'pub struct (\w+)', new).start()
    new_start = new.rfind('///', 0, new_first)
    output(path, old[:start] + new[new_start:].rstrip() + '\n\n' + old[end:])
