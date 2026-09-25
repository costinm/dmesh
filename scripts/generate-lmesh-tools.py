#!/usr/bin/env python3
"""Compose the one installed catalog from device entries and Linux handler API."""
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from dmesh_api import check_additional_device_methods, extract

root = Path(__file__).resolve().parent.parent
path = root / 'crates/lmesh/resources/tools.json'
catalog = json.loads(path.read_text())
check_additional_device_methods(catalog)
if '--local-tools' in sys.argv:
    local_path = Path(sys.argv[sys.argv.index('--local-tools') + 1])
    local = json.loads(local_path.read_text())
else:
    upstream = Path(os.environ.get('DMESH_SSH_MESH_DIR', '/ws/rust/ssh-mesh'))
    with tempfile.NamedTemporaryFile(suffix='.json') as output:
        with tempfile.NamedTemporaryFile(suffix='.md') as api:
            Path(api.name).write_text(extract('portable') + '\n' + extract('linux'))
            upstream_env = os.environ.copy()
            upstream_env.pop('CARGO_TARGET_DIR', None)
            subprocess.run([
                'cargo', 'run', '-p', 'mesh-api-gen', '--',
                '--api', api.name, '--out-tools', output.name,
            ], cwd=upstream, env=upstream_env, check=True)
        local = json.loads(Path(output.name).read_text())
device = [tool for tool in catalog['tools'] if tool.get('x-dmesh-device')]
seen = {tool['name'] for tool in device}
catalog['tools'] = device + [tool for tool in local if tool['name'] not in seen]
generated = json.dumps(catalog, indent=2) + '\n'
if '--check' in sys.argv:
    if path.read_text() != generated:
        raise SystemExit(f'{path} is stale; run scripts/generate-lmesh-tools.py')
else:
    path.write_text(generated)
