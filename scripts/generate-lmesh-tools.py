#!/usr/bin/env python3
"""Compose the one installed catalog from device entries and Linux handler API."""
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from dmesh_api import TIERS, check_additional_device_methods, extract, private_methods, section_platforms, section_tiers

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
            Path(api.name).write_text(
                extract('portable', 'L') + '\n' + extract('linux')
            )
            upstream_env = os.environ.copy()
            upstream_env.pop('CARGO_TARGET_DIR', None)
            subprocess.run([
                'cargo', 'run', '-p', 'mesh-api-gen', '--',
                '--api', api.name, '--out-tools', output.name,
            ], cwd=upstream, env=upstream_env, check=True)
        local = json.loads(Path(output.name).read_text())
device = [tool for tool in catalog['tools'] if tool.get('x-dmesh-device')]
seen = {tool['name'] for tool in device}
# A device entry keeps its hand-maintained check flags, but its response schema
# comes from the API.md table so the UI and CLI name the response tags.
generated = {tool['name']: tool for tool in local}
# Methods that only a device registers are not in the Linux catalog above, so
# take their schemas from every portable method.
if '--local-tools' not in sys.argv:
    with tempfile.NamedTemporaryFile(suffix='.json') as output:
        with tempfile.NamedTemporaryFile(suffix='.md') as api:
            Path(api.name).write_text(extract('portable'))
            upstream_env = os.environ.copy()
            upstream_env.pop('CARGO_TARGET_DIR', None)
            subprocess.run([
                'cargo', 'run', '-p', 'mesh-api-gen', '--',
                '--api', api.name, '--out-tools', output.name,
            ], cwd=upstream, env=upstream_env, check=True)
        for tool in json.loads(Path(output.name).read_text()):
            generated.setdefault(tool['name'], tool)
for tool in device:
    source = generated.get(tool['name'], {})
    schema = source.get('outputSchema', {})
    if schema.get('properties'):
        tool['outputSchema'] = schema
    # Probe's portable API tables own both schemas. Older device methods keep
    # their hand-checked request tables until migrated to the same model.
    request = source.get('inputSchema', {})
    if request.get('properties') and (
        tool['name'] in ('probe.start', 'probe.handler', 'transport.set')
        or not tool['inputSchema'].get('properties')
    ):
        tool['inputSchema'] = request
catalog['tools'] = device + [tool for tool in local if tool['name'] not in seen]
# A section method that firmware (E) registers is addressable by the CLI: it is a device method
# whether or not its entry was written by hand, so the catalog flag follows the Platforms line.
by_name = {tool['name']: tool for tool in catalog['tools']}
for name, platforms in section_platforms().items():
    if 'E' not in platforms or name in private_methods():
        continue
    tool = by_name.get(name) or dict(generated.get(name) or {})
    if not tool:
        raise SystemExit(f'{name} is an E method with no generated schema')
    if name not in by_name:
        catalog['tools'].append(tool)
        by_name[name] = tool
    tool['x-dmesh-device'] = True
    tool.setdefault('x-ui-visibility', 'advanced')
    tool.setdefault('x-check-all', None)
    tool.setdefault('x-check-all-platforms', None)
# The tier of a section method is its `**Tier:**` line in the formal API document; a table-only
# device method keeps the tier of its hand-written entry (check_additional_device_methods compares
# it with the API.md table). Every tool must end up with one.
tiers = section_tiers()
for tool in catalog['tools']:
    if tool['name'] in tiers:
        tool['x-tier'] = tiers[tool['name']]
    if tool.get('x-tier') not in TIERS:
        raise SystemExit(f"{tool['name']} has no tier: add **Tier:** to its API.md section or a Tier column entry")
generated = json.dumps(catalog, indent=2) + '\n'
if '--check' in sys.argv:
    if path.read_text() != generated:
        raise SystemExit(f'{path} is stale; run scripts/generate-lmesh-tools.py')
else:
    path.write_text(generated)
