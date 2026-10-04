#!/usr/bin/env python3
"""Extract a formal API section from the sole root API.md for mesh-api-gen."""
import sys
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# Groups documented outside the root API.md.
GROUP_FILES = {'linux': 'crates/lmesh-wifi/API.md'}


def extract(group: str, platform: str | None = None) -> str:
    source = (ROOT / GROUP_FILES.get(group, 'API.md')).read_text()
    start = f'<!-- dmesh-api:{group} -->\n'
    if source.count(start) != 1:
        raise ValueError(f'expected one {group} API section')
    body = source.split(start, 1)[1].split('<!-- dmesh-api:end -->', 1)[0]
    if platform is not None:
        methods = re.split(r'(?=^#{1,2} )', body, flags=re.M)
        kept = []
        for block in methods:
            if not re.match(r'^## \d+\. ', block):
                kept.append(block)
                continue
            marker = re.search(r'^\*\*Platforms:\*\*\s+(.+)$', block, re.M)
            if marker is None:
                raise ValueError('API method is missing its Platforms marker')
            if platform in marker.group(1).split():
                kept.append(block)
        body = ''.join(kept)
    return body.strip() + '\n'

def check_additional_device_methods(catalog: dict) -> None:
    """Check the root API tables that mesh-api-gen cannot name directly."""
    source = (ROOT / 'API.md').read_text()
    section = source.split('## Additional device methods\n', 1)[1].split(
        '## Firmware module payload contracts', 1
    )[0]
    device = {tool['name']: tool for tool in catalog['tools'] if tool.get('x-dmesh-device')}
    method_rows = re.findall(r'^\| (\d+) \| (\d+) \| `([^`]+)` \| (.+) \|$', section, re.M)
    if not method_rows:
        raise ValueError('root API has no additional device methods')
    for component, method, name, _description in method_rows:
        tool = device.get(name)
        if tool is None or (tool['x-component-index'], tool['x-method-index']) != (
            int(component), int(method)
        ):
            raise ValueError(f'root API tag mismatch for {name}')
    for name, block in re.findall(
        r'^### `([^`]+)` request fields\n(.*?)(?=^### |\Z)', section, re.M | re.S
    ):
        tool = device.get(name)
        if tool is None:
            raise ValueError(f'root API has unknown request {name}')
        expected = {
            field: prop['x-protobuf-index']
            for field, prop in tool['inputSchema']['properties'].items()
        }
        rows = re.findall(
            r'^\| (\d+) \| `([^`]+)` \| `([^`]+)` \| (.+) \|$', block, re.M
        )
        actual = {field: int(tag) for tag, field, _kind, _values in rows}
        if actual != expected:
            raise ValueError(f'root API field tags differ for {name}')
        for _tag, field, kind, values in rows:
            prop = tool['inputSchema']['properties'][field]
            if kind != prop.get('x-dmesh-kind', prop.get('type', 'value')):
                raise ValueError(f'root API field type differs for {name}.{field}')
            expected_values = ', '.join(
                f'{key}={value}' for key, value in prop.get('x-dmesh-values', {}).items()
            ) or '—'
            if values != expected_values:
                raise ValueError(f'root API field values differ for {name}.{field}')

if __name__ == '__main__':
    if len(sys.argv) not in (3, 4):
        raise SystemExit('usage: scripts/dmesh_api.py GROUP OUTPUT [PLATFORM]')
    platform = sys.argv[3] if len(sys.argv) == 4 else None
    Path(sys.argv[2]).write_text(
        '\n'.join(extract(group, platform) for group in sys.argv[1].split('+'))
    )
