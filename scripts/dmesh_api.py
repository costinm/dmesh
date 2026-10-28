#!/usr/bin/env python3
"""Extract a formal API section from the sole root API.md for mesh-api-gen."""
import sys
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

def read_api(path: str) -> str:
    source = (ROOT / path).read_text()
    marker = '<!-- xip-transport-schema -->'
    if marker in source:
        # The esp repo moved the consolidated `abi/API.md` (a C ABI document)
        # to per-component specs; the transport schema is now canonical at
        # `api/transport.API.md`, which starts with the same section heading.
        canonical = ROOT.parent / 'esp-xip-modules/api/transport.API.md'
        schema = canonical.read_text().split('# `transport` API (1)\n', 1)[1]
        source = source.replace(marker, '# `transport` API (1)\n' + schema)
    return source


# Groups documented outside the root API.md.
GROUP_FILES = {'linux': 'crates/lmesh-wifi/API.md'}


TIERS = ('core', 'debug', 'internal')


def section_platforms() -> dict[str, set[str]]:
    """`component.method` -> platform letters (A, L, E) of every section method."""
    platforms: dict[str, set[str]] = {}
    for path in ('API.md', 'crates/lmesh-wifi/API.md'):
        component = None
        method = None
        for line in read_api(path).split('\n'):
            heading = re.match(r'^# `(\w+)` API', line)
            if heading:
                component = heading.group(1)
            method_heading = re.match(r'^## \d+\. `([\w.]+)`', line)
            if method_heading:
                method = f'{component}.{method_heading.group(1)}'
            marker = re.match(r'^\*\*Platforms:\*\*\s+(.+)$', line)
            if marker and method:
                platforms[method] = set(marker.group(1).split())
                method = None
    return platforms


def private_methods() -> set[str]:
    """Section methods marked `**Visibility:** private`: never in a public catalog, so never CLI-addressable."""
    private: set[str] = set()
    for path in ('API.md', 'crates/lmesh-wifi/API.md'):
        component = None
        method = None
        for line in read_api(path).split('\n'):
            heading = re.match(r'^# `(\w+)` API', line)
            if heading:
                component = heading.group(1)
            method_heading = re.match(r'^## \d+\. `([\w.]+)`', line)
            if method_heading:
                method = f'{component}.{method_heading.group(1)}'
            if re.match(r'^\*\*Visibility:\*\*\s+private\s*$', line) and method:
                private.add(method)
    return private


def section_tiers() -> dict[str, str]:
    """`component.method` -> tier for every section method of the formal API documents."""
    tiers: dict[str, str] = {}
    for path in ('API.md', 'crates/lmesh-wifi/API.md'):
        source = read_api(path)
        component = None
        method = None
        for line in source.split('\n'):
            heading = re.match(r'^# `(\w+)` API', line)
            if heading:
                component = heading.group(1)
            method_heading = re.match(r'^## \d+\. `([\w.]+)`', line)
            if method_heading:
                method = f'{component}.{method_heading.group(1)}'
            marker = re.match(r'^\*\*Tier:\*\*\s+(\S+)\s*$', line)
            if marker and method:
                tiers[method] = marker.group(1)
                method = None
    return tiers


def check_tiers(group: str, body: str) -> None:
    """Every method of an API section carries `**Tier:** core|debug|internal`."""
    for block in re.split(r'(?=^#{1,2} )', body, flags=re.M):
        heading = re.match(r'^## (\d+)\. `([\w.]+)`', block)
        if heading is None:
            continue
        marker = re.search(r'^\*\*Tier:\*\*\s+(\S+)\s*$', block, re.M)
        if marker is None or marker.group(1) not in TIERS:
            raise ValueError(f'{group} method {heading.group(2)} needs **Tier:** {"|".join(TIERS)}')


def extract(group: str, platform: str | None = None) -> str:
    source = read_api(GROUP_FILES.get(group, 'API.md'))
    start = f'<!-- dmesh-api:{group} -->\n'
    if source.count(start) != 1:
        raise ValueError(f'expected one {group} API section')
    body = source.split(start, 1)[1].split('<!-- dmesh-api:end -->', 1)[0]
    check_tiers(group, body)
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
    source = read_api('API.md')
    section = source.split('## Additional device methods\n', 1)[1].split(
        '## Firmware module payload contracts', 1
    )[0]
    device = {tool['name']: tool for tool in catalog['tools'] if tool.get('x-dmesh-device')}
    method_rows = re.findall(r'^\| (\d+) \| (\d+) \| `([^`]+)` \| (.+) \| ([a-z]+) \|$', section, re.M)
    if not method_rows:
        raise ValueError('root API has no additional device methods')
    for component, method, name, _description, tier in method_rows:
        tool = device.get(name)
        if tool is None or (tool['x-component-index'], tool['x-method-index']) != (
            int(component), int(method)
        ):
            raise ValueError(f'root API tag mismatch for {name}')
        if tier not in TIERS or tool.get('x-tier') != tier:
            raise ValueError(f'root API tier of {name} is {tier}, catalog has {tool.get("x-tier")}')
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
