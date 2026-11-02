#!/usr/bin/env python3
"""Query OSV for pinned Rust/Dart dependencies; never reads credentials.

Default exit status reflects only the deployed signaling and Flutter clients.
The optional UDP client is reported separately because it is a different product.
Requires Python 3.11+. Run npm audit separately for the browser test tooling.
"""
import json
import pathlib
import re
import tomllib
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parent.parent
queries = {}
for name in ['signaling/Cargo.lock', 'Cargo.lock', 'relay/Cargo.lock']:
    for p in tomllib.loads((ROOT / name).read_text())['package']:
        if p.get('source', '').startswith('registry'):
            queries.setdefault(('crates.io', p['name'], p['version']), []).append(name)
text = (ROOT / 'desktop/pubspec.lock').read_text()
for m in re.finditer(r'^  (\w+):\n(.*?)(?=^  \w+:|^sdks:)', text, re.M | re.S):
    if 'source: hosted' in m[2]:
        version = re.search(r'    version: "([^"]+)"', m[2])[1]
        queries.setdefault(('Pub', m[1], version), []).append('desktop/pubspec.lock')
items = list(queries)
result = []
for start in range(0, len(items), 100):
    batch = items[start:start + 100]
    data = {'queries': [{'package': {'ecosystem': k[0], 'name': k[1]}, 'version': k[2]} for k in batch]}
    request = urllib.request.Request('https://api.osv.dev/v1/querybatch', data=json.dumps(data).encode(), headers={'Content-Type': 'application/json'})
    with urllib.request.urlopen(request, timeout=45) as response:
        result.extend(json.load(response)['results'])
findings = [{'ecosystem': k[0], 'package': k[1], 'version': k[2], 'locks': queries[k], 'advisories': v['vulns']} for k, v in zip(items, result) if v.get('vulns')]
modern = [f for f in findings if any(p in ['signaling/Cargo.lock', 'desktop/pubspec.lock'] for p in f['locks'])]
print(json.dumps({'source': 'https://osv.dev', 'packages_scanned': len(items), 'modern_client_findings': modern, 'legacy_findings': [f for f in findings if f not in modern], 'limitations': 'Registry advisories exclude bundled native libraries, OS packages, and SDK/build-tool advisories; review those separately.'}, indent=2))
raise SystemExit(bool(modern))
