#!/usr/bin/env python3
"""Fail closed on OSV advisories in Rust and hosted Dart lockfiles."""
import json,re,sys,tomllib,urllib.request
from pathlib import Path
root=Path(__file__).resolve().parent.parent
packages={}
for lock in ['Cargo.lock','signaling/Cargo.lock','relay/Cargo.lock']:
 for item in tomllib.loads((root/lock).read_text()).get('package',[]):
  if item.get('source','').startswith('registry+'):
   packages[('crates.io',item['name'],item['version'])]=True
name=None;source=None
for line in (root/'desktop/pubspec.lock').read_text().splitlines():
 match=re.match(r'^  ([a-zA-Z0-9_]+):$',line)
 if match:name=match[1];source=None
 elif line.startswith('    source: '):source=line.split(': ',1)[1]
 elif line.startswith('    version: ') and name and source=='hosted':
  packages[('Pub',name,line.split(': ',1)[1].strip('"'))]=True
items=sorted(packages)
request=urllib.request.Request('https://api.osv.dev/v1/querybatch',data=json.dumps({'queries':[{'package':{'ecosystem':e,'name':n},'version':v} for e,n,v in items]}).encode(),headers={'Content-Type':'application/json'})
with urllib.request.urlopen(request,timeout=60) as response:result=json.load(response)
assert len(result['results'])==len(items),'Incomplete OSV response'
# These notices describe maintenance status, not a security vulnerability.
# They apply to the optional unsupported legacy Rust media client only.
notices={'RUSTSEC-2026-0150':'audiopus_sys is unmaintained','RUSTSEC-2024-0436':'paste is unmaintained'}
failures=[];findings=[]
for item,result in zip(items,result['results']):
 for vuln in result.get('vulns',[]):
  record={'package':item,'advisory':vuln['id'],'notice':notices.get(vuln['id'])}
  findings.append(record)
  if vuln['id'] not in notices:failures.append(record)
print(json.dumps({'packages_scanned':len(items),'findings':findings,'unmitigated':failures},indent=2))
if failures:sys.exit(1)
