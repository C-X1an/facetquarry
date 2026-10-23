"""Explicit publication allowlist and targeted secret/private-data checks.
A conservative heuristic, not a substitute for human review or a dedicated scanner.
"""
from __future__ import annotations
import json
import gzip
import io
from pathlib import Path
import re
import subprocess
from common import ROOT,source_hash
EXCLUDED={'.git','.cache','.local','__pycache__','bin'}

PATTERNS=[re.compile(rb'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----'),
          re.compile(rb'gh[pousr]_[A-Za-z0-9]{30,}'),re.compile(rb'AKIA[0-9A-Z]{16}'),
          re.compile(rb'sk-[A-Za-z0-9_-]{35,}')]
DENIED_PARTS={'private','research','control','.codex','raw','resume'}
ALLOWED_BINARY={'.gz'}

def problems(path:str,data:bytes)->list[str]:
    bad=[];parts=Path(path).parts
    if any(part.lower() in DENIED_PARTS for part in parts) or 'resume' in path.lower():bad.append('private path')
    if len(data)>2_000_000:bad.append('unreviewed oversized file')
    if Path(path).suffix in ALLOWED_BINARY:
        try:
            with gzip.GzipFile(fileobj=io.BytesIO(data)) as f: unpacked=f.read(8_000_001)
            if len(unpacked)>8_000_000:bad.append('compressed evidence exceeds review cap')
            elif any(p.search(unpacked) for p in PATTERNS):bad.append('credential pattern in compressed evidence')
        except (OSError, EOFError):bad.append('invalid compressed evidence')
    else:
        try:data.decode('utf-8')
        except UnicodeDecodeError:bad.append('unapproved binary')
        if any(p.search(data) for p in PATTERNS):bad.append('credential or private-data pattern')
    return bad

def main()->int:
    manifest=ROOT/'verification/public_allowlist.json'
    if not manifest.exists():print('FAIL: public allowlist missing');return 1
    allowed=set(json.loads(manifest.read_text())['files']);findings=[]
    files=[p for p in ROOT.rglob('*') if p.is_file() and not any(x in EXCLUDED for x in p.relative_to(ROOT).parts)]
    for p in files:
        rel=p.relative_to(ROOT).as_posix()
        if p.is_symlink():findings.append({'path':rel,'issue':'symlink not permitted'});continue
        if rel not in allowed:findings.append({'path':rel,'issue':'not explicitly allowlisted'})
        for problem in problems(rel,p.read_bytes()):findings.append({'path':rel,'issue':problem})
    for rel in allowed:
        if not (ROOT/rel).is_file():findings.append({'path':rel,'issue':'allowlisted file missing'})
    history='NOT RUN';checked=0
    r=subprocess.run(['git','rev-list','--objects','--all'],cwd=ROOT,text=True,capture_output=True)
    if r.returncode==0:
        history='PASS'
        for line in r.stdout.splitlines():
            fields=line.split(' ',1)
            if len(fields)!=2:continue
            oid,path=fields
            typ=subprocess.check_output(['git','cat-file','-t',oid],cwd=ROOT,text=True).strip()
            if typ!='blob':continue
            checked+=1
            if checked>10000:findings.append({'path':'history','issue':'history scan cap exceeded'});break
            size=int(subprocess.check_output(['git','cat-file','-s',oid],cwd=ROOT,text=True))
            if size>2_000_000:findings.append({'path':path,'issue':'oversized historical blob'});continue
            data=subprocess.check_output(['git','cat-file','blob',oid],cwd=ROOT)
            for problem in problems(path,data):findings.append({'path':path,'issue':'historical '+problem,'object':oid})
    report={'schema_version':1,'evidence_type':'export_audit','source':source_hash(),'allowlist_audited':True,'history_audited':history=='PASS','status':'FAIL' if findings else 'PASS','current_tree_files':len(files),'history_status':history,'history_blobs_checked':checked,'findings':findings,'scope':'explicit export paths and targeted heuristics; not a comprehensive secrets/security certification'}
    print(json.dumps(report,indent=2));return 1 if findings else 0
if __name__=='__main__':raise SystemExit(main())
