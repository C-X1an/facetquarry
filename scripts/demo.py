"""Generate a script-free offline report from real executable outputs."""
from __future__ import annotations
import html
import json
from pathlib import Path
from common import ROOT,run,source_hash

def main():
    folder=ROOT/'.local/demo';folder.mkdir(parents=True,exist_ok=True)
    snapshot=folder/'index.fq';snapshot.unlink(missing_ok=True)
    binary=str(ROOT/'bin/facetquarry')
    build=run([binary,'build','--input','examples/corpus.json','--output',str(snapshot)])
    base=json.loads((ROOT/'examples/query.json').read_text());cases=[]
    variants=[('Allowed exact fallback',{}),('Original graph search',{'mode':'graph'}),
              ('Postfilter baseline',{'mode':'postfilter'}),('Zero distance budget',{'budget':0}),
              ('Client tenant override denied',{'tenant':'beta'}),
              ('Untrusted text remains text',{'filter':{'kind':'<script>alert(1)</script>'}})]
    for i,(label,patch) in enumerate(variants):
        q={**base,**patch};file=folder/f'query-{i}.json';file.write_text(json.dumps(q))
        command=[binary,'search','--index',str(snapshot),'--tenant','alpha','--query',str(file)]
        r=run(command,check=False)
        cases.append({'label':label,'input':q,'exit_code':r.returncode,
                      'result':json.loads(r.stdout) if r.stdout else None,
                      'error':json.loads(r.stderr) if r.stderr else None})
    if cases[0]['result']['hits'][0]['id']!='a1' or cases[3]['result']['status']!='budget_exhausted' or cases[4]['exit_code']!=2:
        raise AssertionError('real demo expectations failed')
    data={'source':source_hash(),'dataset':'synthetic, four records in two tenants',
          'build':json.loads(build.stdout),'cases':cases,'browser_review':'NOT RUN'}
    (folder/'trace.json').write_text(json.dumps(data,indent=2)+'\n')
    escape=lambda x:html.escape(json.dumps(x,indent=2,ensure_ascii=True))
    sections=''.join('<section><h2>'+html.escape(c['label'])+'</h2><p>Actual process exit: '+str(c['exit_code'])+'</p><details><summary>Input contract</summary><pre>'+escape(c['input'])+'</pre></details><pre>'+escape(c['result'] or c['error'])+'</pre></section>' for c in cases)
    page='''<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'"><title>FacetQuarry | execution inspector</title><style>body{font:17px/1.6 system-ui,sans-serif;max-width:960px;margin:3rem auto;padding:0 1.5rem}h1{font-size:2.8rem;line-height:1.1}section{border-top:1px solid;padding:1.5rem 0}pre{overflow:auto;padding:1rem;border:1px solid;border-radius:.5rem;font:14px/1.5 monospace}summary{cursor:pointer;padding:.5rem}a:focus,summary:focus{outline:3px solid;outline-offset:3px}small{overflow-wrap:anywhere}</style><header><p>FACETQUARRY / ENGINEERING INSPECTOR</p><h1>Search quality is a tradeoff.<br>Authority is not.</h1><p>Real Go executable outputs over a tiny synthetic corpus. Not a production benchmark or browser-test certification.</p><small>Technical source: '''+html.escape(data['source'])+'''</small></header><main>'''+sections+'''</main><footer><p>No scripts, remote assets, telemetry or model APIs. Full acceptance and independent review remain separate gates.</p></footer></html>'''
    (folder/'report.html').write_text(page)
    if '<script>' in page or 'src="http' in page:raise AssertionError('unsafe report content')
    print(json.dumps({'status':'PASS','report':str((folder/'report.html').relative_to(ROOT)),
                      'cases':len(cases),'scope':'real execution and HTML escaping; visual/browser review NOT RUN'}))
if __name__=='__main__':main()
