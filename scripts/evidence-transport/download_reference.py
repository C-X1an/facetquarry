"""Fetch one frozen same-repository artifact, keeping API auth off redirects."""
import hashlib,json,os
from pathlib import Path
import sys
import urllib.error
import urllib.parse
import urllib.request

ARTIFACT=12519574083
RUN=39973710730
REPOSITORY=1430604581
HEAD='625582eb753e7bec76e057a8f368f62f6aaf3d1d'
SIZE=784433491
SHA='f3de649b5ac186c5514c46d84372fba67af4a1b65c7c44176c7e14286b1b86b8'
API=f'https://api.github.com/repos/C-X1an/facetquarry/actions/artifacts/{ARTIFACT}'

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,*args,**kwargs):return None

def require(ok,message):
    if not ok:raise ValueError(message)

def metadata_request(opener,url,token):
    request=urllib.request.Request(url,headers={'Authorization':'Bearer '+token,
        'Accept':'application/vnd.github+json','X-GitHub-Api-Version':'2022-11-28'})
    return opener.open(request,timeout=60)

def download(folder):
    token=os.environ.get('GH_TOKEN','');require(bool(token),'missing ephemeral Actions token')
    require(os.environ.get('GITHUB_REPOSITORY')=='C-X1an/facetquarry','unexpected repository runtime')
    require(folder.is_dir() and not (folder/'original.zip').exists(),'output is not fresh')
    opener=urllib.request.build_opener(NoRedirect())
    with metadata_request(opener,API,token) as response:
        raw=response.read(2_000_001);require(len(raw)<=2_000_000,'metadata admission exceeded')
    metadata=json.loads(raw);run=metadata['workflow_run']
    require(metadata['id']==ARTIFACT and metadata['size_in_bytes']==SIZE and not metadata['expired']
        and metadata['digest']=='sha256:'+SHA and run['id']==RUN and run['repository_id']==REPOSITORY
        and run['head_repository_id']==REPOSITORY and run['head_sha']==HEAD,'frozen artifact metadata mismatch')
    try:
        with metadata_request(opener,API+'/zip',token):raise ValueError('expected signed redirect')
    except urllib.error.HTTPError as error:
        require(error.code in (301,302,303,307,308),'artifact redirect request failed')
        location=error.headers.get('Location','')
    parsed=urllib.parse.urlsplit(location)
    require(parsed.scheme=='https' and parsed.hostname is not None and
        parsed.hostname.endswith('.blob.core.windows.net') and parsed.port in (None,443)
        and parsed.username is None and parsed.password is None and not parsed.fragment,'unexpected signed artifact destination')
    # Separate request/opener; no Authorization or GitHub cookie on storage.
    request=urllib.request.Request(location,headers={'Accept':'application/octet-stream'})
    count=0;digest=hashlib.sha256();partial=folder/'original.zip.partial'
    try:
        with opener.open(request,timeout=120) as response,partial.open('xb') as output:
            require(response.status==200,'unexpected storage response')
            while chunk:=response.read(1024*1024):
                count+=len(chunk);require(count<=SIZE,'artifact download exceeds frozen size')
                output.write(chunk);digest.update(chunk)
    except Exception as error:
        # Network error strings can contain the signed location: omit their text.
        raise RuntimeError('artifact transfer failed: '+type(error).__name__) from None
    require(count==SIZE and digest.hexdigest()==SHA,'artifact download size/SHA mismatch')
    partial.replace(folder/'original.zip')
    # API metadata is public; neither token nor signed URL is retained.
    (folder/'original-artifact-metadata.json').write_text(json.dumps(metadata,indent=2)+'\n')
    print(json.dumps({'status':'PASS','artifact_id':ARTIFACT,'run_id':RUN,'bytes':count,'sha256':SHA}))

if __name__=='__main__':download(Path(sys.argv[1]))
