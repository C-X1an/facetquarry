"""Bounded mocked network controls; these do not claim live artifact transfer."""
import hashlib,io,json,os,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
from urllib.error import HTTPError
import download_reference as d

class Response(io.BytesIO):
    status=200

class DownloadControls(unittest.TestCase):
    def test_auth_is_used_only_on_fixed_github_requests(self):
        payload=b'original ZIP control';digest=hashlib.sha256(payload).hexdigest()
        metadata={'id':d.ARTIFACT,'size_in_bytes':len(payload),'expired':False,'digest':'sha256:'+digest,
            'workflow_run':{'id':d.RUN,'repository_id':d.REPOSITORY,'head_repository_id':d.REPOSITORY,'head_sha':d.HEAD}}
        calls=[]
        class Opener:
            def open(self,request,timeout):
                calls.append(request)
                if request.full_url==d.API:return Response(json.dumps(metadata).encode())
                if request.full_url==d.API+'/zip':
                    raise HTTPError(request.full_url,302,'redirect',{'Location':'https://own.blob.core.windows.net/artifact?sig=do-not-log'},None)
                self_test.assertEqual(request.full_url,'https://own.blob.core.windows.net/artifact?sig=do-not-log')
                self_test.assertNotIn('Authorization',dict(request.header_items()))
                return Response(payload)
        self_test=self
        with tempfile.TemporaryDirectory() as folder,patch.dict(os.environ,{'GH_TOKEN':'test-ephemeral','GITHUB_REPOSITORY':'C-X1an/facetquarry'}),\
            patch.object(d,'SIZE',len(payload)),patch.object(d,'SHA',digest),patch.object(d.urllib.request,'build_opener',return_value=Opener()):
            d.download(Path(folder))
            self.assertEqual((Path(folder)/'original.zip').read_bytes(),payload)
            self.assertNotIn('sig=',(Path(folder)/'original-artifact-metadata.json').read_text())
        self.assertEqual(len(calls),3)
        for request in calls[:2]:self.assertEqual(request.get_header('Authorization'),'Bearer test-ephemeral')

    def test_redirect_handler_disables_automatic_forwarding(self):
        self.assertIsNone(d.NoRedirect().redirect_request(None,None,302,'',{},'https://other.invalid'))

if __name__=='__main__':unittest.main(verbosity=2)
