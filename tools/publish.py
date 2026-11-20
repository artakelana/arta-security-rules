"""Publish generated data only; no server credentials or arbitrary shell interpolation."""
from pathlib import Path
import os,json,urllib.request as ur,urllib.error,base64,re
repo=os.environ['REPOSITORY']
if repo!='artakelana/arta-security-rules':raise SystemExit('Unexpected repository')
token=os.environ['GH_TOKEN']
class NoRedirect(ur.HTTPRedirectHandler):
    def redirect_request(self,*args):return None
opener=ur.build_opener(NoRedirect)
dist=Path('dist');meta=json.loads((dist/'release.json').read_text())
if not re.fullmatch(r'rules-[0-9]{1,10}',meta['tag']):raise SystemExit('Invalid tag')
def api(path,method='GET',data=None,content_type='application/json'):
    if not path.startswith(('https://api.github.com/repos/'+repo+'/', 'https://uploads.github.com/repos/'+repo+'/')):raise SystemExit('Unexpected API destination')
    body=data if isinstance(data,bytes) else json.dumps(data).encode() if data is not None else None
    request=ur.Request(path,body,{'Authorization':'Bearer '+token,'Accept':'application/vnd.github+json','Content-Type':content_type,'X-GitHub-Api-Version':'2022-11-28'},method=method)
    with opener.open(request,timeout=30) as r:return json.load(r)
base='https://api.github.com/repos/'+repo+'/'
release=api(base+'releases','POST',{'tag_name':meta['tag'],'name':'Rules '+str(meta['sequence']),'body':'Signed data-only rules. '+str(meta['rules'])+' reviewed monitoring/mitigation rules. Scheduled publication may renew validity without adding new mitigations.','draft':True,'prerelease':False})
for name in ['stable.json','public-key.json']:
    api('https://uploads.github.com/repos/'+repo+'/releases/'+str(release['id'])+'/assets?name='+name,'POST',(dist/name).read_bytes(),'application/json')
api(base+'releases/'+str(release['id']),'PATCH',{'draft':False})
try:previous=api(base+'contents/channel/stable.json?ref=main')
except urllib.error.HTTPError as e:
    if e.code!=404:raise
    previous=None
if previous:
    old=json.loads(base64.b64decode(previous['content']));old_payload=json.loads(base64.b64decode(old['payload']))
    if int(old_payload['sequence'])>=int(meta['sequence']):raise SystemExit('Sequence is not newer; channel unchanged')
payload={'message':'Publish signed rule sequence '+str(meta['sequence']),'branch':'main','content':base64.b64encode((dist/'stable.json').read_bytes()).decode()}
if previous:payload['sha']=previous['sha']
api(base+'contents/channel/stable.json','PUT',payload)
print('Published signed release and stable channel.')
