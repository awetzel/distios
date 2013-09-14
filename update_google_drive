#!/usr/bin/env python3.3

# plist nano lib
import xml.etree.ElementTree as ET
from itertools import zip_longest,groupby
import re
plistheader = b'<?xml version="1.0" encoding="UTF-8" ?>\n<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n'
def dict2plist(plistdict,bytesio):
    def int2et(i,parent): parent.tag="integer"; parent.text = str(i)
    def date2et(d,parent): parent.tag="date"; parent.text = d.isoformat()
    def str2et(s,parent): parent.tag="string"; parent.text = str(s)
    def bool2et(b,parent): parent.tag="true" if b else "false"
    def arr2et(lst,parent): parent.tag="array";[xmlAdaptDict[type(value).__name__](value,ET.SubElement(parent,'noname')) for value in lst]
    def dict2et(dic,parent): 
        parent.tag="dict"
        for key,value in dic.items():
            ET.SubElement(parent,'key').text = key
            xmlAdaptDict[type(value).__name__](value,ET.SubElement(parent,'noname'))
    xmlAdaptDict = {'dict':dict2et,'list':arr2et,'str':str2et,'bool':bool2et,'datetime.datetime':date2et,'int':int2et}
    bytesio.write(plistheader+b'<plist version="1.0">\n')
    root = ET.Element('root');dict2et(plistdict,root)
    ET.ElementTree(root).write(bytesio, 'utf-8')
    bytesio.write(b'\n</plist>')
import datetime
import base64
def plist2dict(bytesio):
    def et2int(e): return int(e.text)
    def et2data(e): return base64.b64decode(e.text.encode('ascii'))
    def et2date(e): return datetime.datetime(*map(int, re.split('[^\d]', e.text)[:-1]))
    def et2str(e): return str(e.text)
    def et2arr(e): return [xmlAdaptDict[v.tag](v) for v in e]
    def et2dict(e): return dict((k.text,xmlAdaptDict[v.tag](v)) for (k,v) in zip_longest(*([iter(e)]*2)))
    xmlAdaptDict = {'integer':et2int,'data':et2data,'dict':et2dict,'array':et2arr,'string':et2str,'false':lambda x:False,'true':lambda x:True,'date':et2date}
    return et2dict(ET.parse(bytesio).getroot().find('dict'))

#Config loading: script depends on a distribute.plist configuration file and index.tpl layout
from os import path,mkdir,chdir
chdir(path.dirname(path.realpath(__file__)))
config = plist2dict('distribute.plist')

layout = open('index.tpl','r').read()
#update config to create repo (identified by repo name) and profile (identified by bundle id) dependencies
proj_by_repo = {}
for p in config['projects']: p['reponame'] = re.search(r'([^\/\.]*)/?(\.git)?$',p['repo']).group(1)
for k,g in groupby(config['projects'],lambda x: x['reponame']): proj_by_repo[k]=list(g)

## Google Api nano lib
import json
from urllib import parse
from urllib.request import urlopen,Request
from urllib.error import HTTPError
oauth_url = 'https://accounts.google.com/o/oauth2/auth?approval_prompt=force&response_type=code&redirect_uri={redir}&client_id={client_id}&scope={scope}'
token_url = 'https://accounts.google.com/o/oauth2/token'
token = 'none'
def get_token(client_id,client_secret,code,redirect):
    global token; token = json.loads(urlopen(token_url,parse.urlencode(
        {'redirect_uri':redirect,'grant_type':'authorization_code','client_id':client_id,'code':code,'client_secret':client_secret}
    ).encode('utf8')).read().decode('utf8'))['access_token']
def gapi_req(url,**urlparams): return Request(url.format(**urlparams),headers={'Authorization':'Bearer {}'.format(token)})
def gapi_get(url,**urlparams): return json.loads(urlopen(gapi_req(url,**urlparams)).read().decode('utf8'))

## Google drive API nano lib
needed_scopes = ['https://www.googleapis.com/auth/drive','https://spreadsheets.google.com/feeds']
filemeta_url = "https://www.googleapis.com/drive/v2/files/{file_id}"
newmedia_url = "https://www.googleapis.com/upload/drive/v2/files?uploadType=multipart"
filemedia_url = "https://www.googleapis.com/upload/drive/v2/files/{file_id}?uploadType=multipart"
filechildren_url = "https://www.googleapis.com/drive/v2/files/{file_id}/children"
export_url = "https://googledrive.com/host/{folder_id}/{file}"
spreadsheet_url = "https://spreadsheets.google.com/feeds/list/{spreadsheet_id}/private/full?alt=json"
def upload_req(req,method,f,**metadata):
    boundary = "==paozieurychslemf="
    req.method = method
    req.add_header('Content-Type','multipart/related; boundary="{boundary}"'.format(boundary=boundary))
    head = "--{boundary}\nContent-Type: application/json\n\n{metadatas}\n--{boundary}\nContent-Type: application/octet-stream\n\n".format(boundary=boundary,metadatas=json.dumps(metadata))
    tail = "\n--{boundary}--".format(boundary=boundary)
    req.data = head.encode('utf-8') + open(f,'rb').read() + tail.encode('utf-8')
    return req
def update_content(fileid,f,**metadata): urlopen(upload_req(gapi_req(filemedia_url,file_id=fileid),'PUT',f,**metadata))
def new_content(f,**metadata): urlopen(upload_req(gapi_req(newmedia_url),'POST',f,**metadata))

## openssl nano lib
def extract_cert(certbinary,type='DER'):
    p=Popen(["openssl","x509","-inform",type,"-subject","-fingerprint","-checkend","0","-noout"],stdout=PIPE,stdin=PIPE)
    cert=p.communicate(input=certbinary)[0]
    fingerprint = re.findall(b'(?:[0-9A-F]{2}:)+[0-9A-F]{2}',cert)[0].replace(b':',b'')
    return (re.search(b'CN=([^=]*)/..?=',cert).group(1),fingerprint,p.returncode != 0)

## apple security nanolib
from os import getcwd
def check_keychain(cn,fingerprint):
    with Popen(["security","find-certificate","-c",cn,'-Z',getcwd()+'/distribute.keychain'],stdout=PIPE) as proc:
        cert_present = fingerprint in proc.stdout.read()[0:200]
    with Popen(["security","find-identity",getcwd()+'/distribute.keychain'],stdout=PIPE) as proc:
        identity_present = fingerprint in proc.stdout.read()
    with Popen(["security","find-identity","-v",getcwd()+'/distribute.keychain'],stdout=PIPE) as proc:
        identity_valid = fingerprint in proc.stdout.read()
    return (cert_present,identity_present,identity_valid)

## Apple specific mime types for distributing apps with ipa/plist
import mimetypes
mimetypes.init()
def mimetype(f): return "text/xml" if f.endswith('.plist') else mimetypes.types_map.get(path.splitext(f)[1],'application/octet-stream')

## Steps are triggered into a webserver, define UI
section = """<section>
            <img src="{img_url}">
            <h2>{name}</h2>
            <div class="reason">{reason}</div><div class="action">{action}</div>
        </section>"""
needprofile = """<form enctype="multipart/form-data" action="/profile?target={target}" method="post">
    <a href="https://developer.apple.com/account/ios/profile/profileList.action?type=production">Create one here</a>
    <input type="file" name="profile">
    <button type="submit">Set this new profile</button>
</form>"""
missudids=('missing {num} serial numbers, go at <a href="https://developer.apple.com/account/ios/device/deviceCreate.action">'
           'provisionning portal</a> and post file <a href="/missing.deviceids?target={target}">of missing devices</a>')
needrepo = '<form action="/repo?target={target}" method="post"><button type="submit">Sync code</button></form>'
needcompile = '<form action="/build?target={target}" method="post"><button type="submit">Build Application</button></form>'
needpackage = '<form action="/package?target={target}" method="post"><button type="submit">Generate package</button></form>'
needdistribute = """<div class="global"><form action="/distribute" method="post"><button type="submit">Upload to google drive</button></form>
<p><strong>modified files :</strong> {changed}, <strong>new files :</strong> {new}.</p> </div>"""
dlpackage = '<a href="itms-services://?action=download-manifest&url={manifest_url}"><button type="submit">Install the app</button></a>'

# define backend files
if not path.exists('build'): mkdir('build')
appnametpl = "build/{target}.app"
repotpl = "build/{reponame}-repo"
logtpl = "build/{target}-app.log"
logipatpl = "build/{target}-ipa.log"
profiletpl = "build/{target}.mobileprovision"
ipatpl = "{target}.ipa"
plisttpl = "{target}-distribute.plist"
imagetpl = "{target}.png"
def pname(type,proj): return type.format(target=proj['target'])
def repname(proj): return repotpl.format(reponame=proj['reponame'])

#define project resource state
import sys
from os import stat
from multiprocessing import Pool,Array
# multiprocess requests to drive/spreadsheets to list upload files and valid udids
def get_deps(dep):
    if dep == 'udids':
        return dict((entry['gsx$'+config['spreadfield_udid']]['$t'],entry['gsx$'+config['spreadfield_desc']]['$t'])
                  for entry in gapi_get(spreadsheet_url,spreadsheet_id=config['spreadsheet_id'])['feed']['entry']
                      if entry['gsx$valid']['$t']=='TRUE')
    else:
        return gapi_get(filechildren_url,file_id=config['folder_id'])['items']
def globalstate():
    g = {} #retreive infos from google doc backend
    with Pool(processes=8) as pool:
        g['udids'],children = pool.map(get_deps,['udids','children'])
        g['gfiles'] =dict((item['title'],item) for item in pool.map(gapi_get,[i['childLink'] for i in children]) if not item['labels']['trashed'])
    g['to_update'] = [f for f in glob('*') if f in g['gfiles'] and stat(f).st_size != int(g['gfiles'][f]['fileSize'])]
    g['to_create'] = [f for f in glob('*') if f not in g['gfiles'] 
           and f not in sys.argv[0] and f != 'build' and f != 'distribute.keychain' and f != 'distribute.plist' and f != 'index.tpl' and f != 'sign.sh']
    if not g['to_update'] and not g['to_create']: g['action'] = '<div class="global"><p>google drive synced</p></div>'
    else: g['action'] = needdistribute.format(changed=','.join(g['to_update'])if g['to_update'] else 'none',new=','.join(g['to_create']) if g['to_create'] else 'none')
    return g
def projectstate(target,g):
    proj = next(p for p in config['projects'] if p['target']==target)
    proj['img_url'] = pname(imagetpl,proj) if path.exists(pname(imagetpl,proj)) else ''
    proj['valid'] = False
    if not path.exists(repname(proj)):
        proj['reason'] = 'currently no code repository sync'
        proj['action'] = needrepo.format(target=proj['target'])
    elif not repo_up2date(proj):
        proj['reason'] = 'code repository is out of sync'
        proj['action'] = needrepo.format(target=proj['target'])
    elif not path.exists(pname(appnametpl,proj)):
        proj['reason'] = 'no application found '+', build failed (see build.log)'if path.exists(pname(logtpl,proj)) else ''
        proj['action'] = needcompile.format(target=proj['target'])
    else:
        with Popen(["plutil","-convert","xml1",pname(appnametpl,proj)+'/Info.plist',"-o",'-'],stdout=PIPE) as proc:
            proj['app'] = plist2dict(proc.stdout)
        if not path.exists(pname(imagetpl,proj)): # use sips to convert application icon application icns png to valid png
            call(['sips','-s','format','png',pname(appnametpl,proj)+'/'+proj['app']['CFBundleIconFiles'][0],'--out',pname(imagetpl,proj)])
        if not path.exists(pname(profiletpl,proj)):
            proj['reason'] = "No provisionning profile found"
            proj['action'] = needprofile.format(target=proj['target'])
        else:
            with open(pname(profiletpl,proj),'rb') as f: proj['profile'] = plist2dict(BytesIO(plistheader+re.search(b'<plist.*</plist>',f.read(),re.S).group(0)))
            proj['missing_udids'] = dict((udid,name) for (udid,name) in g['udids'].items() if udid not in proj['profile']['ProvisionedDevices'])
            proj['valid_udids'] = dict((udid,name) for (udid,name) in g['udids'].items() if udid in proj['profile']['ProvisionedDevices'])
            if  not proj['profile']['Entitlements']['application-identifier'].endswith(proj['app']['CFBundleIdentifier']):
                proj['reason'] = "Profile and App don't match {} not in {}".format(proj['app']['CFBundleIdentifier'],proj['profile']['Entitlements']['application-identifier'])
                proj['action'] = needprofile.format(target=proj['target'])
            elif proj['missing_udids']:
                proj['reason'] = missudids.format(num=len(proj['missing_udids']),target=proj['target'])
                proj['action'] = needprofile.format(target=proj['target'])
            elif proj['profile']['ExpirationDate'] < datetime.datetime.now():
                proj['reason'] = 'The profile has expired, please renew one'
                proj['action'] = needprofile.format(target=proj['target'])
            elif not path.exists(pname(ipatpl,proj)):
                proj['cert_id'],proj['cert_fingerpring'],proj['cert_expired']=extract_cert(proj['profile']['DeveloperCertificates'][0])
                proj['cert_present'],proj['identity_present'],proj['identity_valid'] = check_keychain(proj['cert_id'].decode('ascii'),proj['cert_fingerpring'])
                if not proj['cert_present']:
                    proj['reason'] = 'You do not have any certificate for {certid}'.format(certid=proj['cert_id'])
                    proj['action'] = 'create a new privatekey and signin request from <a href="/keychain">distribute.keychain</a>'
                elif not proj['identity_present']:
                    proj['reason'] = 'You have the correct certificate, but associated private key is missing, get it from the certificate creator'
                    proj['action'] = 'Check <a href="/keychain">distribute.keychain</a>'
                elif proj['cert_expired']:
                    proj['reason']=('The key is there but its certificate is now expired, recreate one from this key : '
                    'right click on the key -> generate signin request file -> go <a href="https://developer.apple.com/account/ios/certificate/certificateList.action?type=distribution">there</a>'
                    ' and generate a new certificate and new profile')
                    proj['action'] = 'Check <a href="/keychain">distribute.keychain</a>'
                elif not proj['identity_valid']:
                    proj['reason']='identity invalid for unknown reason'
                    proj['action'] = 'Please check <a href="/keychain">distribute.keychain</a>, and recreate all certificates and profiles if necessary'
                else:
                    proj['reason'] = 'no package found'+', build failed (see build.log)'if path.exists(pname(logipatpl,proj)) else ''
                    proj['action'] = needpackage.format(target=proj['target'])
            else:
                proj['valid'] = True
                proj['reason'] = 'Package ready for {num} devices, created at {date}'.format(num=len(proj['valid_udids']),date='')
                proj['action'] = dlpackage.format(manifest_url=export_url.format(folder_id=config['folder_id'],file=pname(plisttpl,proj)))
    return proj

from subprocess import Popen,PIPE,STDOUT
from os import remove,rename
from shutil import copyfile,rmtree
def repo_up2date(proj):
    Popen(["git","fetch"],cwd=repname(proj)).communicate()
    return (Popen(["git","rev-parse",proj['branch']],cwd=repname(proj),stdout=PIPE).communicate()
     == Popen(["git","rev-parse","origin/"+proj['branch']],cwd=repname(proj),stdout=PIPE).communicate())
def proc_repo(proj): 
    for p in proj_by_repo[proj['reponame']]: 
        if path.exists(pname(appnametpl,p)): rmtree(pname(appnametpl,p))
        if path.exists(pname(ipatpl,p)): remove(pname(ipatpl,p))
    if not path.exists(repname(proj)):
        with Popen(["git","clone","-b",proj['branch'],proj['repo'],repname(proj)],stdout=PIPE) as proc:
            log = proc.stdout.read()
            if proc.returncode != 0:
                with open(pname(logtpl,proj),'wb') as f: f.write(log)
    else:
        with Popen(["git","pull","origin",proj['branch']],cwd=repname(proj),stdout=PIPE) as proc:
            log = proc.stdout.read()
            if proc.returncode != 0:
                with open(pname(logtpl,proj),'wb') as f: f.write(log)
def proc_application(proj): 
    if path.exists(pname(logtpl,proj)): remove(pname(logtpl,proj))
    with Popen(["xcodebuild","-target",proj['target'],"-configuration",proj['conf'],"-sdk",proj['sdk'],"clean","build"],cwd=repname(proj),stdout=PIPE) as proc:
        log = proc.stdout.read()
        if b"** BUILD SUCCEEDED **" not in log[-300:]:
            with open(pname(logtpl,proj),'wb') as f: 
                f.write(log)
        else:
            rename('{}/build/{}-iphoneos/{}.app'.format(repname(proj),proj['conf'],proj['target']),pname(appnametpl,proj))
def proc_package(proj):
    if path.exists(pname(logipatpl,proj)): remove(pname(logipatpl,proj))
    with Popen(["./sign.sh",getcwd()+'/distribute.keychain',proj['cert_fingerpring'],pname(profiletpl,proj),pname(appnametpl,proj),getcwd()+'/'+pname(ipatpl,proj)],stdout=PIPE,stderr=STDOUT) as proc:
        if proc.returncode != 0:
            with open(pname(logipatpl,proj),'wb') as f: f.write(proc.stdout.read())
        else:
            with open(pname(plisttpl,proj),'wb') as f:
                dict2plist({'items':[{ 'assets':[
                       {'kind':'software-package','url':export_url.format(folder_id=config['folder_id'],file=pname(ipatpl,proj))},
                       {'kind':'display-image','needs-shine':False,'url':pname(imagetpl,proj)},
                       {'kind':'full-size-image','needs-shine':False,'url':pname(imagetpl,proj)}
                   ],'metadata':{
                       'bundle-identifier':proj['app']['CFBundleIdentifier'],
                       'bundle-version':proj['app']['CFBundleShortVersionString'],
                       'kind':'software',
                       'title':proj['name']
                   }}]},f)
def proc_distribute(g,projects):
    open('index.html','w').write(layout.format(content='\n'.join(
            [section.format(**p) for p in projects if p['valid']])))
    if 'index.html' in g['gfiles']: g['to_update'].append('index.html')
    else: g['to_create'].append('index.html')
    [update_content(g['gfiles'][f]['id'],f,mimeType=mimetype(f)) for f in g['to_update']]
    [new_content(f,title=f,parents=[{'id':config['folder_id'],'isRoot': False}],mimeType=mimetype(f)) for f in g['to_create']]

## Web Processed Script !!!
## Call user browser to get a google token access and trigger next steps
from subprocess import call
redirect = 'http://{}:{}/oauth2callback'.format(config['listen'],config['port'])
auth_entry = oauth_url.format(redir=redirect,client_id=config['client_id'],scope=' '.join(needed_scopes))
call(["open",auth_entry])

# web processing handler
import wsgiref.simple_server
from glob import glob
from urllib import parse
from io import BytesIO
from cgi import FieldStorage
def app(environ,startresp):
    m,p,q = environ['REQUEST_METHOD'],environ['PATH_INFO'],environ['QUERY_STRING']
    def go2home(): return ('302 Found',[('location','/')],[])
    def oauth(code):
        get_token(config['client_id'],config['client_secret'],code,redirect)
        return go2home()
    def home():
        g = globalstate()
        return ('200 OK',[('Content-type','text/html; charset=utf-8')],
                [layout.format(content=g['action']+'\n'.join([section.format(**projectstate(p['target'],g)) for p in config['projects']])).encode('utf8')])
    def missing_devices(target):
        devices = projectstate(target,globalstate())['missing_udids']
        plist = BytesIO(); dict2plist({'Device UDIDs':[{'deviceIdentifier':udid,'deviceName':devices[udid]}for udid in devices]},plist)
        plist.seek(0); return ('200 OK',[('Content-type','text/xml')],[plist.read()])
    def profile(target):
        newprofile = FieldStorage(fp=environ['wsgi.input'],environ=environ).getfirst('profile')
        isnew = True
        if path.exists(pname(profiletpl,{'target':target})):
            with open(pname(profiletpl,{'target':target}),'rb') as f:  
                isnew = f.read() != newprofile
        if isnew:
            with open(pname(profiletpl,{'target':target}),'wb') as f: f.write(newprofile)
            if path.exists(pname(ipatpl,{'target':target})): remove(pname(ipatpl,{'target':target}))
        return go2home()
    def distribute():
        g = globalstate()
        proc_distribute(g,[projectstate(p['target'],g) for p in config['projects'] if p['valid']])
        return go2home()
    def keychain():
        call(["open",'distribute.keychain'])
        return ('204 No Content',[],[])
    def proc_handler(proc):
        def handler(target):
            proc(projectstate(target,globalstate()))
            return go2home()
        return handler
    try:
        (s,h,r) = { 'GET':{'/':home,'/oauth2callback':oauth,'/missing.deviceids':missing_devices,'/keychain':keychain},
            'POST':{'/profile':profile,'/build':proc_handler(proc_application),'/package':proc_handler(proc_package),
                    '/repo':proc_handler(proc_repo),'/distribute':distribute}
        }[m][p](**dict((k,v[0]) for (k,v) in  parse.parse_qs(q).items()))
        startresp(s,h); return r
    except HTTPError as e: # google app error
        e = json.loads(e.fp.read().decode('utf8'))['error']
        msg = e['message'] if type(e) != str else e
        if "Credentials" in msg: startresp('302 Found',[('location',auth_entry)]);return []
        startresp('500 Server Error',[('Content-type','text/plain')]);return [msg.encode('utf8')]
    except KeyError as e: # no route : static file or 404
        if m == 'GET' and path.exists('.'+p): startresp('200 OK',[('Content-type',mimetype(p))]);return[open('.'+p,'rb').read()]
        startresp('404 Not Found',[('Content-type','text/plain')]);return [b'Page not found']
print("Listen on {}:{}".format(config['listen'],config['port']))
wsgiref.simple_server.make_server(config['listen'],int(config['port']),app).serve_forever()
