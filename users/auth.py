# Python
import sys
import importlib
import logging

import json
import time
import base64
import hmac
import hashlib 

# net libs
import http.client
import urllib.parse

# Django
from django.conf import settings
from django.http import HttpResponse
from django.shortcuts import render, redirect
from django.contrib.auth import login
from django.core.exceptions import ObjectDoesNotExist

#loacal imports 
from . import models

# setup some basics
_this = sys.modules[__name__]
_logger = logging.getLogger(__name__)


# JWT
class JWT(dict):
    #def __init__(self):
    #    super().__init__()

    @staticmethod
    def default(iss,sub,aud,expire):
        now = int(time.time())
        jwt = JWT()
        jwt["iat"] = now
        jwt["exp"] = now + expire
        jwt["iss"] = iss 
        jwt["sub"] = sub
        jwt["aud"] = aud
        return jwt

    def __setitem__(self, key, item):
        self.__dict__[key] = item

    def __getitem__(self, key):
        return self.__dict__[key]

    def __repr__(self):
        return repr(self.__dict__)

    def __len__(self):
        return len(self.__dict__)

    def __delitem__(self, key):
        del self.__dict__[key]

    def clear(self):
        return self.__dict__.clear()

    def copy(self):
        return self.__dict__.copy()

    def has_key(self, k):
        return k in self.__dict__

    def update(self, *args, **kwargs):
        return self.__dict__.update(*args, **kwargs)

    def keys(self):
        return self.__dict__.keys()

    def values(self):
        return self.__dict__.values()

    def items(self):
        return self.__dict__.items()

    def pop(self, *args):
        return self.__dict__.pop(*args)

    def __cmp__(self, dict_):
        return self.__cmp__(self.__dict__, dict_)

    def __contains__(self, item):
        return item in self.__dict__

    def __iter__(self):
        return iter(self.__dict__)

    def __unicode__(self):
        return unicode(repr(self.__dict__))

    def encode(self,key):
        header = base64.standard_b64encode(b'{"alg":"HS256","typ":"JWT"}')
        payload = base64.standard_b64encode(json.dumps(self.__dict__).encode())
        sig = base64.standard_b64encode(hmac.new(key, header+b'.'+payload, hashlib.sha256).digest())
        return header+b'.'+payload+b'.'+sig

    def decode_json(self,data):
        self.__dict__ = json.loads(data)

    def decode(self,data):
        chunk = data.split(b'.')
        self.__dict__ = json.loads(base64.standard_b64decode(chunk[1]+ b"==="))

    def decode_verify(self,data,key):
        chunk = data.split(b'.')
        sig = base64.standard_b64encode(hmac.new(key, chunk[0]+b'.'+chunk[1], hashlib.sha256).digest())
        if chunk[2] == sig:
            self.__dict__ = json.loads(base64.standard_b64decode(chunk[1]+ b"==="))
            return True
        else: 
            return False

    def decode_member_token(self,name):
        ret = JWT() 
        ret.decode(self[name].encode())
        return ret

    def writeto(self,to,indent='   ',offset=''):
        to.write(offset+"JWT:\n")
        for x in self.__dict__:
            to.write(offset+indent+"%s: %s\n"%(x,str(self.__dict__[x])))
        




# Authenticators 
class OAuth2:
    def __init__(self, login_uri, request_server, request_path, request_body):
        self.login_uri = login_uri
        self.request_server = request_server
        self.request_path = request_path
        self.request_body = request_body
        #self.conn = None # not threadsafe

    def redirect_link(self,state):
        return self.login_uri+"&state="+urllib.parse.quote(state)

    def redirect_login(self,state):
        return redirect(self.login_uri+"&state="+urllib.parse.quote(state))

    def receive_auth(self,code):
        # if self.conn == None:
        conn = http.client.HTTPSConnection(self.request_server)
        _logger.warning("Request: "+self.request_server)
        conn.request('POST', 
            self.request_path, 
            body=self.request_body+code,
            headers={'Content-type': 'application/x-www-form-urlencoded'})
        _logger.warning("Request Body: "+self.request_body+code)
        res = conn.getresponse()
        data = res.read()
        conn.close()
        return data 

    def receive_auth_jwt(self,code):
        jwt = JWT() 
        jwt.decode_json(self.receive_auth(code))
        return jwt

        

class Google(OAuth2):
    def __init__(self, client_id, client_secret, redirect_uri, scope):
        login_uri = "https://accounts.google.com/o/oauth2/v2/auth?" \
            "scope="+scope+"&" \
            "include_granted_scopes=true&" \
            "redirect_uri=" + redirect_uri + "&" \
            "access_type=offline&" \
            "response_type=code&" \
            "client_id="+client_id
        request_server = "www.googleapis.com"
        request_path = "/oauth2/v4/token"
        request_body = "client_id=" + client_id + "&" \
            "client_secret=" + client_secret + "&" \
            "redirect_uri=" + redirect_uri + "&" \
            "grant_type=authorization_code&" \
            "code="
        super().__init__(login_uri, request_server, request_path, request_body)

class MS_Azure(OAuth2):
    pass

class Facebook(OAuth2):
    pass



# View
def perform_request(req):
    # handle state
    state = req.GET['state'].split('.')
    a = _AUTH[state[0]]
    jwt = a.receive_auth_jwt(req.GET['code'])
    res =  HttpResponse(content_type="text/plain")
    jwt.writeto(res)
    if 'id_token' in jwt:
        oid = jwt.decode_member_token('id_token')
        res.write('\nOPEN ID TOKEN\n')
        oid.writeto(res)
        try:
            u = models.User.objects.get(email=oid['email'])
            res.write('\nUser: '+str(u)+'\n')
            login(req,u)
        except ObjectDoesNotExist:
            res.write('\nUser: not found\n')
            models.User.objects.create(username=oid['name'].replace(" ", "_"), first_name=oid['given_name'], last_name=oid['family_name'], email=oid['email'])
    return res

def list_links(request):
    res =  HttpResponse(content_type="text/html")
    res.write("<html><body>")
    auths = _AUTH
    for a in auths:
        res.write('<a href="%s">%s</a><br/>'%(auths[a].redirect_link(a+'.testlogin'),a))
    res.write("</body></html>")
    return res


# create a login view
def view_login(req,provider=None):
    if False:#provider != None:
        pass
    else:
         # has a code and a state
        if (  req.method == 'GET' 
          and 'code'  in req.GET
          and 'state' in req.GET):
            return perform_request(req)
        # is login kick of
        else: 
            return list_links(req)


# store auth
_AUTH = {}

def add_authenticator(name, auth_cl, *args, **kwargs):
    d = auth_cl.rfind('.')
    if d > 0:
        module = importlib.import_module(auth_cl[0:d])
        cl = getattr(module, auth_cl[d+1:len(auth_cl)])
        _AUTH[name] = cl(*args,**kwargs)
    elif d == 0:
        logger.warning('Failed loading authenticator: %s' % auth_cl)
    else: 
        cl = getattr(_this, auth_cl[d+1:len(auth_cl)])
        _AUTH[name] = cl(*args,**kwargs)

def get_authenticator(name=None):
    if name in _AUTH:
        return _AUTH[name]
    else:
        return _AUTH

def del_authenticator(name):
    del _AUTH[name]

def _init(*args,**kwargs):
    _logger.warning("Init Users Auth ...")
    _logger.warning("Loading Authenticators:")
    for a in settings.USERS_AUTH:
        _logger.warning("--> "+ a[0])
        add_authenticator(a[0],a[1],*a[2],**a[3])


# init code
_init()  