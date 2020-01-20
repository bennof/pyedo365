import sys
import importlib
import logging

# net libs
import http.client
import urllib.parse

from django.db import models
from django.contrib.auth.models import AbstractUser
from django.conf import settings

from .jwt import JWT

_this = sys.modules[__name__]
_logger = logging.getLogger(__name__)

# override user model
class User(AbstractUser): 
    pass


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
        #_logger.warning("Request: "+self.request_server)
        conn.request('POST', 
            self.request_path, 
            body=self.request_body+code,
            headers={'Content-type': 'application/x-www-form-urlencoded'})
        #_logger.warning("Request Body: "+self.request_body+code)
        res = conn.getresponse()
        data = res.read()
        conn.close()
        return data 

    def receive_auth_jwt(self,code):
        jwt = JWT() 
        jwt.decode_json(self.receive_auth(code))
        return jwt

    def get_user(self,jwt,create=False):
        if 'id_token' in jwt:
            oid = jwt.decode_member_token('id_token')
            try:
                return User.objects.get(email=oid['email'])
            except ObjectDoesNotExist:
                if create: 
                    return User.objects.create(username=oid['name'].replace(" ", "_"), first_name=oid['given_name'], last_name=oid['family_name'], email=oid['email'])
                else:
                    return None
        elif 'email' in jwt:
            try: 
                return User.objects.get(email=jwt['email'])
            except ObjectDoesNotExist:
                return None
        else:
            return None

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



# store auth
AUTH = {}

def add_authenticator(name, auth_cl, *args, **kwargs):
    d = auth_cl.rfind('.')
    if d > 0:
        module = importlib.import_module(auth_cl[0:d])
        cl = getattr(module, auth_cl[d+1:len(auth_cl)])
        AUTH[name] = cl(*args,**kwargs)
    elif d == 0:
        logger.warning('Failed loading authenticator: %s' % auth_cl)
    else: 
        cl = getattr(_this, auth_cl[d+1:len(auth_cl)])
        AUTH[name] = cl(*args,**kwargs)

def get_authenticator(name=None):
    if name in AUTH:
        return AUTH[name]
    else:
        return AUTH

def del_authenticator(name):
    del AUTH[name]

def _init(*args,**kwargs):
    _logger.warning("Init Users Auth ...")
    _logger.warning("Loading Authenticators:")
    for a in settings.USERS_AUTH:
        _logger.warning("--> "+ a[0])
        add_authenticator(a[0],a[1],*a[2],**a[3])


# init code
_init()  
