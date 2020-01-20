from django.http import HttpResponse
from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login
from django.core.exceptions import ObjectDoesNotExist
from django.contrib.auth.forms import AuthenticationForm

from secrets import token_bytes
import time

from .models import AUTH, User
from .jwt import JWT
from .keys import AuthKey

import logging
_logger = logging.getLogger(__name__)






def login_page(req,provider=None):
    next = '/admin/'
    if 'next' in req.GET: 
        next = req.GET['next']

    if False:#provider != None:
        pass
    else:
         # has a code and a state
        if (  req.method == 'GET' 
          and 'code'  in req.GET
          and 'state' in req.GET):
            return login_auth(req,next)
        elif (  req.method == 'POST' 
          and 'username' in req.POST
          and 'password' in req.POST):
            if next in req.POST:
                next = req.POST['next']
            return login_passwd(req,next)
        # is login kick of
        else: 
            return login_form(req,next)


# View
#def perform_request(req):
   
    #res =  HttpResponse(content_type="text/plain")
    #jwt.writeto(res)
    #if 'id_token' in jwt:
    #    oid = jwt.decode_member_token('id_token')
    #    res.write('\nOPEN ID TOKEN\n')
    #    oid.writeto(res)
    #    try:
    #        u = User.objects.get(email=oid['email'])
    #        res.write('\nUser: '+str(u)+'\n')
    #        login(req,u)
    #    except ObjectDoesNotExist:
    #        res.write('\nUser: not found\n')
    #        User.objects.create(username=oid['name'].replace(" ", "_"), first_name=oid['given_name'], last_name=oid['family_name'], email=oid['email'])
    #return res

def login_auth(req,next):
    state = req.GET['state'].split('.')
    a = AUTH[state[0]]
    jwt = a.receive_auth_jwt(req.GET['code'])
    u = a.get_user(jwt)
    if u:
        login(req,u)
        _logger.warning('Logged in: %s'%str(u))
        return redirect('/admin/')
    else:
        return login_form(req,failed=True)

def login_passwd(req,next):
    username = req.POST['username']
    password = req.POST['password']
    user = authenticate(req, username=username, password=password)
    if user is not None:
        login(req, user)
        _logger.warning('Logged in: %s'%str(u))
        return redirect('/admin/')
    else:
        return login_form(req,failed=True)

def login_form(req,next,failed=False):
    data = {}
    for key in AUTH:
        data[key] = AUTH[key].redirect_link(key+'.testlogin')
    return render(req, 'users/login.html', {'auth': data, 'failed':failed, 'form':AuthenticationForm(), 'next': next})