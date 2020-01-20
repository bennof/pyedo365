import json
import time
import base64
import hmac
import hashlib 

# JWT
class JWT(dict):
    def __init__(self,**kwargs):
        super().__init__()
        for key in kwargs:
            self.__dict__[key] = kwargs[key]

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
        