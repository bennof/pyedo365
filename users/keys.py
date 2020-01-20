from secrets import token_bytes
import time
import threading

from .jwt import JWT

import logging
_logger = logging.getLogger(__name__)


class KeyMGR:
    def __init__(self,renew):
        self._lock    = threading.Lock()
        self._key     = token_bytes(nbytes=32)
        self._time    = int(time.time()) + renew
        self._old_key = token_bytes(nbytes=32)
        self._renew   = renew
        _logger.warning('Generate keys for %s ... ' % (__name__))

    def update(self, update):
        if self._time < int(time.time()):
            if self._lock.acquire(True):
                if self._time < int(time.time()):
                    self._old_key = self.key
                    self._key     = token_bytes(nbytes=32)
                    self._time    = int(time.time()) + renew
                self._lock.release()
        
    def check(self, key):
        self.update()
        if key == self._key:
            return True
        elif key == self._old_key:
            return True
        else:
            return False

    # this should not be used
    def get():
        self.update()
        return self._key

    def encode_jwt(self,jwt):
        self.update()
        return jwt.encode(self._key)

    def decode_jwt(self,data):
        self.update()
        jwt = JWT()
        if jwt.decode_verify(data,self._key):
            return True, jwt
        elif jwt.decode_verify(data,self._old_key):
            return True, jwt
        else:
            return False, None

    
AuthKey = KeyMGR(60)
