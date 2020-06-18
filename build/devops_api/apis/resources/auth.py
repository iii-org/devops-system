from Cryptodome.Hash import SHA256

from .util import util
from model import db

class auth(object):
    
    def __init__(self):
        pass

    def get_token(self, logger):
        url="https://10.50.1.55/v3-public/localProviders/local?action=login"
        headers = {
            'Content-Type': 'application/json'
        }
        parameter ={
            "username":"admin",
            "password":"openstack"
        }
        output = util.callpostapi(self, url, parameter, logger, headers)
        return output.json()['token']
    
    def user_login(self, logger, args):
        h = SHA256.new()
        h.update(args["password"].encode())
        result = db.engine.execute("SELECT login, password FROM public.user")
        for row in result:
            if row['login'] == args["username"] and row['password'] == h.hexdigest():
                return True
        return False