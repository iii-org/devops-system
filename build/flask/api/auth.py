from .util import util

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