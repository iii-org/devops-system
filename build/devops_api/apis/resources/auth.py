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

    def user_forgetpassword(self, logger, args):
        result = db.engine.execute("SELECT login, email FROM public.user")
        for row in result:
            if row['login'] == args["user_account"] and row['email'] == args["mail"]:
                # sent reset password url to mail
                logger.info("user_forgetpassword API: user_account and mail were correct")
    
    def user_info(self, logger, user_id):
        result = db.engine.execute("SELECT * FROM public.user WHERE id = {0}".format(user_id))
        user_data = result.fetchone()
        logger.info("user info: {0}".format(user_data["id"]))
        return {
            "id": user_data["id"],
            "name": user_data["name"],
            "usernmae": user_data["name"],
            "email": user_data["email"],
            "phone": user_data["phone"],
            "login": user_data["login"],
            "create_at": user_data["create_at"],
            "update_at": user_data["update_at"],
            "group": {
                "name": "III"
            },
            "role":{
                "name": "Engineer"
            }
        }