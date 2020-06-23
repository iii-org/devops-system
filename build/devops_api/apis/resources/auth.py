from Cryptodome.Hash import SHA256

from .util import util
from model import db

# from jsonwebtoken import jsonwebtoken
from flask_jwt_extended import (
    JWTManager, jwt_required, create_access_token,
    jwt_refresh_token_required, create_refresh_token,
    get_jwt_identity
)

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
                access_token = create_access_token(identity=args["username"])
                logger.info("jwt access_token: {0}".format(access_token))
                return access_token
        return None

    def user_forgetpassword(self, logger, args):
        result = db.engine.execute("SELECT login, email FROM public.user")
        for row in result:
            if row['login'] == args["user_account"] and row['email'] == args["mail"]:
                # sent reset password url to mail
                logger.info("user_forgetpassword API: user_account and mail were correct")
    
    def user_info(self, logger, user_id):
        result = db.engine.execute("SELECT * FROM public.user WHERE id = {0}".format(user_id))
        user_data = result.fetchone()
        result.close()
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
    
    def update_user_info(self, logger, user_id, args):
        set_string = ""
        if args["name"] is not None:
            set_string += "name = '{0}'".format(args["name"])
            set_string += ","
        if args["username"] is not None:
            set_string += "username = '{0}'".format(args["username"])
            set_string += ","
        if args["password"] is not None:
            h = SHA256.new()
            h.update(args["password"].encode())
            set_string += "password = '{0}'".format(h.hexdigest())
            set_string += ","
        if args["phone"] is not None:
            set_string += "phone = {0}".format(args["phone"])
            set_string += ","
        if args["email"] is not None:
            set_string += "email = '{0}'".format(args["email"])
            set_string += ","
        '''
        if args["group"] is not None:
            set_string += "group = '{0}'".format(args["group"])
            set_string += ","
        if args["role"] is not None:
            set_string += "role = '{0}'".format(args["role"])
            set_string += ","
        '''
        set_string += "update_at = localtimestamp"
        logger.info("set_string: {0}".format(set_string))
        result = db.engine.execute("UPDATE public.user SET {0} WHERE id = {1}".format(set_string, user_id))