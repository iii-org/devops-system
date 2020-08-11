import datetime
import json
from Cryptodome.Hash import SHA256

from model import db

# from jsonwebtoken import jsonwebtoken
from flask_jwt_extended import (
    create_access_token, JWTManager, get_jwt_claims
)

jwt = JWTManager()

class auth(object):

    '''
    @jwt.user_claims_loader
    def jwt_response_data(row):
        return {
            'user_id': row['id'],
            'role_id': row['role_id']
        }
    '''

    def __init__(self):
        pass

    def user_login(self, logger, args):
        
        h = SHA256.new()
        h.update(args["password"].encode())
        result = db.engine.execute("SELECT ur.id, ur.login, ur.password, pur.role_id \
            FROM public.user as ur, public.project_user_role as pur WHERE ur.id = pur.user_id")
        for row in result:
            if row['login'] == args["username"] and row['password'] == h.hexdigest():
                data = {'user_id': row["id"], 'role_id': row["role_id"]}
                expires = datetime.timedelta(days=1)
                logger.info("data type: {0}".format(type(data)))
                access_token = create_access_token(identity=json.dumps(data), expires_delta=expires)
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
        result = db.engine.execute("SELECT ur.id as id, ur.name as name, ur.username as username,\
            ur.email as email, ur.phone as phone, ur.login as login, ur.create_at as create_at,\
            ur.update_at as update_at, rl.name as role_name, gp.name as group_name FROM public.user as ur, \
            public.project_user_role as pur, public.roles as rl, public.groups_has_users as gu,\
            public.group as gp WHERE ur.id = {0} AND ur.id = pur.user_id AND pur.role_id = rl.id \
            AND ur.id = gu.user_id AND gu.group_id = gp.id ".format(user_id))
        user_data = result.fetchone()
        result.close()
        logger.info("user info: {0}".format(user_data["id"]))
        return {
            "id": user_data["id"],
            "name": user_data["name"],
            "usernmae": user_data["username"],
            "email": user_data["email"],
            "phone": user_data["phone"],
            "login": user_data["login"],
            "create_at": user_data["create_at"],
            "update_at": user_data["update_at"],
            "group": {
                "name": user_data["group_name"]
            },
            "role":{
                "name": user_data["role_name"]
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