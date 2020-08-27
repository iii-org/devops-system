import datetime
import json
from Cryptodome.Hash import SHA256

from .util import util
from .redmine import Redmine
from .gitlab import GitLab
from model import db, User, UserPluginRelation, GroupsHasUsers, ProjectUserRole, TableGroup

# from jsonwebtoken import jsonwebtoken
from flask_jwt_extended import (create_access_token, JWTManager,
                                get_jwt_claims)

jwt = JWTManager()


class auth(object):
    @jwt.user_claims_loader
    def jwt_response_data(row):
        return {
            'user_id': row['id'],
            'user_account': row["login"],
            'role_id': row['role_id'],
            'role_name': row['role_name']
        }

    def __init__(self):
        self.redmine_key = None
        self.headers = {'Content-Type': 'application/json'}

    def user_login(self, logger, args):

        h = SHA256.new()
        h.update(args["password"].encode())
        result = db.engine.execute(
            "SELECT ur.id, ur.login, ur.password, pur.role_id, \
            rl.name as role_name \
            FROM public.user as ur, public.project_user_role as pur, public.roles as rl \
            WHERE ur.id = pur.user_id AND pur.role_id = rl.id")
        for row in result:
            if row['login'] == args["username"] and row[
                    'password'] == h.hexdigest():
                expires = datetime.timedelta(days=1)
                access_token = create_access_token(
                    identity=auth.jwt_response_data(row),
                    expires_delta=expires)
                logger.info("jwt access_token: {0}".format(access_token))
                return access_token
        return None

    def user_forgetpassword(self, logger, args):
        result = db.engine.execute("SELECT login, email FROM public.user")
        for row in result:
            if row['login'] == args["user_account"] and row['email'] == args[
                    "mail"]:
                # sent reset password url to mail
                logger.info(
                    "user_forgetpassword API: user_account and mail were correct"
                )

    def user_info(self, logger, user_id):
        result = db.engine.execute(
            "SELECT ur.id as id, ur.name as name, ur.username as username,\
            ur.email as email, ur.phone as phone, ur.login as login, ur.create_at as create_at,\
            ur.update_at as update_at, rl.name as role_name \
            FROM public.user as ur, public.project_user_role as pur, public.roles as rl \
            WHERE ur.id = {0} AND ur.id = pur.user_id AND pur.role_id = rl.id".
            format(user_id))
        user_data = result.fetchone()
        result.close()
        logger.info("user info: {0}".format(user_data["id"]))
        select_groups_has_users_command = db.select([
            GroupsHasUsers.stru_groups_has_users
        ]).where(
            db.and_(GroupsHasUsers.stru_groups_has_users.c.user_id == user_id))
        logger.debug("select_groups_has_users_command: {0}".format(
            select_groups_has_users_command))
        reMessage = util.callsqlalchemy(self, select_groups_has_users_command,
                                        logger)
        group_has_user_array = reMessage.fetchall()
        logger.debug("group_has_user_array: {0}".format(group_has_user_array))
        group_list = []
        if group_has_user_array:
            logger.debug("User {0} has group".format(user_id))
            for group_has_user in group_has_user_array:
                select_group_command = db.select(
                    [TableGroup.stru_group]).where(
                        db.and_(TableGroup.stru_group.c.id ==
                                group_has_user['group_id']))
                logger.debug(
                    "select_group_command: {0}".format(select_group_command))
                reMessage = util.callsqlalchemy(self, select_group_command,
                                                logger)
                group_info = reMessage.fetchone()
                logger.debug("group_name: {0}".format(group_info))
                group_list.append({
                    "id": group_info['id'],
                    "name": group_info['name']
                })
        output = {
            "id": user_data["id"],
            "name": user_data["name"],
            "usernmae": user_data["username"],
            "email": user_data["email"],
            "phone": user_data["phone"],
            "login": user_data["login"],
            "create_at": user_data["create_at"].isoformat(),
            "update_at": user_data["update_at"].isoformat(),
            "role": {
                "name": user_data["role_name"]
            }
        }
        if group_list:
            output["group"] = group_list
        else:
            output["group"] = {}
        logger.debug(output)
        return output

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
        set_string += "update_at = {0}}".format(datetime.datetime.now())
        logger.info("set_string: {0}".format(set_string))
        result = db.engine.execute(
            "UPDATE public.user SET {0} WHERE id = {1}".format(
                set_string, user_id))

    def delete_user(self, logger, user_id):
        ''' disable user on user table'''
        update_user_to_disable_command = db.update(User.stru_user)\
            .where(db.and_(User.stru_user.c.id==user_id)).values(disable=True)
        logger.debug("update_user_to_disable_command: {0}".format(
            update_user_to_disable_command))
        reMessage = util.callsqlalchemy(self, update_user_to_disable_command,
                                        logger)
        logger.info("reMessage: {0}".format(reMessage))

    def create_user(self, logger, args, app):
        ''' create user in plan phase software(redmine) and repository_user_id(gitlab)
        Create DB user, user_plugin_relation, project_user_role, groups_has_users 4 table
        '''
        h = SHA256.new()
        h.update(args["password"].encode())
        args["password"] = h.hexdigest()
        insert_user_command = db.insert(User.stru_user).values(
            name=args['name'],
            username=args['username'],
            email=args['email'],
            phone=args['phone'],
            login=args['login'],
            password=h.hexdigest(),
            create_at=datetime.datetime.now())
        logger.debug("insert_user_command: {0}".format(insert_user_command))
        reMessage = util.callsqlalchemy(self, insert_user_command, logger)
        logger.info("reMessage: {0}".format(reMessage))

        #get user_id
        get_user_command = db.select([User.stru_user]).where(
            db.and_(User.stru_user.c.login == args['login']))
        logger.debug("get_user_command: {0}".format(get_user_command))
        reMessage = util.callsqlalchemy(self, get_user_command, logger)
        user_id = reMessage.fetchone()['id']
        logger.info("user_id: {0}".format(user_id))

        # plan software user create
        Redmine.get_redmine_key(self, logger, app)
        red_user = Redmine.redmine_post_user(self, logger, app, args)
        if red_user.status_code == 201:
            redmine_user_id = red_user.json()['user']['id']
        else:
            return {
                "message": {
                    "redmine": red_user.json()
                }
            }, red_user.status_code
        # git software user create
        git_user = GitLab.create_user(self, logger, app, args)
        if git_user.status_code == 201:
            gitlab_user_id = git_user.json()['id']
        else:
            return {
                "message": {
                    "gitlab": git_user.json()
                }
            }, git_user.status_code

        #insert user_plugin_relation table
        insert_user_plugin_relation_command = db.insert(UserPluginRelation.stru_user_plug_relation)\
            .values(user_id = user_id, plan_user_id = redmine_user_id, \
            repository_user_id = gitlab_user_id)
        logger.debug("insert_user_plugin_relation_command: {0}".format(
            insert_user_plugin_relation_command))
        reMessage = util.callsqlalchemy(self,
                                        insert_user_plugin_relation_command,
                                        logger)
        logger.info("reMessage: {0}".format(reMessage))

        # insert role and user into project_user_role
        insert_project_user_role_command = db.insert(ProjectUserRole.stru_project_user_role)\
            .values(user_id = user_id, role_id = args['role_id'])
        logger.debug("insert_project_user_role_command: {0}".format(
            insert_project_user_role_command))
        reMessage = util.callsqlalchemy(self, insert_project_user_role_command,
                                        logger)
        logger.info("reMessage: {0}".format(reMessage))

        if args["group_id"] is not None:
            # add users into groups_has_users table
            for group_id in args["group_id"]:
                #insert groups_has_users table
                insert_groups_has_users_command = db.insert(GroupsHasUsers.stru_groups_has_users)\
                    .values(group_id = group_id, user_id = user_id)
                logger.debug("insert_groups_has_users_command: {0}".format(
                    insert_groups_has_users_command))
                reMessage = util.callsqlalchemy(
                    self, insert_groups_has_users_command, logger)
                logger.info("reMessage: {0}".format(reMessage))

    def get_user_plugin_relation(self, logger):
        get_user_plugin_relation_command = db.select(
            [UserPluginRelation.stru_user_plug_relation])
        logger.debug("get_user_plugin_relation_command: {0}".format(
            get_user_plugin_relation_command))
        reMessage = util.callsqlalchemy(self, get_user_plugin_relation_command,
                                        logger)
        user_plugin_relation_array = reMessage.fetchall()
        return user_plugin_relation_array
