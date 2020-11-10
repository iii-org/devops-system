import config
import datetime
import json
import logging
import re

import requests
from Cryptodome.Hash import SHA256
# from jsonwebtoken import jsonwebtoken
from flask_jwt_extended import (create_access_token, JWTManager)

from model import db, User, UserPluginRelation, ProjectUserRole, TableProjects, ProjectPluginRelation, \
    TableRolesPluginRelation
import resources.apiError as apiError
from .gitlab import GitLab
from .project import Project
import resources.util as util

logger = logging.getLogger(config.get('LOGGER_NAME'))

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

    def __init__(self, app, redmine, git):
        self.app = app
        self.redmine_key = None
        self.headers = {'Content-Type': 'application/json'}
        self.redmine = redmine
        self.git = git

        if config.get("GITLAB_API_VERSION") == "v3":
            # get gitlab admin token
            url = "http://{0}/api/v3/session".format(
                config.get("GITLAB_IP_PORT"))
            parame = {}
            parame["login"] = config.get("GITLAB_ADMIN_ACCOUNT")
            parame["password"] = config.get("GITLAB_ADMIN_PASSWORD")

            output = requests.post(url,
                                   data=json.dumps(parame),
                                   headers=self.headers,
                                   verify=False)
            # logger.info("private_token api output: {0}".format(output))
            self.private_token = output.json()['private_token']
        else:
            self.private_token = config.get("GITLAB_PRIVATE_TOKEN")

    def get_roleID_by_userID(self, logger, user_id):
        role_id = None
        get_rl_cmd = db.select([ProjectUserRole.stru_project_user_role]).where(db.and_(\
            ProjectUserRole.stru_project_user_role.c.user_id==user_id))
        get_role_out = util.call_sqlalchemy(get_rl_cmd).fetchone()
        if get_role_out is not None:
            role_id = get_role_out['role_id']
            return role_id
        else:
            return {"message": "Could not get user role_id"}, 400

    def get_redmineRoleID_by_roleID(self, logger, role_id):
        select_redmien_role_cmd = db.select([TableRolesPluginRelation.stru_rolerelation])\
            .where(db.and_(TableRolesPluginRelation.stru_rolerelation.c.role_id==role_id))
        logger.debug(
            "select_redmien_role_cmd: {0}".format(select_redmien_role_cmd))
        reMessage = util.call_sqlalchemy(select_redmien_role_cmd).fetchone()
        return reMessage['plan_role_id']

    def user_login(self, logger, args):

        h = SHA256.new()
        h.update(args["password"].encode())
        result = db.engine.execute(
            "SELECT ur.id, ur.login, ur.password, pur.role_id, \
            rl.name as role_name \
            FROM public.user as ur, public.project_user_role as pur, public.roles as rl \
            WHERE ur.disabled = false AND ur.id = pur.user_id AND pur.role_id = rl.id"
        )
        for row in result:
            if row['login'] == args["username"] and row[
                    'password'] == h.hexdigest():
                if args["username"] == "admin":
                    expires = datetime.timedelta(days=36500)
                else:
                    expires = datetime.timedelta(days=1)
                access_token = create_access_token(
                    identity=auth.jwt_response_data(row),
                    expires_delta=expires)
                logger.info("jwt access_token: {0}".format(access_token))
                return {
                    "message": "success",
                    "data": {
                        "token": access_token
                    }
                }, 200
        return {"message": "you dont have authorize to get token"}, 401

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
        ''' get user info'''
        result = db.engine.execute("SELECT ur.id as id, ur.name as name,\
            ur.email as email, ur.phone as phone, ur.login as login, ur.create_at as create_at,\
            ur.update_at as update_at, rl.id as role_id, rl.name as role_name, ur.disabled as disabled \
            FROM public.user as ur, public.project_user_role as pur, public.roles as rl \
            WHERE ur.id = {0} AND ur.id = pur.user_id AND pur.role_id = rl.id".
                                   format(user_id))
        user_data = result.fetchone()
        result.close()

        if user_data:
            logger.info("user info: {0}".format(user_data))
            account_status = ""
            if user_data["disabled"] == True:
                status = "disable"
            else:
                status = "enable"
            output = {
                "id": user_data["id"],
                "name": user_data["name"],
                "email": user_data["email"],
                "phone": user_data["phone"],
                "login": user_data["login"],
                "create_at": util.date_to_str(user_data["create_at"]),
                "update_at": util.date_to_str(user_data["update_at"]),
                "role": {
                    "name": user_data["role_name"],
                    "id": user_data["role_id"]
                },
                "status": status
            }
            # get user involve project list
            select_project = db.select([ProjectUserRole.stru_project_user_role,
                TableProjects.stru_projects, ProjectPluginRelation.stru_project_plug_relation]).where(
                db.and_(
                ProjectUserRole.stru_project_user_role.c.user_id==user_id,
                ProjectUserRole.stru_project_user_role.c.project_id!=-1,
                ProjectUserRole.stru_project_user_role.c.project_id==\
                TableProjects.stru_projects.c.id,
                ProjectUserRole.stru_project_user_role.c.project_id==\
                ProjectPluginRelation.stru_project_plug_relation.c.project_id))
            logger.debug("select_project: {0}".format(select_project))
            reMessage = util.call_sqlalchemy(select_project).fetchall()
            logger.debug("reMessage: {0}".format(reMessage))
            if len(reMessage) > 0:
                project_list = []
                for project in reMessage:
                    logger.debug("project: {0}".format(project))
                    project_list.append({
                        "id":
                        project["id"],
                        "name":
                        project["name"],
                        "display":
                        project["display"],
                        "repository_id":
                        project["git_repository_id"]
                    })
                output["project"] = project_list
            else:
                output["project"] = []

            return {'message': 'success', 'data': output}, 200
        else:
            return {"message": "Could not found user information"}, 400

    def update_user_info(self, user_id, args):
        # Check user id disabled or not.
        select_user_to_disable_command = db.select([User.stru_user])\
            .where(db.and_(User.stru_user.c.id==user_id))
        logger.debug("select_user_to_disable_command: {0}".format(
            select_user_to_disable_command))
        user_data = util.call_sqlalchemy(select_user_to_disable_command).fetchone()
        set_string = ""
        if args["name"] is not None:
            set_string += "name = '{0}'".format(args["name"])
            set_string += ","
        if args["password"] is not None:
            err = self.update_external_passwords(user_id, args["password"])
            if err is not None:
                logger.exception(err)  # Don't stop change password on API server
            h = SHA256.new()
            h.update(args["password"].encode())
            set_string += "password = '{0}'".format(h.hexdigest())
            set_string += ","
        if args["phone"] is not None:
            set_string += "phone = '{0}'".format(args["phone"])
            set_string += ","
        if args["email"] is not None:
            set_string += "email = '{0}'".format(args["email"])
            set_string += ","
        if args["status"] is not None:
            status = False
            if args["status"] == "disable":
                status = True
            set_string += "disabled = '{0}'".format(status)
            set_string += ","
        set_string += "update_at = localtimestamp"
        logger.info("set_string: {0}".format(set_string))
        result = db.engine.execute(
            "UPDATE public.user SET {0} WHERE id = {1}".format(
                set_string, user_id))
        logger.debug("{0} rows updated.".format(result.rowcount))

        return {'message': 'success'}, 200

    def update_external_passwords(self, user_id, new_pwd):
        user_relation = auth.get_user_plugin_relation(user_id=user_id)
        logger.debug("user_relation_list: {0}".format(user_relation))
        if user_relation is None:
            return util.respond(404, 'Error when updating password', error=apiError.user_not_found(user_id))
        redmine_user_id = user_relation['plan_user_id']
        err = self.redmine.rm_update_password(redmine_user_id, new_pwd)
        if err is not None:
            return err

        gitlab_user_id = user_relation['repository_user_id']
        err = self.git.gl_update_password(gitlab_user_id, new_pwd)
        if err is not None:
            return err

        return None

    def delete_user(self, logger, app, user_id):
        ''' disable user on user table'''
        # update_user_to_disable_command = db.update(User.stru_user)\
        #     .where(db.and_(User.stru_user.c.id==user_id)).values(\
        #     update_at = datetime.datetime.now(), disabled=True)
        # logger.debug("update_user_to_disable_command: {0}".format(
        #     update_user_to_disable_command))
        # reMessage = util.callsqlalchemy(self, update_user_to_disable_command,
        #                                 logger)
        # logger.info("reMessage: {0}".format(reMessage))

        # 取得gitlab & redmine user_id
        result = db.engine.execute(
            "SELECT * FROM public.user_plugin_relation WHERE user_id = '{0}'".
            format(user_id))
        user_relation = result.fetchone()
        result.close()
        redmine_user_id = user_relation["plan_user_id"]
        gitlab_user_id = user_relation["repository_user_id"]
        # 刪除gitlab user
        gitlab_url = "http://{0}/api/{1}/users/{2}?private_token={3}".format(\
            config.get("GITLAB_IP_PORT"), config.get("GITLAB_API_VERSION"), gitlab_user_id, self.private_token)
        logger.info("delete gitlab user url: {0}".format(gitlab_url))
        gitlab_output = requests.delete(gitlab_url,
                                        headers=self.headers,
                                        verify=False)
        logger.info("delete gitlab user output: {0}".format(gitlab_output))
        # 如果gitlab user成功被刪除則繼續刪除redmine user
        if gitlab_output.status_code == 204:
            redmine_url = "http://{0}/users/{1}.json?key={2}".format(\
                config.get("REDMINE_IP_PORT"), redmine_user_id, config.get("REDMINE_API_KEY"))
            logger.info("delete redmine user url: {0}".format(redmine_url))
            redmine_output = requests.delete(redmine_url,
                                             headers=self.headers,
                                             verify=False)
            logger.info(
                "delete redmine user output: {0}".format(redmine_output))
            # 如果gitlab & redmine user都成功被刪除則繼續刪除db內相關tables欄位
            if redmine_output.status_code == 204:
                db.engine.execute(
                    "DELETE FROM public.user_plugin_relation WHERE user_id = '{0}'"
                    .format(user_id))
                db.engine.execute(
                    "DELETE FROM public.project_user_role WHERE user_id = '{0}'"
                    .format(user_id))
                db.engine.execute(
                    "DELETE FROM public.user WHERE id = '{0}'".format(user_id))

                return {
                    "message": "success",
                    "data": {
                        "result": "success delete"
                    }
                }, 200

            else:
                error_code = redmine_output.status_code
                return {
                    "message": "error",
                    "data": {
                        "from": "redmine",
                        "result": redmine_output.json()
                    }
                }, error_code

        else:
            error_code = gitlab_output.status_code
            return {
                "message": "error",
                "data": {
                    "from": "gitlab",
                    "result": gitlab_output.json()
                }
            }, error_code

    def put_user_status(self, logger, user_id, args):
        ''' change user on user status'''
        disabled = False
        if args["status"] == "enable":
            disabled = False
        elif args["status"] == "disable":
            disabled = True
        update_user_to_disable_command = db.update(User.stru_user)\
            .where(db.and_(User.stru_user.c.id==user_id)).values(\
            update_at = datetime.datetime.now(), disabled=disabled)
        logger.debug("update_user_to_disable_command: {0}".format(
            update_user_to_disable_command))
        reMessage = util.call_sqlalchemy(update_user_to_disable_command)
        logger.info("reMessage: {0}".format(reMessage))
        return {'message': 'success'}, 200

    def create_user(self, logger, args, app):
        """
        Create user in plan phase software(redmine) and repository_user_id(gitlab)
        Create DB user, user_plugin_relation, project_user_role, groups_has_users 4 table
        """

        # Check if name is valid
        login = args['login']
        if re.fullmatch(r'^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,58}[a-zA-Z0-9]$', login) is None:
            return util.respond(400, "Error when creating new user", error=
                                error.invalid_user_name(login))

        user_source_password = args["password"]
        if re.fullmatch(r'(?=.*\d)(?=.*[a-z])(?=.*[A-Z])'
                        r'^[\w!@#$%^&*()+|{}\[\]`~\-\'\";:/?.\\>,<]{8,20}$',
                        user_source_password) is None:
            return util.respond(400, "Error when creating new user", error=
                                error.invalid_user_password())




        # Check DB has this login, email, if has, return error 400
        chekc_email_login_command = db.select([User.stru_user]).where(
            db.or_(User.stru_user.c.login == args['login'],
                   User.stru_user.c.email == args['email']))
        logger.debug(
            "chekc_email_login_command: {0}".format(chekc_email_login_command))
        reMessage = util.call_sqlalchemy(chekc_email_login_command)
        user_info = reMessage.fetchone()
        logger.info("Check user table has this account or email: {0}".format(
            user_info))
        if user_info is not None:
            return {"message": "System already has this account or email"}, 400
        # Check Redmine has this login, email, if has, return error 400
        offset = 0
        limit = 25
        total_count = 1
        while offset < total_count:
            # logger.debug("offset: {0}, total_count: {1}".format(offset, total_count))
            parame = {'offset': offset, 'limit': limit}
            user_list_output, status_code = self.redmine.rm_get_user_list(parame)
            try:
                user_list_output = user_list_output.json()
            except Exception as e:
                return util.respond(500, str(type(e)) + ': ' + str(e),
                                    error=apiError.redmine_error(user_list_output))

            # logger.debug("user_list_output: {0}".format(user_list_output))
            total_count = user_list_output['total_count']
            for user in user_list_output['users']:
                if user['login'] == args['login'] or user['mail'] == args[
                        'email']:
                    return {
                        "message": "Redmine already has this account or email"
                    }, 400
            offset += limit
        # Check Gitlab has this login, email, if has, return error 400
        page = 1
        X_Total_Pages = 10
        while page <= X_Total_Pages:
            #logger.debug("page: {0}, X_Total_Pages: {1}".format(page, X_Total_Pages))
            parame = {'page': page}
            user_list_output = self.git.gl_get_user_list(parame)
            X_Total_Pages = int(user_list_output.headers['X-Total-Pages'])
            #logger.debug("X_Total_Pages: {0}".format(X_Total_Pages))
            for user in user_list_output.json():
                logger.debug("gitlab login: {0}, email: {1}".format(
                    user['name'], user['email']))
                if user['name'] == args['login'] or user['email'] == args[
                        'email']:
                    return {
                        "message": "gitlab already has this account or email"
                    }, 400
            page += 1

        # plan software user create
        self.redmine.rm_refresh_key()
        red_user = self.redmine.rm_create_user(args, user_source_password)
        if red_user.status_code == 201:
            redmine_user_id = red_user.json()['user']['id']
        else:
            return {"message": red_user.text}, red_user.status_code

        # gitlab software user create
        git_user = self.git.gl_create_user(args, user_source_password)
        if git_user.status_code == 201:
            gitlab_user_id = git_user.json()['id']
        else:
            # delete redmine user
            self.redmine.rm_delete_user(redmine_user_id)
            return {"message": git_user.text}, git_user.status_code

        h = SHA256.new()
        h.update(args["password"].encode())
        args["password"] = h.hexdigest()
        disabled = False
        if args['status'] == "disable":
            disabled = True
        insert_user_command = db.insert(User.stru_user).values(
            name=args['name'],
            email=args['email'],
            phone=args['phone'],
            login=args['login'],
            password=h.hexdigest(),
            create_at=datetime.datetime.now(),
            disabled=disabled)

        logger.debug("insert_user_command: {0}".format(insert_user_command))
        reMessage = util.call_sqlalchemy(insert_user_command)
        logger.info("reMessage: {0}".format(reMessage))

        #get user_id
        get_user_command = db.select([User.stru_user]).where(
            db.and_(User.stru_user.c.login == args['login']))
        logger.debug("get_user_command: {0}".format(get_user_command))
        reMessage = util.call_sqlalchemy(get_user_command)
        user_id = reMessage.fetchone()['id']
        logger.info("user_id: {0}".format(user_id))

        #insert user_plugin_relation table
        insert_user_plugin_relation_command = db.insert(UserPluginRelation.stru_user_plug_relation)\
            .values(user_id = user_id, plan_user_id = redmine_user_id, \
            repository_user_id = gitlab_user_id)
        logger.debug("insert_user_plugin_relation_command: {0}".format(
            insert_user_plugin_relation_command))
        reMessage = util.call_sqlalchemy(insert_user_plugin_relation_command)
        logger.info("reMessage: {0}".format(reMessage))

        #insert project_user_role
        insert_project_user_role_command = db.insert(ProjectUserRole.stru_project_user_role)\
            .values(project_id = -1, user_id = user_id, role_id = args['role_id'])
        logger.debug("insert_project_user_role_command: {0}".format(
            insert_project_user_role_command))
        reMessage = util.call_sqlalchemy(insert_project_user_role_command)
        logger.info("reMessage: {0}".format(reMessage))

        return {"message": "success", "data": {"user_id": user_id}}, 200

    @staticmethod
    def get_user_plugin_relation(user_id=None, plan_user_id=None, repository_user_id=None):
        if plan_user_id is not None:
            get_user_plugin_relation_command = db.select(
                [UserPluginRelation.stru_user_plug_relation]).where(db.and_(\
                UserPluginRelation.stru_user_plug_relation.c.plan_user_id==plan_user_id))
        elif repository_user_id is not None:
            get_user_plugin_relation_command = db.select(
                [UserPluginRelation.stru_user_plug_relation]).where(db.and_(\
                UserPluginRelation.stru_user_plug_relation.c.repository_user_id==repository_user_id))
        else:
            get_user_plugin_relation_command = db.select(
                [UserPluginRelation.stru_user_plug_relation]).where(db.and_(\
                UserPluginRelation.stru_user_plug_relation.c.user_id==user_id))
        logger.debug("get_user_plugin_relation_command: {0}".format(
            get_user_plugin_relation_command))
        reMessage = db.engine.execute(get_user_plugin_relation_command)
        user_plugin_relation = reMessage.fetchone()
        return user_plugin_relation

    def get_user_list(self, logger):
        ''' get user list'''
        result = db.engine.execute(
            "SELECT ur.id as id, ur.name as name, ur.email as email, \
            ur.phone as phone, ur.login as login, ur.create_at as create_at, \
            ur.update_at as update_at, rl.id as role_id, rl.name as role_name, \
            ur.disabled as disabled\
            FROM public.user as ur \
            left join public.project_user_role as pur \
            on ur.id = pur.user_id \
            left join public.roles as rl \
            on pur.role_id = rl.id \
            group by ur.id, rl.id\
            ORDER BY ur.id DESC")
        user_data_array = result.fetchall()
        result.close()
        if user_data_array:
            output_array = []
            for user_data in user_data_array:
                # logger.info("user_data: {0}".format(user_data))
                select_project_by_userid = db.select([ProjectUserRole.stru_project_user_role, \
                    TableProjects.stru_projects]).where(db.and_(\
                    ProjectUserRole.stru_project_user_role.c.user_id==user_data["id"], \
                    ProjectUserRole.stru_project_user_role.c.project_id!=-1, \
                    ProjectUserRole.stru_project_user_role.c.project_id==\
                    TableProjects.stru_projects.c.id))
                output_project_array = util.call_sqlalchemy(select_project_by_userid).fetchall()
                #logger.debug("output_project: {0}".format(output_project_array))
                project = []
                if output_project_array:
                    for output_project in output_project_array:
                        project.append({
                            "id": output_project["id"],
                            "name": output_project["name"],
                            "display": output_project["display"]
                        })
                status = "disable"
                if user_data["disabled"] == False:
                    status = "enable"
                output = {
                    "id": user_data["id"],
                    "name": user_data["name"],
                    "email": user_data["email"],
                    "phone": user_data["phone"],
                    "login": user_data["login"],
                    "create_at": util.date_to_str(user_data["create_at"]),
                    "update_at": util.date_to_str(user_data["update_at"]),
                    "role": {
                        "name": user_data["role_name"],
                        "id": user_data["role_id"]
                    },
                    "project": project,
                    "status": status
                }
                output_array.append(output)
            return {
                "message": "success",
                "data": {
                    "user_list": output_array
                }
            }, 200
        else:
            return {"message": "Could not get user list"}, 400

    def get_userlist_by_project(self, logger, project_id, args):
        logger.debug("args[exclude] {0}".format(args["exclude"]))

        if args["exclude"] is not None and args["exclude"] == 1:
            # exclude project users
            select_all_user_cmd = "select distinct on (ur.id) pur.user_id as user_id, \
                ur.name as user_name, ur.email as email, ur.phone as phone, ur.login as login, \
                ur.create_at as create_at, ur.update_at as update_at, rl.id as role_id, \
                rl.name as role_name FROM public.user as ur, \
                public.project_user_role as pur , public.roles as rl \
                where ur.disabled is false and ur.id = pur.user_id and pur.role_id!=5 and\
                pur.role_id=rl.id ORDER BY ur.id DESC"

            logger.debug(
                "select_all_user_cmd: {0}".format(select_all_user_cmd))
            data_userRole_by_project_array = util.call_sqlalchemy(select_all_user_cmd).fetchall()
            logger.debug("data_userRole_by_project_array: {0}".format(
                data_userRole_by_project_array))
            select_user_in_this_project_list_cmd = "select distinct pur.user_id \
                from public.project_user_role pur, public.user ur , public.roles rl \
                where pur.project_id={0} and pur.role_id!=5 and pur.user_id=ur.id and \
                ur.disabled is false and pur.role_id=rl.id \
                order by pur.user_id DESC".format(project_id)
            logger.debug("select_user_in_this_project_list_cmd: {0}".format(
                select_user_in_this_project_list_cmd))
            select_user_in_this_project_list_output = util.call_sqlalchemy(
                select_user_in_this_project_list_cmd).fetchall()
            logger.debug("select_user_in_this_project_list_output: {0}".format(
                select_user_in_this_project_list_output))
            i = 0
            while i < len(data_userRole_by_project_array):
                j = 0
                while j < len(select_user_in_this_project_list_output):
                    # logger.debug("data_userRole_by_project_array['id']: {0}".format(data_userRole_by_project_array[i][0]))
                    # logger.debug("select_user_in_this_project_list: {0}".format(select_user_in_this_project_list_output[j][0]))
                    if data_userRole_by_project_array[i][
                            0] == select_user_in_this_project_list_output[j][
                                0]:
                        del data_userRole_by_project_array[i]
                    j += 1
                i += 1
                #logger.debug("j times: {0}".format(j))
            #logger.debug("i times: {0}".format(i))
            logger.debug("data_userRole_by_project_array: {0}".format(
                data_userRole_by_project_array))
        else:
            # in project users
            select_userRole_by_project = "SELECT distinct on (pur.user_id) pur.user_id as user_id, \
                ur.name as user_name, ur.email as email, ur.phone as phone, ur.login as login, \
                ur.create_at as create_at, ur.update_at as update_at, rl.id as role_id, \
                rl.name as role_name FROM\
                public.project_user_role as pur, public.user as ur, public.roles as rl \
                WHERE pur.project_id={0} AND pur.role_id!=5 AND pur.user_id=ur.id AND \
                ur.disabled=False AND pur.role_id=rl.id ORDER BY pur.user_id DESC".format(
                project_id)
            logger.debug("select_userRole_by_project: {0}".format(
                select_userRole_by_project))
            data_userRole_by_project_array = util.call_sqlalchemy(select_userRole_by_project).fetchall()

        user_list = []
        for data_userRole_by_project in data_userRole_by_project_array:
            logger.debug("data_userRole_by_project: {0}".format(
                data_userRole_by_project['user_id']))

            user_list.append({
                "id":
                data_userRole_by_project['user_id'],
                "name":
                data_userRole_by_project['user_name'],
                "email":
                data_userRole_by_project['email'],
                "phone":
                data_userRole_by_project['phone'],
                "login":
                data_userRole_by_project['login'],
                "create_at":
                    util.date_to_str(data_userRole_by_project['create_at']),
                "update_at":
                    util.date_to_str(data_userRole_by_project['update_at']),
                "role_id":
                data_userRole_by_project['role_id'],
                "role_name":
                data_userRole_by_project['role_name'],
            })
        return {"message": "success", "data": {"user_list": user_list}}, 200

    def project_add_member(self, project_id, args):
        # get role_id by user
        role_id = auth.get_roleID_by_userID(self, logger, args['user_id'])

        # Check ProjectUserRole table has relationship or not
        get_pj_ur_rl_cmd = db.select([ProjectUserRole.stru_project_user_role]).where(db.and_(\
            ProjectUserRole.stru_project_user_role.c.user_id==args['user_id'], \
            ProjectUserRole.stru_project_user_role.c.project_id==project_id,
            ProjectUserRole.stru_project_user_role.c.role_id==role_id))
        get_pj_ur_rl = util.call_sqlalchemy(get_pj_ur_rl_cmd).fetchone()
        # if ProjectUserRole table not has relationship
        if get_pj_ur_rl is None:
            # insert one relationship
            get_pj_ur_rl_cmd = db.insert(ProjectUserRole.stru_project_user_role).values(\
                project_id = project_id, user_id=args['user_id'], role_id=role_id)
            reMessage = util.call_sqlalchemy(get_pj_ur_rl_cmd)
        else:
            return {"message": "Projett_user_role table already has data"}, 400
        # get redmine_role_id from role_id
        redmine_role_id = auth.get_redmineRoleID_by_roleID(
            self, logger, role_id)

        # get redmine, gitlab user_id
        redmine_user_id = None
        gitlab_user_id = None
        user_relation = auth.get_user_plugin_relation(user_id=args['user_id'])
        logger.debug("user_relation_list: {0}".format(user_relation))
        if user_relation is not None:
            redmine_user_id = user_relation['plan_user_id']
            gitlab_user_id = user_relation['repository_user_id']
        else:
            return {"cloud not get user plug relation data"}, 400
        # get redmine, gitlab project id
        redmine_project_id = None
        gitlab_project_id = None
        project_relat = Project.get_project_plugin_relation(logger, project_id)
        if project_relat is not None:
            redmine_project_id = project_relat['plan_project_id']
            gitlab_project_id = project_relat['git_repository_id']
        else:
            return {"message": "Could not get project relationship data"}, 400
        if (redmine_role_id != None and redmine_user_id != None
                and redmine_project_id != None):
            self.redmine.rm_refresh_key()
            output, status_code = self.redmine.redmine_create_memberships(redmine_project_id, redmine_user_id,
                                                                          redmine_role_id)
            if status_code == 201:
                logger.debug(
                    "redmine add member success, output: {0}".format(output))
            elif status_code == 422:
                return {"message": "user alreay in redmine memebersip"}, 400
            else:
                return {"message": "redemine project add member error"}, 400
        else:
            return {
                "message": "Could not get redmine user or project or role id"
            }, 400

        # gitlab project add member
        if gitlab_project_id is not None and gitlab_user_id is not None:
            output = self.git.gl_project_add_member(gitlab_project_id, gitlab_user_id)
            status_code = output.status_code
            if status_code == 201:
                logger.debug(
                    "gitlab add member success, output: {0}".format(output))
            else:
                return {"message": "gitlab project add member error"}, 400
        else:
            logger.info("gitlab do not has this project")
        return {"message": "success"}, 200

    def project_delete_member(self, logger, app, project_id, user_id):
        # get role_id
        role_id = auth.get_roleID_by_userID(self, logger, user_id)

        # get redmine, gitlab user_id
        redmine_user_id = None
        gitlab_user_id = None
        user_relation = auth.get_user_plugin_relation(user_id=user_id)
        logger.debug("user_relation_list: {0}".format(user_relation))
        if user_relation is not None:
            redmine_user_id = user_relation['plan_user_id']
            gitlab_user_id = user_relation['repository_user_id']
        else:
            return {"cloud not get user plug relation data"}, 400

        project_relat = Project.get_project_plugin_relation(logger, project_id)
        if project_relat is not None:
            redmine_project_id = project_relat['plan_project_id']
            gitlab_project_id = project_relat['git_repository_id']
        else:
            return {"message": "Could not get project relationship data"}, 400

        if (redmine_user_id != None and redmine_project_id != None):
            # get memebership id
            memeberships, status_code = self.redmine.rm_get_memberships_list(redmine_project_id)
            redmine_membership_id = None
            if status_code == 200:
                for membership in memeberships.json()['memberships']:
                    if membership['user']['id'] == redmine_user_id:
                        redmine_membership_id = membership['id']
            if redmine_membership_id is not None:
                #delete membership
                output, status_code = self.redmine.rm_delete_memberships(redmine_membership_id)
                if status_code == 204:
                    logger.debug(
                        "redmine delete membership success, output: {0}".
                        format(output))
                elif status_code == 422:
                    return {
                        "message": "user alreay in redmine memebersip"
                    }, 400
                else:
                    return {
                        "message": "redemine project delete member error"
                    }, 400
            else:
                return {"message": "could not get redmine membership id"}, 400
        else:
            return {
                "message": "Could not get redmine user: {0} or project: {1}"\
            .format(redmine_project_id, redmine_user_id)}, 400

        # delete relationship from  ProjectUserRole table.
        delete_pj_ur_rl_cmd = db.delete(ProjectUserRole.stru_project_user_role).where(db.and_(\
            ProjectUserRole.stru_project_user_role.c.user_id==user_id, \
            ProjectUserRole.stru_project_user_role.c.project_id==project_id,
            ProjectUserRole.stru_project_user_role.c.role_id==role_id))
        delete_pj_ur_rl = util.call_sqlalchemy(delete_pj_ur_rl_cmd)

        # gitlab project delete member
        if gitlab_project_id is not None and gitlab_user_id is not None:
            output = self.git.gl_project_delete_member(gitlab_project_id, gitlab_user_id)
            status_code = output.status_code
            if status_code == 204:
                logger.debug("gitlab delete member success, output")
            else:
                return {"message": "gitlab project delete member error"}, 400
        else:
            logger.debug("gitlab do not has this project")
        return {"message": "success"}, 200

    # 從db role table取得role list
    def get_role_list(self, logger, app):
        result = db.engine.execute(
            "SELECT * FROM public.roles ORDER BY id ASC")
        role_array = result.fetchall()
        result.close()

        if role_array:
            output_array = []
            for role in role_array:
                role_info = {"id": role["id"], "name": role["name"]}
                output_array.append(role_info)

            return {
                "message": "success",
                "data": {
                    "role_list": output_array
                }
            }, 200
        else:
            return {"message": "Could not get role list"}, 400

    def get_useridname_by_planuserid(self, logger, plan_user_id):
        get_useridname_cmd = db.select([UserPluginRelation.stru_user_plug_relation,
                                User.stru_user]).where(db.and_(\
            UserPluginRelation.stru_user_plug_relation.c.plan_user_id==plan_user_id,
            UserPluginRelation.stru_user_plug_relation.c.user_id==User.stru_user.c.id))
        return util.call_sqlalchemy(get_useridname_cmd).fetchone()
