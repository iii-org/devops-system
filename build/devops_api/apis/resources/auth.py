import datetime
import requests
import json
from Cryptodome.Hash import SHA256

from .util import util
from .redmine import Redmine
from .gitlab import GitLab
from model import db, User, UserPluginRelation, ProjectUserRole, TableProjects, TableRole

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

    def __init__(self, logger, app):
        self.redmine_key = None
        self.headers = {'Content-Type': 'application/json'}

        if app.config["GITLAB_API_VERSION"] == "v3":
            # get gitlab admin token
            url = "http://{0}/api/v3/session".format(\
                app.config["GITLAB_IP_PORT"])
            parame = {}
            parame["login"] = app.config["GITLAB_ADMIN_ACCOUNT"]
            parame["password"] = app.config["GITLAB_ADMIN_PASSWORD"]

            output = requests.post(url,
                                   data=json.dumps(parame),
                                   headers=self.headers,
                                   verify=False)
            # logger.info("private_token api output: {0}".format(output))
            self.private_token = output.json()['private_token']
        else:
            self.private_token = app.config["GITLAB_PRIVATE_TOKEN"]

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
            if row['login'] == args["login"] and row[
                    'password'] == h.hexdigest():
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
            if row['login'] == args["login"] and row['email'] == args["email"]:
                # sent reset password url to mail
                logger.info(
                    "user_forgetpassword API: login and mail were correct")

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
                "phone": int(user_data["phone"]),
                "login": user_data["login"],
                "create_at": util.dateToStr(self, user_data["create_at"]),
                "update_at": util.dateToStr(self, user_data["update_at"]),
                "role_name": user_data["role_name"],
                "role_id": user_data["role_id"],
                "status": status
            }
            # get user involve project list
            select_project = db.select([ProjectUserRole.stru_project_user_role, \
                TableProjects.stru_projects]).where(db.and_(\
                ProjectUserRole.stru_project_user_role.c.user_id==user_id, \
                ProjectUserRole.stru_project_user_role.c.project_id==\
                TableProjects.stru_projects.c.id))
            logger.debug("select_project: {0}".format(select_project))
            reMessage = util.callsqlalchemy(self, select_project,
                                            logger).fetchall()
            logger.debug("reMessage: {0}".format(reMessage))
            if reMessage:
                project_list = []
                for project in reMessage:
                    logger.debug("project: {0}".format(project["name"]))
                    project_list.append({
                        "id": project["id"],
                        "name": project["name"]
                    })
                output["project"] = project_list
            else:
                output["project"] = []

            return {'message': 'success', 'data': output}, 200
        else:
            return {"message": "Could not found user information"}, 400

    def update_user_info(self, logger, user_id, args):
        #Check user id disabled or not.
        select_user_to_disable_command = db.select([User.stru_user])\
            .where(db.and_(User.stru_user.c.id==user_id))
        logger.debug("select_user_to_disable_command: {0}".format(
            select_user_to_disable_command))
        user_data = util.callsqlalchemy(self, select_user_to_disable_command,
                                        logger).fetchone()
        set_string = ""
        if args["name"] is not None:
            set_string += "name = '{0}'".format(args["name"])
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
        logger.debug("update db reslut: {0}".format(result))
        # update project_user_role
        if args["project_id"] is not None:
            # get user role_id
            select_pjuerl_by_userid = db.select([ProjectUserRole.stru_project_user_role]).where(db.and_(\
                ProjectUserRole.stru_project_user_role.c.user_id==user_id))
            logger.debug(
                "select_pjuerl_by_userid: {0}".format(select_pjuerl_by_userid))
            data_pjuerl_by_userid = util.callsqlalchemy(
                self, select_pjuerl_by_userid, logger).fetchone()
            logger.debug(
                "data_pjuerl_by_userid: {0}".format(data_pjuerl_by_userid))

            for project_id in args["project_id"]:
                select_pjuerl_by_userpjtrl = db.select([ProjectUserRole.stru_project_user_role]).where(db.and_(\
                ProjectUserRole.stru_project_user_role.c.user_id==user_id,\
                ProjectUserRole.stru_project_user_role.c.project_id==project_id,\
                ProjectUserRole.stru_project_user_role.c.role_id==data_pjuerl_by_userid['role_id']))
                logger.debug("select_pjuerl_by_userpjtrl: {0}".format(
                    select_pjuerl_by_userpjtrl))
                data_pjuerl_by_userpjtrl = util.callsqlalchemy(
                    self, select_pjuerl_by_userpjtrl, logger).fetchone()
                logger.debug("data_pjuerl_by_userpjtrl: {0}".format(
                    data_pjuerl_by_userpjtrl))

                if not data_pjuerl_by_userpjtrl:
                    # insert role and user into project_user_role
                    insert_project_user_role_command = db.insert(ProjectUserRole.stru_project_user_role)\
                        .values(user_id = user_id, role_id = data_pjuerl_by_userid['role_id'], project_id = project_id)
                    logger.debug(
                        "insert_project_user_role_command: {0}".format(
                            insert_project_user_role_command))
                    reMessage = util.callsqlalchemy(
                        self, insert_project_user_role_command, logger)
                    logger.info("reMessage: {0}".format(reMessage))

        return {'message': 'success'}, 200

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
            app.config["GITLAB_IP_PORT"], app.config["GITLAB_API_VERSION"], gitlab_user_id, self.private_token)
        logger.info("delete gitlab user url: {0}".format(gitlab_url))
        gitlab_output = requests.delete(gitlab_url,
                                        headers=self.headers,
                                        verify=False)
        logger.info("delete gitlab user output: {0}".format(gitlab_output))
        # 如果gitlab user成功被刪除則繼續刪除redmine user
        if gitlab_output.status_code == 204:
            redmine_url = "http://{0}/users/{1}.json?key={2}".format(\
                app.config["REDMINE_IP_PORT"], redmine_user_id, app.config["REDMINE_API_KEY"])
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
        reMessage = util.callsqlalchemy(self, update_user_to_disable_command,
                                        logger)
        logger.info("reMessage: {0}".format(reMessage))
        return {'message': 'success'}, 200

    def create_user(self, logger, args, app):
        ''' create user in plan phase software(redmine) and repository_user_id(gitlab)
        Create DB user, user_plugin_relation, project_user_role, groups_has_users 4 table
        '''
        user_source_password = args["password"]
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
        red_user = Redmine.redmine_post_user(self, logger, app, args,
                                             user_source_password)
        if red_user.status_code == 201:
            redmine_user_id = red_user.json()['user']['id']
        else:
            return {
                "message": {
                    "redmine": red_user.json()
                }
            }, red_user.status_code
        # git software user create
        git_user = GitLab.create_user(self, logger, app, args,
                                      user_source_password)
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

        if args["project_id"] is not None:
            for project_id in args["project_id"]:
                # insert role and user into project_user_role
                insert_project_user_role_command = db.insert(ProjectUserRole.stru_project_user_role)\
                    .values(user_id = user_id, role_id = args['role_id'], project_id = project_id)
                logger.debug("insert_project_user_role_command: {0}".format(
                    insert_project_user_role_command))
                reMessage = util.callsqlalchemy(
                    self, insert_project_user_role_command, logger)
                logger.info("reMessage: {0}".format(reMessage))

        insert_project_user_role_command = db.insert(ProjectUserRole.stru_project_user_role)\
            .values(user_id = user_id, role_id = args['role_id'])
        logger.debug("insert_project_user_role_command: {0}".format(
            insert_project_user_role_command))
        reMessage = util.callsqlalchemy(self, insert_project_user_role_command,
                                        logger)
        logger.info("reMessage: {0}".format(reMessage))

        return {"message": "success", "data": {"user_id": user_id}}, 200

    def get_user_plugin_relation(self, logger):
        get_user_plugin_relation_command = db.select(
            [UserPluginRelation.stru_user_plug_relation])
        logger.debug("get_user_plugin_relation_command: {0}".format(
            get_user_plugin_relation_command))
        reMessage = util.callsqlalchemy(self, get_user_plugin_relation_command,
                                        logger)
        user_plugin_relation_array = reMessage.fetchall()
        return user_plugin_relation_array

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
            ORDER BY ur.id ASC")
        user_data_array = result.fetchall()
        result.close()
        if user_data_array:
            output_array = []
            for user_data in user_data_array:
                logger.info("user_data: {0}".format(user_data))
                select_project_by_userid = db.select([ProjectUserRole.stru_project_user_role, \
                    TableProjects.stru_projects]).where(db.and_(\
                    ProjectUserRole.stru_project_user_role.c.user_id==user_data["id"], \
                    ProjectUserRole.stru_project_user_role.c.project_id==\
                    TableProjects.stru_projects.c.id))
                output_project_array = util.callsqlalchemy(
                    self, select_project_by_userid, logger).fetchall()
                logger.debug(
                    "output_project: {0}".format(output_project_array))
                project = []
                if output_project_array:
                    for output_project in output_project_array:
                        project.append({
                            "id": output_project["id"],
                            "name": output_project["name"]
                        })
                status = "disable"
                if user_data["disabled"] == False:
                    status = "enable"
                output = {
                    "id": user_data["id"],
                    "name": user_data["name"],
                    "email": user_data["email"],
                    "phone": int(user_data["phone"]),
                    "login": user_data["login"],
                    "create_at": util.dateToStr(self, user_data["create_at"]),
                    "update_at": util.dateToStr(self, user_data["update_at"]),
                    "role_name": user_data["role_name"],
                    "role_id": user_data["role_id"],
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
            select_userRole_by_project = db.select([ProjectUserRole.stru_project_user_role, \
            User.stru_user, TableRole.stru_role])\
            .where(db.and_(ProjectUserRole.stru_project_user_role.c.project_id!=project_id,\
            ProjectUserRole.stru_project_user_role.c.role_id!=5,\
            ProjectUserRole.stru_project_user_role.c.user_id==User.stru_user.c.id,\
            User.stru_user.c.disabled == False,\
            ProjectUserRole.stru_project_user_role.c.role_id==TableRole.stru_role.c.id))\
            .distinct(ProjectUserRole.stru_project_user_role.c.user_id)\
            .order_by(db.desc(ProjectUserRole.stru_project_user_role.c.user_id))
            logger.debug("select_userRole_by_project: {0}".format(
                select_userRole_by_project))
            data_userRole_by_project_array = util.callsqlalchemy(
                self, select_userRole_by_project, logger).fetchall()
            logger.debug("data_userRole_by_project_array: {0}".format(
                data_userRole_by_project_array))

            # get user list when project is project_id
            select_userid_by_project_array = db.select([ProjectUserRole.stru_project_user_role]) \
                .where(db.and_(ProjectUserRole.stru_project_user_role.c.project_id==project_id))
            data_userid_by_project_array = util.callsqlalchemy(
                self, select_userid_by_project_array, logger).fetchall()
            logger.debug("data_userid_by_project_array: {0}".format(
                data_userid_by_project_array))

            count_duplicate = []
            for data_userRole_by_project in data_userRole_by_project_array:
                for data_userid_by_project in data_userid_by_project_array:
                    if data_userRole_by_project[ProjectUserRole.stru_project_user_role.c.user_id]\
                        == data_userid_by_project[ProjectUserRole.stru_project_user_role.c.user_id]:
                        logger.debug(type(data_userRole_by_project))
                        count_duplicate.append(data_userRole_by_project[
                            ProjectUserRole.stru_project_user_role.c.user_id])
            count_duplicate = list(set(count_duplicate))
            logger.debug("count_duplicate: {0}".format(count_duplicate))
            i = 0
            while i < len(data_userRole_by_project_array):
                if data_userRole_by_project_array[i][
                        ProjectUserRole.stru_project_user_role.c.
                        user_id] in count_duplicate:
                    data_userRole_by_project_array.pop(i)
                else:
                    i += 1
            logger.debug("data_userRole_by_project_array: {0}".format(
                data_userRole_by_project_array))

        else:
            # in project users
            select_userRole_by_project = db.select([ProjectUserRole.stru_project_user_role, \
            User.stru_user, TableRole.stru_role])\
            .where(db.and_(ProjectUserRole.stru_project_user_role.c.project_id==project_id,\
            ProjectUserRole.stru_project_user_role.c.role_id!=5,\
            ProjectUserRole.stru_project_user_role.c.user_id==User.stru_user.c.id,\
            User.stru_user.c.disabled == False,\
            ProjectUserRole.stru_project_user_role.c.role_id==TableRole.stru_role.c.id))\
            .distinct(ProjectUserRole.stru_project_user_role.c.user_id)\
            .order_by(db.desc(ProjectUserRole.stru_project_user_role.c.user_id))
            logger.debug("select_userRole_by_project: {0}".format(
                select_userRole_by_project))
            data_userRole_by_project_array = util.callsqlalchemy(
                self, select_userRole_by_project, logger).fetchall()

        user_list = []
        for data_userRole_by_project in data_userRole_by_project_array:
            logger.debug("data_userRole_by_project: {0}".format(
                data_userRole_by_project[
                    ProjectUserRole.stru_project_user_role.c.user_id]))
            status = "disable"
            if data_userRole_by_project[User.stru_user.c.disabled] == False:
                status = "enable"

            user_list.append({
                "id":
                data_userRole_by_project[
                    ProjectUserRole.stru_project_user_role.c.user_id],
                "name":
                data_userRole_by_project[User.stru_user.c.name],
                "email":
                data_userRole_by_project[User.stru_user.c.email],
                "phone":
                int(data_userRole_by_project[User.stru_user.c.phone]),
                "login":
                data_userRole_by_project[User.stru_user.c.login],
                "create_at":
                util.dateToStr(
                    self,
                    data_userRole_by_project[User.stru_user.c.create_at]),
                "update_at":
                util.dateToStr(
                    self,
                    data_userRole_by_project[User.stru_user.c.update_at]),
                "role_id":
                data_userRole_by_project[TableRole.stru_role.c.id],
                "role_name":
                data_userRole_by_project[TableRole.stru_role.c.name],
                "project_id":
                data_userRole_by_project[
                    ProjectUserRole.stru_project_user_role.c.project_id],
                "status":
                status
            })
        return {"message": "success", "data": {"user_list": user_list}}, 200

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
