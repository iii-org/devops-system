import datetime
import logging
import re

from Cryptodome.Hash import SHA256
from flask_jwt_extended import (create_access_token, JWTManager)

import config
import resources.apiError as apiError
import resources.util as util
from model import User as UserModel
from model import db, UserPluginRelation, ProjectUserRole, TableProjects, ProjectPluginRelation, \
    TableRolesPluginRelation
import resources.project as pjt

from api import logger

jwt = JWTManager()


@jwt.user_claims_loader
def jwt_response_data(row):
    return {
        'user_id': row['id'],
        'user_account': row["login"],
        'role_id': row['role_id'],
        'role_name': row['role_name']
    }


def get_3pt_user_ids(user_id, message):
    user_relation = User.get_user_plugin_relation(user_id=user_id)
    if user_relation is None:
        return util.respond(400, message,
                            error=apiError.user_not_found(user_id)), None, None
    redmine_user_id = user_relation['plan_user_id']
    gitlab_user_id = user_relation['repository_user_id']
    if redmine_user_id is None:
        return util.respond(500, message,
                            error=apiError.db_error(
                                "Cannot get redmine id of the user.")), None, None
    if gitlab_user_id is None:
        return util.respond(500, message,
                            error=apiError.db_error(
                                "Gitlab does not have this user.")), None, None
    return None, redmine_user_id, gitlab_user_id


def get_3pt_project_ids(project_id, message):
    project_relation = pjt.get_project_plugin_relation(project_id)
    if project_relation is None:
        return util.respond(400, message,
                            error=apiError.project_not_found(project_id)), None, None
    redmine_project_id = project_relation['plan_project_id']
    gitlab_project_id = project_relation['git_repository_id']

    if redmine_project_id is None:
        return util.respond(500, message,
                            error=apiError.db_error(
                                "Cannot get redmine id of the project.")), None, None
    if gitlab_project_id is None:
        return util.respond(500, message,
                            error=apiError.db_error(
                                "Gitlab does not have this project.")), None, None

    return None, redmine_project_id, gitlab_project_id


class User(object):
    def __init__(self, redmine, git):
        self.redmine = redmine
        self.git = git

    @staticmethod
    def get_role_id(user_id):
        get_rl_cmd = db.select([ProjectUserRole.stru_project_user_role]).where(db.and_(
            ProjectUserRole.stru_project_user_role.c.user_id == user_id))
        get_role_out = util.call_sqlalchemy(get_rl_cmd).fetchone()
        if get_role_out is not None:
            role_id = get_role_out['role_id']
            return role_id
        else:
            return util.respond(404, 'Error while getting role id',
                                error=apiError.user_not_found(user_id))

    @staticmethod
    def to_redmine_role_id(role_id):
        command = db.select([TableRolesPluginRelation.stru_rolerelation]).where(
            db.and_(TableRolesPluginRelation.stru_rolerelation.c.role_id == role_id))
        ret_msg = util.call_sqlalchemy(command).fetchone()
        return ret_msg['plan_role_id']

    @staticmethod
    def login(args):
        h = SHA256.new()
        h.update(args["password"].encode())
        result = db.engine.execute(
            "SELECT ur.id, ur.login, ur.password, pur.role_id,"
            " rl.name as role_name"
            " FROM public.user as ur, public.project_user_role as pur, public.roles as rl"
            " WHERE ur.disabled = false AND ur.id = pur.user_id AND pur.role_id = rl.id"
        )
        for row in result:
            if row['login'] == args["username"] and row['password'] == h.hexdigest():
                if args["username"] == "admin":
                    expires = datetime.timedelta(days=36500)
                else:
                    expires = datetime.timedelta(days=1)
                access_token = create_access_token(
                    identity=jwt_response_data(row),
                    expires_delta=expires)
                return util.success({'token': access_token})
        return util.respond(401, "Error when logging in.", error=apiError.wrong_password())

    @staticmethod
    def user_forgot_password(args):
        result = db.engine.execute("SELECT login, email FROM public.user")
        for row in result:
            if row['login'] == args["user_account"] and row['email'] == args["mail"]:
                pass
                logger.info(
                    "user_forgot_password API: user_account and mail were correct"
                )

    # noinspection PyMethodMayBeStatic
    def get_user_info(self, user_id):
        result = db.engine.execute(
            "SELECT ur.id as id, ur.name as name,"
            " ur.email as email, ur.phone as phone, ur.login as login, ur.create_at as create_at,"
            " ur.update_at as update_at, rl.id as role_id, rl.name as role_name, ur.disabled as disabled"
            " FROM public.user as ur, public.project_user_role as pur, public.roles as rl"
            " WHERE ur.id = {0} AND ur.id = pur.user_id AND pur.role_id = rl.id".format(user_id))
        user_data = result.fetchone()
        result.close()

        if user_data:
            if user_data["disabled"] is True:
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
            # get user's involved project list
            select_project = db.select([ProjectUserRole.stru_project_user_role,
                                        TableProjects.stru_projects,
                                        ProjectPluginRelation.stru_project_plug_relation]).where(
                db.and_(
                    ProjectUserRole.stru_project_user_role.c.user_id == user_id,
                    ProjectUserRole.stru_project_user_role.c.project_id != -1,
                    ProjectUserRole.stru_project_user_role.c.project_id ==
                    TableProjects.stru_projects.c.id,
                    ProjectUserRole.stru_project_user_role.c.project_id ==
                    ProjectPluginRelation.stru_project_plug_relation.c.project_id))
            result = util.call_sqlalchemy(select_project).fetchall()
            if len(result) > 0:
                project_list = []
                for project in result:
                    project_list.append({
                        "id": project["id"],
                        "name": project["name"],
                        "display": project["display"],
                        "repository_id": project["git_repository_id"]
                    })
                output["project"] = project_list
            else:
                output["project"] = []

            return util.success(output)
        else:
            return util.respond(404, "User not found.", error=apiError.user_not_found(user_id))

    def update_info(self, user_id, args):
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

        return util.success()

    def update_external_passwords(self, user_id, new_pwd):
        user_relation = User.get_user_plugin_relation(user_id=user_id)
        logger.debug("user_relation_list: {0}".format(user_relation))
        if user_relation is None:
            return util.respond(400, 'Error when updating password',
                                error=apiError.user_not_found(user_id))
        redmine_user_id = user_relation['plan_user_id']
        err = self.redmine.rm_update_password(redmine_user_id, new_pwd)
        if err is not None:
            return err

        gitlab_user_id = user_relation['repository_user_id']
        err = self.git.gl_update_password(gitlab_user_id, new_pwd)
        if err is not None:
            return err

        return None

    def delete_user(self, user_id):
        # 取得gitlab & redmine user_id
        result = db.engine.execute(
            "SELECT * FROM public.user_plugin_relation WHERE user_id = '{0}'".format(user_id))
        user_relation = result.fetchone()
        result.close()
        gitlab_user_id = user_relation["repository_user_id"]
        # 刪除gitlab user
        gitlab_response = self.git.gl_delete_user(gitlab_user_id)
        if gitlab_response.status_code != 204:
            return util.respond(gitlab_response.status_code, "Error when deleting user.",
                                error=apiError.gitlab_error(gitlab_response))

        # 如果gitlab user成功被刪除則繼續刪除redmine user
        redmine_user_id = user_relation["plan_user_id"]
        redmine_output, redmine_status_code = self.redmine.rm_delete_user(redmine_user_id)
        if redmine_output.status_code != 204:
            return util.respond(redmine_status_code, "Error when deleting user.",
                                error=apiError.redmine_error(redmine_output))

        # 如果gitlab & redmine user都成功被刪除則繼續刪除db內相關tables欄位
        db.engine.execute(
            "DELETE FROM public.user_plugin_relation WHERE user_id = '{0}'".format(user_id))
        db.engine.execute(
            "DELETE FROM public.project_user_role WHERE user_id = '{0}'".format(user_id))
        db.engine.execute(
            "DELETE FROM public.user WHERE id = '{0}'".format(user_id))

        return util.success()

    @staticmethod
    def change_user_status(user_id, args):
        disabled = False
        if args["status"] == "enable":
            disabled = False
        elif args["status"] == "disable":
            disabled = True
        update_user_to_disable_command = db.update(UserModel.stru_user).where(
            db.and_(UserModel.stru_user.c.id == user_id)).values(
            update_at=datetime.datetime.now(), disabled=disabled)
        ret_msg = util.call_sqlalchemy(update_user_to_disable_command)
        logger.info("update_user_to_disable_command: {0}; ret_msg: {1}".format(
            update_user_to_disable_command, ret_msg))
        return {'message': 'success'}, 200

    def create_user(self, args):
        """
        Create user in plan phase software(redmine) and repository_user_id(gitlab)
        Create DB user, user_plugin_relation, project_user_role, groups_has_users 4 table
        """

        # Check if name is valid
        login = args['login']
        if re.fullmatch(r'^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,58}[a-zA-Z0-9]$', login) is None:
            return util.respond(400, "Error when creating new user",
                                error=apiError.invalid_user_name(login))

        user_source_password = args["password"]
        if re.fullmatch(r'(?=.*\d)(?=.*[a-z])(?=.*[A-Z])'
                        r'^[\w!@#$%^&*()+|{}\[\]`~\-\'\";:/?.\\>,<]{8,20}$',
                        user_source_password) is None:
            return util.respond(400, "Error when creating new user",
                                error=apiError.invalid_user_password())

        # Check DB has this login, email, if has, return error
        check_email_login_command = db.select([UserModel.stru_user]).where(
            db.or_(UserModel.stru_user.c.login == args['login'],
                   UserModel.stru_user.c.email == args['email']))
        ret_msg = util.call_sqlalchemy(check_email_login_command)
        user_info = ret_msg.fetchone()
        if user_info is not None:
            return util.respond(422, "System already has this account or email.",
                                error=apiError.already_used())
        offset = 0
        limit = 25
        total_count = 1
        while offset < total_count:
            params = {'offset': offset, 'limit': limit}
            user_list_output, status_code = self.redmine.rm_get_user_list(params)
            try:
                user_list_output = user_list_output.json()
            except Exception:
                return util.respond(500, "Error while creating user.",
                                    error=apiError.redmine_error(user_list_output))

            total_count = user_list_output['total_count']
            for user in user_list_output['users']:
                if user['login'] == args['login'] or user['mail'] == args['email']:
                    return util.respond(422, "Redmine already has this account or email.",
                                        error=apiError.already_used())
            offset += limit
        # Check Gitlab has this login, email, if has, return error 400
        page = 1
        x_total_pages = 10
        while page <= x_total_pages:
            params = {'page': page}
            user_list_output = self.git.gl_get_user_list(params)
            x_total_pages = int(user_list_output.headers['X-Total-Pages'])
            for user in user_list_output.json():
                logger.debug("gitlab login: {0}, email: {1}".format(
                    user['name'], user['email']))
                if user['name'] == args['login'] or user['email'] == args['email']:
                    return util.respond(422, "Gitlab already has this account or email.",
                                        error=apiError.already_used())
            page += 1

        # plan software user create
        red_user = self.redmine.rm_create_user(args, user_source_password)
        if red_user.status_code == 201:
            redmine_user_id = red_user.json()['user']['id']
        else:
            return util.respond(red_user.status_code, "Error while creating user.",
                                error=apiError.redmine_error(red_user))

        # gitlab software user create
        git_user = self.git.gl_create_user(args, user_source_password)
        if git_user.status_code == 201:
            gitlab_user_id = git_user.json()['id']
        else:
            # delete redmine user
            self.redmine.rm_delete_user(redmine_user_id)
            return util.respond(git_user.status_code, "Error while creating user.",
                                error=apiError.gitlab_error(git_user))

        h = SHA256.new()
        h.update(args["password"].encode())
        args["password"] = h.hexdigest()
        disabled = False
        if args['status'] == "disable":
            disabled = True
        insert_user_command = db.insert(UserModel.stru_user).values(
            name=args['name'],
            email=args['email'],
            phone=args['phone'],
            login=args['login'],
            password=h.hexdigest(),
            create_at=datetime.datetime.now(),
            disabled=disabled)

        util.call_sqlalchemy(insert_user_command)

        # get user_id
        get_user_command = db.select([UserModel.stru_user]).where(
            db.and_(UserModel.stru_user.c.login == args['login']))
        ret_msg = util.call_sqlalchemy(get_user_command)
        user_id = ret_msg.fetchone()['id']

        # insert user_plugin_relation table
        insert_user_plugin_relation_command = db.insert(
            UserPluginRelation.stru_user_plug_relation
        ).values(
            user_id=user_id, plan_user_id=redmine_user_id,
            repository_user_id=gitlab_user_id
        )
        util.call_sqlalchemy(insert_user_plugin_relation_command)

        # insert project_user_role
        insert_project_user_role_command = db.insert(
            ProjectUserRole.stru_project_user_role).values(
            project_id=-1, user_id=user_id, role_id=args['role_id'])
        util.call_sqlalchemy(insert_project_user_role_command)

        return util.success({"user_id": user_id})

    @staticmethod
    def get_user_plugin_relation(user_id=None, plan_user_id=None, repository_user_id=None):
        if plan_user_id is not None:
            get_user_plugin_relation_command = db.select(
                [UserPluginRelation.stru_user_plug_relation]).where(
                db.and_(
                    UserPluginRelation.stru_user_plug_relation.c.plan_user_id == plan_user_id))
        elif repository_user_id is not None:
            get_user_plugin_relation_command = db.select(
                [UserPluginRelation.stru_user_plug_relation]).where(
                db.and_(
                    UserPluginRelation.stru_user_plug_relation.c.repository_user_id == repository_user_id))
        else:
            get_user_plugin_relation_command = db.select(
                [UserPluginRelation.stru_user_plug_relation]).where(
                db.and_(
                    UserPluginRelation.stru_user_plug_relation.c.user_id == user_id))
        ret_msg = db.engine.execute(get_user_plugin_relation_command)
        user_plugin_relation = ret_msg.fetchone()
        return user_plugin_relation

    @staticmethod
    def user_list():
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
        if not user_data_array:
            return util.respond(500, 'Cannot get user list.',
                                error=apiError.db_error('Cannot query user list'))
        output_array = []
        for user_data in user_data_array:
            select_project_by_userid = db.select(
                [ProjectUserRole.stru_project_user_role,
                 TableProjects.stru_projects]).where(
                db.and_(
                    ProjectUserRole.stru_project_user_role.c.user_id == user_data["id"],
                    ProjectUserRole.stru_project_user_role.c.project_id != -1,
                    ProjectUserRole.stru_project_user_role.c.project_id ==
                    TableProjects.stru_projects.c.id))
            output_project_array = util.call_sqlalchemy(select_project_by_userid).fetchall()
            project = []
            if output_project_array:
                for output_project in output_project_array:
                    project.append({
                        "id": output_project["id"],
                        "name": output_project["name"],
                        "display": output_project["display"]
                    })
            status = "disable"
            if user_data["disabled"] is False:
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
        return util.success({"user_list": output_array})

    @staticmethod
    def user_list_by_project(project_id, args):
        if args["exclude"] is not None and args["exclude"] == 1:
            # list users not in the project
            cmd_legal_users = "select distinct on (ur.id) pur.user_id as user_id, \
                ur.name as user_name, ur.email as email, ur.phone as phone, ur.login as login, \
                ur.create_at as create_at, ur.update_at as update_at, rl.id as role_id, \
                rl.name as role_name FROM public.user as ur, \
                public.project_user_role as pur , public.roles as rl \
                where ur.disabled is false and ur.id = pur.user_id and pur.role_id!=5 and\
                pur.role_id=rl.id ORDER BY ur.id DESC"
            ret_users = util.call_sqlalchemy(cmd_legal_users).fetchall()

            cmd_project_users = "select distinct pur.user_id \
                from public.project_user_role pur, public.user ur , public.roles rl \
                where pur.project_id={0} and pur.role_id!=5 and pur.user_id=ur.id and \
                ur.disabled is false and pur.role_id=rl.id \
                order by pur.user_id DESC".format(project_id)
            project_users = util.call_sqlalchemy(cmd_project_users).fetchall()

            i = 0
            while i < len(ret_users):
                for pu in project_users:
                    if ret_users[i][0] == pu[0]:
                        del ret_users[i]
                        break
                i += 1
        else:
            # list users in the project
            cmd_project_users = "SELECT distinct on (pur.user_id) pur.user_id as user_id, \
                ur.name as user_name, ur.email as email, ur.phone as phone, ur.login as login, \
                ur.create_at as create_at, ur.update_at as update_at, rl.id as role_id, \
                rl.name as role_name FROM\
                public.project_user_role as pur, public.user as ur, public.roles as rl \
                WHERE pur.project_id={0} AND pur.role_id!=5 AND pur.user_id=ur.id AND \
                ur.disabled=False AND pur.role_id=rl.id ORDER BY pur.user_id DESC".format(
                project_id)
            ret_users = util.call_sqlalchemy(cmd_project_users).fetchall()

        user_list = []
        for data_userRole_by_project in ret_users:
            user_list.append({
                "id": data_userRole_by_project['user_id'],
                "name": data_userRole_by_project['user_name'],
                "email": data_userRole_by_project['email'],
                "phone": data_userRole_by_project['phone'],
                "login": data_userRole_by_project['login'],
                "create_at": util.date_to_str(data_userRole_by_project['create_at']),
                "update_at": util.date_to_str(data_userRole_by_project['update_at']),
                "role_id": data_userRole_by_project['role_id'],
                "role_name": data_userRole_by_project['role_name'],
            })
        return util.success({"user_list": user_list})

    def project_add_member(self, project_id, args):
        user_id = args['user_id']
        role_id = User.get_role_id(user_id)

        # Check ProjectUserRole table has relationship or not
        get_pj_ur_rl_cmd = db.select([ProjectUserRole.stru_project_user_role]).where(db.and_(
            ProjectUserRole.stru_project_user_role.c.user_id == user_id,
            ProjectUserRole.stru_project_user_role.c.project_id == project_id,
            ProjectUserRole.stru_project_user_role.c.role_id == role_id))
        get_pj_ur_rl = util.call_sqlalchemy(get_pj_ur_rl_cmd).fetchone()
        # if ProjectUserRole table not has relationship
        if get_pj_ur_rl is None:
            # insert one relationship
            get_pj_ur_rl_cmd = db.insert(ProjectUserRole.stru_project_user_role).values(
                project_id=project_id, user_id=user_id, role_id=role_id)
            util.call_sqlalchemy(get_pj_ur_rl_cmd)
        else:
            return util.respond(422, "Error while adding user to project.",
                                error=apiError.already_in_project(user_id, project_id))

        error, redmine_user_id, gitlab_user_id = get_3pt_user_ids(
            user_id,
            "Error while adding user to project.")
        if error is not None:
            return error
        error, redmine_project_id, gitlab_project_id = get_3pt_project_ids(
            project_id,
            "Error while adding user to project.")
        if error is not None:
            return error

        redmine_role_id = User.to_redmine_role_id(role_id)
        if redmine_role_id is None:
            return util.respond(500, "Error while adding user to project.",
                                error=apiError.db_error("Cannot get redmine role of the user."))

        output, status_code = self.redmine.rm_create_memberships(
            redmine_project_id, redmine_user_id, redmine_role_id)
        if status_code == 201:
            pass
        elif status_code == 422:
            return util.respond(422, "Error while adding user to project: Already in redmine project.",
                                error=apiError.already_in_project(user_id, project_id))
        else:
            return util.respond(status_code, "Error while adding user to project.",
                                error=apiError.redmine_error(output))

        # gitlab project add member
        output = self.git.gl_project_add_member(gitlab_project_id, gitlab_user_id)
        status_code = output.status_code
        if status_code == 201:
            return util.success()
        else:
            return util.respond(status_code, "Error while removing user from project.",
                                error=apiError.gitlab_error(output))

    def remove_from_project(self, project_id, user_id):
        role_id = User.get_role_id(user_id)

        error, redmine_user_id, gitlab_user_id = get_3pt_user_ids(
            user_id, "Error while removing user from project.")
        if error is not None:
            return error
        error, redmine_project_id, gitlab_project_id = get_3pt_project_ids(
            project_id, "Error while removing user from project.")
        if error is not None:
            return error

        # get membership id
        memberships, status_code = self.redmine.rm_get_memberships_list(redmine_project_id)
        redmine_membership_id = None
        if status_code == 200:
            for membership in memberships.json()['memberships']:
                if membership['user']['id'] == redmine_user_id:
                    redmine_membership_id = membership['id']
        if redmine_membership_id is not None:
            # delete membership
            output, status_code = self.redmine.rm_delete_memberships(redmine_membership_id)
            if status_code == 204:
                pass
            elif status_code == 404:
                # Already deleted, let it go
                pass
            else:
                return util.respond(status_code, "Error while removing user from project.",
                                    error=apiError.redmine_error(output))
        else:
            return util.respond(status_code, "Error while removing user from project.",
                                error=apiError.redmine_error(memberships))

        # delete relationship from  ProjectUserRole table.
        delete_pj_ur_rl_cmd = db.delete(ProjectUserRole.stru_project_user_role).where(db.and_(
            ProjectUserRole.stru_project_user_role.c.user_id == user_id,
            ProjectUserRole.stru_project_user_role.c.project_id == project_id,
            ProjectUserRole.stru_project_user_role.c.role_id == role_id))
        util.call_sqlalchemy(delete_pj_ur_rl_cmd)

        # gitlab project delete member
        output = self.git.gl_project_delete_member(gitlab_project_id, gitlab_user_id)
        status_code = output.status_code
        if status_code == 204:
            pass
        else:
            return util.respond(status_code, "Error while removing user from project.",
                                error=apiError.gitlab_error(output))

        return {"message": "success"}, 200

    # 從db role table取得role list
    @staticmethod
    def get_role_list():
        result = db.engine.execute(
            "SELECT * FROM public.roles ORDER BY id ASC")
        role_array = result.fetchall()
        result.close()

        if role_array:
            output_array = []
            for role in role_array:
                role_info = {"id": role["id"], "name": role["name"]}
                output_array.append(role_info)

            return util.success({"role_list": output_array})
        else:
            return util.respond(500, "Could not get role list",
                                error=apiError.db_error("public.roles SELECT returns False"))

    @staticmethod
    def get_user_id_name_by_plan_user_id(plan_user_id):
        command = db.select([UserPluginRelation.stru_user_plug_relation,
                             UserModel.stru_user]).where(
            db.and_(
                UserPluginRelation.stru_user_plug_relation.c.plan_user_id == plan_user_id,
                UserPluginRelation.stru_user_plug_relation.c.user_id == UserModel.stru_user.c.id))
        return util.call_sqlalchemy(command).fetchone()
