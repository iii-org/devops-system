import datetime
import re

import kubernetes
from Cryptodome.Hash import SHA256
from flask_jwt_extended import (create_access_token, JWTManager, jwt_required, get_jwt_identity)
from flask_restful import Resource, reqparse
from sqlalchemy import desc
from sqlalchemy.orm.exc import NoResultFound

import resources.apiError as apiError
import util as util
from model import db
from nexus import get_user_plugin_relation
from resources.apiError import DevOpsError
import model
from resources import harbor
import role
from resources.logger import logger
from resources.redmine import redmine
from resources.gitlab import gitlab
from resources import kubernetesClient

jwt = JWTManager()


@jwt.user_claims_loader
def jwt_response_data(row):
    return {
        'user_id': row['id'],
        'user_account': row["login"],
        'role_id': row['role_id'],
        'role_name': role.get_role_name(row['role_id'])
    }


def get_user_id_name_by_plan_user_id(plan_user_id):
    return db.session.query(model.User.id, model.User.name).filter(
        model.UserPluginRelation.plan_user_id == plan_user_id,
        model.UserPluginRelation.user_id == model.User.id
    ).first()


def get_role_id(user_id):
    row = model.ProjectUserRole.query.filter_by(user_id=user_id).first()
    if row is not None:
        return row.role_id
    else:
        raise apiError.DevOpsError(
            404, 'Error while getting role id', apiError.user_not_found(user_id))


def to_redmine_role_id(role_id):
    if role_id == role.RD.id:
        return 3
    elif role_id == role.PM.id:
        return 4
    else:
        return 4


def login(args):
    h = SHA256.new()
    h.update(args["password"].encode())
    result = db.engine.execute(
        "SELECT ur.id, ur.login, ur.password, pur.role_id"
        " FROM public.user as ur, public.project_user_role as pur"
        " WHERE ur.disabled = false AND ur.id = pur.user_id"
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


def user_forgot_password(args):
    result = db.engine.execute("SELECT login, email FROM public.user")
    for row in result:
        if row['login'] == args["user_account"] and row['email'] == args["mail"]:
            pass
            logger.info(
                "user_forgot_password API: user_account and mail were correct"
            )
    return 'dummy_response', 200


# noinspection PyMethodMayBeStatic
def get_user_info(user_id):
    result = db.engine.execute(
        "SELECT ur.id as id, ur.name as name,"
        " ur.email as email, ur.phone as phone, ur.login as login, ur.create_at as create_at,"
        " ur.update_at as update_at, pur.role_id, ur.disabled as disabled"
        " FROM public.user as ur, public.project_user_role as pur"
        " WHERE ur.id = {0} AND ur.id = pur.user_id".format(user_id))
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
                "name": role.get_role_name(user_data["role_id"]),
                "id": user_data["role_id"]
            },
            "status": status
        }
        # get user's involved project list
        rows = db.session. \
            query(model.Project, model.ProjectPluginRelation.git_repository_id). \
            join(model.ProjectPluginRelation). \
            filter(model.ProjectUserRole.user_id == user_id,
                   model.ProjectUserRole.project_id != -1,
                   model.ProjectUserRole.project_id == model.ProjectPluginRelation.project_id
                   ).all()
        if len(rows) > 0:
            project_list = []
            for row in rows:
                project_list.append({
                    "id": row.Project.id,
                    "name": row.Project.name,
                    "display": row.Project.display,
                    "repository_id": row.git_repository_id
                })
            output["project"] = project_list
        else:
            output["project"] = []

        return util.success(output)
    else:
        raise apiError.DevOpsError(
            404, 'User not found.', apiError.user_not_found(user_id))


def update_info(user_id, args):
    set_string = ""
    if args["name"] is not None:
        set_string += "name = '{0}'".format(args["name"])
        set_string += ","
    if args["password"] is not None:
        if 5 != get_jwt_identity()['role_id']:
            if args["old_password"] is None:
                return util.respond(400, "old_password is empty", error=apiError.wrong_password())
            h_old_password = SHA256.new()
            h_old_password.update(args["old_password"].encode())
            result = db.engine.execute(
                "SELECT ur.id, ur.password FROM public.user as ur"
                " WHERE ur.disabled = false AND ur.id = {0}".format(get_jwt_identity()['user_id'])
            ).fetchone()
            if result['password'] != h_old_password.hexdigest():
                return util.respond(400, "Password is incorrect", error=apiError.wrong_password())
        err = update_external_passwords(user_id, args["password"])
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


def update_external_passwords(user_id, new_pwd):
    user_relation = get_user_plugin_relation(user_id=user_id)
    if user_relation is None:
        return util.respond(400, 'Error when updating password',
                            error=apiError.user_not_found(user_id))
    redmine_user_id = user_relation.plan_user_id
    redmine.rm_update_password(redmine_user_id, new_pwd)

    gitlab_user_id = user_relation.repository_user_id
    gitlab.gl_update_password(gitlab_user_id, new_pwd)

    return None


def try_to_delete(delete_method, obj):
    try:
        delete_method(obj)
    except DevOpsError as e:
        if e.status_code != 404:
            raise e


def delete_user(user_id):
    # 取得gitlab & redmine user_id
    relation = get_user_plugin_relation(user_id=user_id)

    try_to_delete(gitlab.gl_delete_user, relation.repository_user_id)
    try_to_delete(redmine.rm_delete_user, relation.plan_user_id)
    try_to_delete(harbor.hb_delete_user, relation.harbor_user_id)
    try:
        try_to_delete(kubernetesClient.delete_service_account, relation.kubernetes_sa_name)
    except kubernetes.client.exceptions.ApiException as e:
        if e.status != 404:
            raise e

    # 如果gitlab & redmine user都成功被刪除則繼續刪除db內相關tables欄位
    db.session.delete(relation)
    del_roles = model.ProjectUserRole.query.filter_by(user_id=user_id).all()
    for row in del_roles:
        db.session.delete(row)
    del_user = model.User.query.filter_by(id=user_id).one()
    db.session.delete(del_user)
    db.session.commit()

    return util.success()


def change_user_status(user_id, args):
    disabled = False
    if args["status"] == "enable":
        disabled = False
    elif args["status"] == "disable":
        disabled = True
    try:
        user = model.User.query.filter_by(id=user_id).one()
        user.update_at = datetime.datetime.now()
        user.disabled = disabled
        db.session.commit()
        return util.success()
    except NoResultFound:
        raise apiError.DevOpsError(
            404, 'Error when change user status.',
            error=apiError.user_not_found(user_id))


def create_user(args):
    # Check if name is valid
    login_name = args['login']
    if re.fullmatch(r'^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,58}[a-zA-Z0-9]$', login_name) is None:
        return util.respond(400, "Error when creating new user",
                            error=apiError.invalid_user_name(login_name))

    user_source_password = args["password"]
    if re.fullmatch(r'(?=.*\d)(?=.*[a-z])(?=.*[A-Z])'
                    r'^[\w!@#$%^&*()+|{}\[\]`~\-\'\";:/?.\\>,<]{8,20}$',
                    user_source_password) is None:
        return util.respond(400, "Error when creating new user",
                            error=apiError.invalid_user_password())

    # Check DB has this login, email, if has, raise error
    check_count = model.User.query.filter(db.or_(
        model.User.login == args['login'],
        model.User.email == args['email'],
    )).count()
    if check_count > 0:
        raise DevOpsError(422, "System already has this account or email.",
                          error=apiError.already_used())

    is_admin = args['role_id'] == role.ADMIN.id

    offset = 0
    limit = 25
    total_count = 1
    while offset < total_count:
        params = {'offset': offset, 'limit': limit}
        user_list_output = redmine.rm_get_user_list(params)
        total_count = user_list_output['total_count']
        for user in user_list_output['users']:
            if user['login'] == args['login'] or user['mail'] == args['email']:
                raise DevOpsError(422, "Redmine already has this account or email.",
                                  error=apiError.already_used())
        offset += limit
    # Check Gitlab has this login, email, if has, raise error
    page = 1
    x_total_pages = 10
    while page <= x_total_pages:
        params = {'page': page}
        user_list_output = gitlab.gl_get_user_list(params)
        x_total_pages = int(user_list_output.headers['X-Total-Pages'])
        for user in user_list_output.json():
            if user['name'] == args['login'] or user['email'] == args['email']:
                raise DevOpsError(422, "Gitlab already has this account or email.",
                                  error=apiError.already_used())
        page += 1
    
    # Check Kubernetes has this Service Account (login), if has, return error 400
    sa_list = kubernetesClient.list_service_account()
    login_sa_name = util.encode_k8s_sa(login_name)
    if login_sa_name in sa_list:
        return util.respond(422, "Kubernetes already has this service account.",
                            error=apiError.already_used())

    # plan software user create
    red_user = redmine.rm_create_user(args, user_source_password, is_admin=is_admin)
    redmine_user_id = red_user['user']['id']

    # gitlab software user create
    try:
        git_user = gitlab.gl_create_user(args, user_source_password, is_admin=is_admin)
    except Exception as e:
        redmine.rm_delete_user(redmine_user_id)
        raise e
    gitlab_user_id = git_user['id']

    # kubernetes service account create
    try:
        kubernetes_sa = kubernetesClient.create_service_account(login_sa_name)
    except Exception as e:
        redmine.rm_delete_user(redmine_user_id)
        gitlab.gl_delete_user(gitlab_user_id)
        raise e
    kubernetes_sa_name = kubernetes_sa.metadata.name

    # Harbor user create
    try:
        harbor_user_id = harbor.hb_create_user(args, is_admin=is_admin)
    except Exception as e:
        gitlab.gl_delete_user(gitlab_user_id)
        redmine.rm_delete_user(redmine_user_id)
        raise e

    try:
        # DB
        h = SHA256.new()
        h.update(args["password"].encode())
        args["password"] = h.hexdigest()
        disabled = False
        if args['status'] == "disable":
            disabled = True
        user = model.User(
            name=args['name'],
            email=args['email'],
            phone=args['phone'],
            login=args['login'],
            password=h.hexdigest(),
            create_at=datetime.datetime.now(),
            disabled=disabled)
        db.session.add(user)
        db.session.commit()

        user_id = user.id

        # insert user_plugin_relation table
        rel = model.UserPluginRelation(user_id=user_id,
                                       plan_user_id=redmine_user_id,
                                       repository_user_id=gitlab_user_id,
                                       harbor_user_id=harbor_user_id,
                                       kubernetes_sa_name=kubernetes_sa_name)
        db.session.add(rel)
        db.session.commit()

        # insert project_user_role
        rol = model.ProjectUserRole(project_id=-1, user_id=user_id, role_id=args['role_id'])
        db.session.add(rol)
        db.session.commit()
    except Exception as e:
        harbor.hb_delete_user(harbor_user_id)
        gitlab.gl_delete_user(gitlab_user_id)
        redmine.rm_delete_user(redmine_user_id)
        kubernetesClient.delete_service_account(kubernetes_sa_name)
        raise e

    return util.success({"user_id": user_id})



def user_list():
    rows = db.session.query(model.User, model.ProjectUserRole.role_id). \
        join(model.ProjectUserRole). \
        order_by(desc(model.User.id)).all()
    output_array = []
    for row in rows:
        project_rows = model.Project.query.filter(
            model.ProjectUserRole.user_id == row.User.id,
            model.ProjectUserRole.project_id != -1,
            model.ProjectUserRole.project_id == model.Project.id
        ).all()
        projects = []
        for p in project_rows:
            projects.append({
                "id": p.id,
                "name": p.name,
                "display": p.display
            })
        status = "disable"
        if row.User.disabled is False:
            status = "enable"
        output = {
            "id": row.User.id,
            "name": row.User.name,
            "email": row.User.email,
            "phone": row.User.phone,
            "login": row.User.login,
            "create_at": util.date_to_str(row.User.create_at),
            "update_at": util.date_to_str(row.User.update_at),
            "role": {
                "name": role.get_role_name(row.role_id),
                "id": row.role_id
            },
            "project": projects,
            "status": status
        }
        output_array.append(output)
    return util.success({"user_list": output_array})


def user_list_by_project(project_id, args):
    if args["exclude"] is not None and args["exclude"] == 1:
        # list users not in the project
        ret_users = db.session.query(model.User, model.ProjectUserRole.role_id). \
            join(model.ProjectUserRole). \
            filter(model.User.disabled == False). \
            order_by(desc(model.User.id)).all()

        project_users = db.session.query(model.User).join(model.ProjectUserRole).filter(
            model.User.disabled == False,
            model.ProjectUserRole.project_id == project_id
        ).all()

        i = 0
        while i < len(ret_users):
            for pu in project_users:
                if ret_users[i].User.id == pu.id:
                    del ret_users[i]
                    break
            i += 1
    else:
        # list users in the project
        ret_users = db.session.query(model.User, model.ProjectUserRole.role_id). \
            join(model.ProjectUserRole). \
            filter(model.User.disabled == False,
                   model.ProjectUserRole.project_id == project_id). \
            order_by(desc(model.User.id)).all()

    arr_ret = []
    for data_userRole_by_project in ret_users:
        arr_ret.append({
            "id": data_userRole_by_project.User.id,
            "name": data_userRole_by_project.User.name,
            "email": data_userRole_by_project.User.email,
            "phone": data_userRole_by_project.User.phone,
            "login": data_userRole_by_project.User.login,
            "create_at": util.date_to_str(data_userRole_by_project.User.create_at),
            "update_at": util.date_to_str(data_userRole_by_project.User.update_at),
            "role_id": data_userRole_by_project.role_id,
            "role_name": role.get_role_name(data_userRole_by_project.role_id),
        })
    return util.success({"user_list": arr_ret})

def user_sa_config(user_id):
    ret_users = db.session.query(model.User, model.UserPluginRelation.kubernetes_sa_name). \
            join(model.UserPluginRelation). \
            filter(model.User.id == user_id). \
            filter(model.User.disabled == False).first()
    sa_name = str(ret_users.kubernetes_sa_name)
    sa_config = kubernetesClient.get_service_account_config(sa_name)
    return util.success(sa_config)

# --------------------- Resources ---------------------
class Login(Resource):
    # noinspection PyMethodMayBeStatic
    def post(self):
        parser = reqparse.RequestParser()
        parser.add_argument('username', type=str, required=True)
        parser.add_argument('password', type=str, required=True)
        args = parser.parse_args()
        return login(args)


class UserForgetPassword(Resource):
    # noinspection PyMethodMayBeStatic
    def post(self):
        parser = reqparse.RequestParser()
        parser.add_argument('mail', type=str, required=True)
        parser.add_argument('user_account', type=str, required=True)
        args = parser.parse_args()
        status = user_forgot_password(args)
        return util.success(status)


class UserStatus(Resource):
    @jwt_required
    def put(self, user_id):
        role.require_admin('Only admins can modify user.')
        parser = reqparse.RequestParser()
        parser.add_argument('status', type=str, required=True)
        args = parser.parse_args()
        return change_user_status(user_id, args)


class SingleUser(Resource):
    @jwt_required
    def get(self, user_id):
        role.require_user_himself(user_id, even_pm=False,
                                  err_message="Only admin and PM can access another user's data.")
        return get_user_info(user_id)

    @jwt_required
    def put(self, user_id):
        role.require_user_himself(user_id)
        parser = reqparse.RequestParser()
        parser.add_argument('name', type=str)
        parser.add_argument('password', type=str)
        parser.add_argument('old_password', type=str)
        parser.add_argument('phone', type=str)
        parser.add_argument('email', type=str)
        parser.add_argument('status', type=str)
        args = parser.parse_args()
        return update_info(user_id, args)

    @jwt_required
    def delete(self, user_id):
        role.require_admin("Only admin can delete user.")
        return delete_user(user_id)

    @jwt_required
    def post(self):
        role.require_admin('Only admins can create user.')
        parser = reqparse.RequestParser()
        parser.add_argument('name', type=str)
        parser.add_argument('email', type=str, required=True)
        parser.add_argument('phone', type=str, required=True)
        parser.add_argument('login', type=str, required=True)
        parser.add_argument('password', type=str, required=True)
        parser.add_argument('role_id', type=int, required=True)
        parser.add_argument('status', type=str)
        args = parser.parse_args()
        return create_user(args)


class UserList(Resource):
    @jwt_required
    def get(self):
        role.require_pm()
        return user_list()

class UserSaConfig(Resource):
    @jwt_required
    def get(self, user_id):
        role.require_in_project(project_id, "Error while getting project info.")
        return user_sa_config(user_id)