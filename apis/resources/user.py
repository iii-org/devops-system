import datetime
import json
import re

import nexus
import kubernetes
from Cryptodome.Hash import SHA256
from flask_jwt_extended import (
    create_access_token, JWTManager, get_jwt_identity)
from sqlalchemy import inspect, or_
from sqlalchemy.orm import joinedload
from sqlalchemy.orm.exc import NoResultFound

import model
import resources.apiError as apiError
import util as util
from enums.action_type import ActionType
from model import ProjectUserRole, db
from nexus import nx_get_user_plugin_relation, nx_get_user
from plugins.sonarqube import sonarqube_main as sonarqube
from plugins.ad.ad_main import ldap_api
from resources import harbor, role
from resources import kubernetesClient
from resources.activity import record_activity
from resources.apiError import DevOpsError
from resources.gitlab import gitlab
from resources.logger import logger
from resources.redmine import redmine
from resources.project import get_project_list
import resources
from sqlalchemy import desc
import gitlab as gitlab_pack

# Make a regular expression
default_role_id = 3
jwt = JWTManager()


# Use lazy loading to avoid redundant db queries, build up this object like:
# NexusUser().set_user_id(4) or NexusProject().set_user_row(row)
class NexusUser:
    def __init__(self):
        self.__user_id = None
        self.__user_row = None

    def set_user_id(self, user_id, do_query=True):
        self.__user_id = user_id
        if do_query:
            self.get_user_row()
        return self

    def set_user_row(self, user_row):
        self.__user_row = user_row
        self.set_user_id(user_row.id, False)
        # Mirror data model fields to this object, so it can be used like an ORM row
        inst = inspect(model.User)
        attr_names = [c_attr.key for c_attr in inst.mapper.column_attrs]
        for attr in attr_names:
            setattr(self, attr, getattr(user_row, attr))
        return self

    def get_user_id(self):
        if self.__user_id is None:
            raise DevOpsError(500, 'User id or row is not set!')
        return self.__user_id

    def get_user_row(self):
        if self.__user_row is None:
            self.set_user_row(model.User.query.filter_by(id=self.get_user_id()).one())
        return self.__user_row

    def to_json(self):
        ret = json.loads(str(self.get_user_row()))
        ret['default_role'] = {
            'id': self.default_role_id(),
            'name': role.get_role_name(self.default_role_id())
        }
        return ret

    def default_role_id(self):
        for row in self.get_user_row().project_role:
            if row.project_id == -1:
                return row.role_id
        raise DevOpsError(500, 'This user does not have project -1 role.',
                          error=apiError.invalid_code_path('This user does not have project -1 role.'))

    def fill_dummy_user(self):
        self.set_user_row(model.User(id=0, name='No One'))


def get_user_id_name_by_plan_user_id(plan_user_id):
    return db.session.query(model.User.id, model.User.name, model.User.login).filter(
        model.UserPluginRelation.plan_user_id == plan_user_id,
        model.UserPluginRelation.user_id == model.User.id
    ).first()


def get_all_user_info():
    return db.session.query(model.User.id, model.User.name, model.User.login,
                            model.UserPluginRelation.plan_user_id).filter(
        model.UserPluginRelation.user_id == model.User.id).all()


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
    elif role_id == role.ADMIN.id:
        return 4
    elif role_id == role.BOT.id:
        return 4
    else:
        return 4


def get_token_expires(role_id):
    expires = datetime.timedelta(days=1)
    if role_id == 5:
        expires = datetime.timedelta(days=36500)
    return expires


def check_ad_login(account, password, ad_info=None):
    if ad_info is None:
        ad_info = {}
    try:
        ad_info_data = ldap_api.get_user_info(account, password)
        if ad_info_data is not None:
            ad_info['is_pass'] = True
            ad_info['data'] = ad_info_data
        return ad_info
    except Exception as e:
        raise DevOpsError(500, 'Error when AD Login ',
                          error=apiError.uncaught_exception(e))


@jwt.user_claims_loader
def jwt_response_data(id, login, role_id, from_ad):
    return {
        'user_id': id,
        'user_account': login,
        'role_id': role_id,
        'role_name': role.get_role_name(role_id),
        'from_ad': from_ad
    }


def get_access_token(id, login, role_id, from_ad=True):
    expires = get_token_expires(role_id)
    token = create_access_token(
        identity=jwt_response_data(id, login, role_id, from_ad),
        expires_delta=expires
    )
    return token


def verify_password(db_password, login_password):
    is_verify = True
    h = SHA256.new()
    h.update(login_password.encode())
    hex_login_password = h.hexdigest()
    if db_password != hex_login_password:
        is_verify = False
    return is_verify, hex_login_password


def check_db_login(user, password, output):
    project_user_role = db.session.query(model.ProjectUserRole).filter(
        model.ProjectUserRole.user_id == user.id).first()
    is_password_verify, hex_login_password = verify_password(user.password, password)
    output['hex_password'] = hex_login_password
    output['from_ad'] = user.from_ad
    output['role_id'] = project_user_role.role_id
    output['is_password_verify'] = is_password_verify
    if is_password_verify and user.disabled is False:
        output['is_pass'] = True
        logger.info("User Login success by DB user_id: {0}".format(user.id))
    else:
        logger.info("User Login failed by DB user_id: {0}".format(user.id))
    return output, user, project_user_role


def login(args):
    login_account = args['username']
    login_password = args['password']
    user = db.session.query(model.User).filter(
        model.User.login == login_account).first()
    try:

        ad_info = {'is_pass': False,
                   'login': login_account, 'data': {}}

        # Check Ad server exists
        if (user is not None and user.from_ad is True) or user is None:
            ad_server = ldap_api.check_ad_info()
            if ad_server['disabled'] is False:
                ad_info = check_ad_login(login_account, login_password, ad_info)

        db_info = {'connect': False,
                   'login': login_account,
                   'is_pass': False,
                   'is_password_verify': False,
                   'User': {}, 'ProjectUserRole': {}}
        # Check User in DB
        if user is not None:
            db_info['connect'] = True
            db_info, user, project_user_role = check_db_login(
                user, login_password, db_info)

        # Login By AD
        if ad_info['is_pass'] is True:
            status, token = ldap_api.login_by_ad(
                user, db_info, ad_info, login_account, login_password)
            if token is None:
                return util.respond(401, "Error when logging in. Please contact system administrator",
                                    error=apiError.ad_account_not_allow())
            # User First Login
            elif user is None:
                return util.success({'status': status, 'token': token, 'ad_info': ad_info})
            else:
                save_last_login(user)
                return util.success({'status': status, 'token': token, 'ad_info': ad_info})

        # Login By Database
        elif db_info['is_pass'] is True and db_info['from_ad'] is False:
            status = "DB Login"
            token = get_access_token(
                user.id, user.login, project_user_role.role_id, user.from_ad)
            save_last_login(user)
            return util.success({'status': status, 'token': token, 'ad_info': ad_info})
        else:
            return util.respond(401, "Error when logging in.", error=apiError.wrong_password())
    except Exception as e:
        raise DevOpsError(500, 'Error when user login.',
                          error=apiError.uncaught_exception(e))


def user_forgot_password(args):
    return 'dummy_response', 200


@record_activity(ActionType.UPDATE_USER)
def update_user(user_id, args, from_ad=False):
    user = model.User.query.filter_by(id=user_id).first()
    if 'role_id' in args:
        update_user_role(user_id, args.get('role_id'))
    user_role_id = -1
    jwt_token = get_jwt_identity()
    if jwt_token is not None:
        user_role_id = jwt_token.get('role_id')
    new_email = None
    new_password = None
    # Change Password
    if args.get('password') is not None:
        if args["old_password"] == args["password"]:
            return util.respond(400, "Password is not changed.", error=apiError.wrong_password())
        # Only Update password from ad trigger or syadmin can skip verify password
        if role.ADMIN.id != user_role_id and not from_ad:
            is_password_verify, hex_login_password = verify_password(user.password, args['old_password'])
            if args["old_password"] is None:
                return util.respond(400, "old_password is empty", error=apiError.wrong_password())
            if is_password_verify is False:
                return util.respond(400, "Password is incorrect", error=apiError.wrong_password())
        err = update_external_passwords(
            user_id, args["password"], args["old_password"])
        if err is not None:
            logger.exception(err)  # Don't stop change password on API server
        h = SHA256.new()
        h.update(args["password"].encode())
        new_password = h.hexdigest()

    user = model.User.query.filter_by(id=user_id).first()
    # API update AD User only can update password
    if user_role_id == role.ADMIN.id and not from_ad and user.from_ad:
        if new_password is not None:
            user.password = new_password
        db.session.commit()
    else:
        if new_password is not None:
            user.password = new_password
        # Change Email
        if args["email"] is not None:
            err = update_external_email(user_id, user.name, args['email'])
            if err is not None:
                logger.exception(err)
            new_email = args['email']
        if new_email is not None:
            user.email = new_email
        if args["name"] is not None:
            user.name = args['name']
            update_external_name(user_id, args['name'], user.login, user.email)
        if args["phone"] is not None:
            user.phone = args['phone']
        if args["title"] is not None:
            user.title = args['title']
        if args["department"] is not None:
            user.department = args['department']
        if args.get("status", None) is not None:
            if args.get("status", None) == "disable":
                user.disabled = True
                block_external_user(user_id)
            else:
                user.disabled = False
                unblock_external_user(user_id)
        if from_ad:
            user.update_at = args['update_at']
        else:
            user.update_at = util.date_to_str(datetime.datetime.utcnow())
        if user.from_ad and not from_ad:
            return util.respond(400, 'Error when updating Message',
                                error=apiError.user_from_ad(user_id))
        else:
            db.session.commit()
    return util.success()


def update_user_role(user_id, role_id):
    if role_id is None:
        return
    role.require_admin('Only admin can update role.')
    role.update_role(user_id, role_id)


def update_external_passwords(user_id, new_pwd, old_pwd):
    user_login = nx_get_user(id=user_id).login
    user_relation = nx_get_user_plugin_relation(user_id=user_id)
    if user_relation is None:
        return util.respond(400, 'Error when updating password',
                            error=apiError.user_not_found(user_id))
    redmine_user_id = user_relation.plan_user_id
    redmine.rm_update_password(redmine_user_id, new_pwd)

    gitlab_user_id = user_relation.repository_user_id
    gitlab.gl_update_password(gitlab_user_id, new_pwd)

    harbor_user_id = user_relation.harbor_user_id
    harbor.hb_update_user_password(harbor_user_id, new_pwd, old_pwd)

    sonarqube.sq_update_password(user_login, new_pwd)


def update_external_email(user_id, user_name, new_email):
    user_relation = nx_get_user_plugin_relation(user_id=user_id)
    if user_relation is None:
        return util.respond(400, 'Error when updating email',
                            error=apiError.user_not_found(user_id))
    redmine_user_id = user_relation.plan_user_id
    redmine.rm_update_email(redmine_user_id, new_email)

    gitlab_user_id = user_relation.repository_user_id
    gitlab.gl_update_email(gitlab_user_id, new_email)

    gitlab_user_email_list = gitlab.gl_get_user_email(gitlab_user_id).json()
    need_to_delete_email = [email['id'] for email in gitlab_user_email_list if email['email'] != new_email]
    for gitlab_email_id in need_to_delete_email:
        gitlab.gl_delete_user_email(gitlab_user_id, gitlab_email_id)

    harbor_user_id = user_relation.harbor_user_id
    harbor.hb_update_user_email(harbor_user_id, user_name, new_email)


def update_external_name(user_id, new_name, login, email):
    relation = nx_get_user_plugin_relation(user_id=user_id)
    redmine.rm_update_user_name(relation.plan_user_id, new_name)
    gitlab.gl_update_user_name(relation.repository_user_id, new_name)
    harbor.hb_update_user_email(relation.harbor_user_id, new_name, email)
    sonarqube.sq_update_user_name(login, new_name)


def block_external_user(user_id):
    relation = nx_get_user_plugin_relation(user_id=user_id)
    redmine.rm_update_user_active(relation.plan_user_id, 3)
    gitlab.gl_update_user_state(relation.repository_user_id, True)


def unblock_external_user(user_id):
    relation = nx_get_user_plugin_relation(user_id=user_id)
    redmine.rm_update_user_active(relation.plan_user_id, 1)
    gitlab.gl_update_user_state(relation.repository_user_id, False)


def try_to_delete(delete_method, obj):
    try:
        delete_method(obj)
    except DevOpsError as e:
        if e.status_code != 404:
            raise e


@record_activity(ActionType.DELETE_USER)
def delete_user(user_id):
    if user_id == 1:
        raise apiError.NotAllowedError('You cannot delete the system admin.')
    pj_list = get_project_list(user_id)
    for pj in pj_list:
        if pj["owner_id"] == user_id:
            nexus.nx_update_project(pj["id"], {"owner_id": 1})

    relation = nx_get_user_plugin_relation(user_id=user_id)
    user_login = model.User.query.filter_by(id=user_id).one().login
    pj_ur_rls = db.session.query(model.Project, model.ProjectUserRole).join(model.ProjectUserRole). \
        filter(model.ProjectUserRole.user_id == user_id, model.ProjectUserRole.project_id != -1,
               model.ProjectUserRole.project_id == model.Project.id).all()

    try_to_delete(gitlab.gl_delete_user, relation.repository_user_id)
    try_to_delete(redmine.rm_delete_user, relation.plan_user_id)
    try_to_delete(harbor.hb_delete_user, relation.harbor_user_id)
    try_to_delete(sonarqube.sq_deactivate_user, user_login)
    try:
        for pur_row in pj_ur_rls:
            kubernetesClient.delete_role_binding(pur_row.Project.name, f"{util.encode_k8s_sa(user_login)}-rb")
        try_to_delete(kubernetesClient.delete_service_account,
                      relation.kubernetes_sa_name)
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
    return None


def change_user_status(user_id, args):
    disabled = False
    if args["status"] == "enable":
        disabled = False
    elif args["status"] == "disable":
        disabled = True
    try:
        user = model.User.query.filter_by(id=user_id).one()
        user.update_at = datetime.datetime.utcnow()
        user.disabled = disabled
        db.session.commit()
        return util.success()
    except NoResultFound:
        raise apiError.DevOpsError(
            404, 'Error when change user status.',
            error=apiError.user_not_found(user_id))


@record_activity(ActionType.CREATE_USER)
def create_user(args):
    logger.info('Creating user...')
    # Check if name is valid
    login_name = args['login']
    force = args.get("force", False)
    if re.fullmatch(r'^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,58}[a-zA-Z0-9]$', login_name) is None:
        raise apiError.DevOpsError(400, "Error when creating new user",
                                   error=apiError.invalid_user_name(login_name))
    logger.info('Name is valid.')

    user_source_password = args["password"]
    #  User created by AD skip password check
    # if 'from_ad' in args and args['from_ad'] is False:
    need_password_check = True
    if 'from_ad' in args and args['from_ad'] is True:
        need_password_check = False

    if need_password_check is True and re.fullmatch(r'(?=.*\d)(?=.*[a-z])(?=.*[A-Z])'
                                                    r'^[\w!@#$%^&*()+|{}\[\]`~\-\'\";:/?.\\>,<]{8,20}$',
                                                    user_source_password) is None:
        raise apiError.DevOpsError(400, "Error when creating new user",
                                   error=apiError.invalid_user_password())
    logger.info('Password is valid.')

    # Check DB has this login, email, if has, raise error
    check_count = model.User.query.filter(db.or_(
        model.User.login == args['login'],
        model.User.email == args['email'],
    )).count()
    if check_count > 0:
        raise DevOpsError(422, "System already has this account or email.",
                          error=apiError.already_used())
    logger.info('Account is unique.')

    is_admin = args['role_id'] == role.ADMIN.id
    logger.info(f'is_admin is {is_admin}')

    # Check Redmine has this login, email, if has, raise error(if force remove it.)
    offset = 0
    limit = 25
    total_count = 1
    while offset < total_count:
        params = {'offset': offset, 'limit': limit}
        user_list_output = redmine.rm_get_user_list(params)
        total_count = user_list_output['total_count']
        for user in user_list_output['users']:
            if user['login'] == args['login'] or user['mail'] == args['email']:
                if force:
                    redmine.rm_delete_user(user["id"])
                    logger.info('Force is True, so delete this Redmine account.')
                else:
                    raise DevOpsError(422, "Redmine already has this account or email.",
                                      error=apiError.already_used())
        offset += limit
    logger.info('Account name not used in Redmine or force is True.')

    # Check Gitlab has this login, email, if has, raise error(if force remove it.)
    login_users = gitlab.gl.search(gitlab_pack.const.SEARCH_SCOPE_USERS, args['login'])
    for login_user in login_users:
        gl_user = gitlab.gl.users.get(login_user['id'])
        if gl_user.name == args['login'] or gl_user.email == args['email']:
            if force:
                gitlab.gl_delete_user(gl_user.id)
                logger.info('Force is True, so delete this Gitlab account.')
            else:
                raise DevOpsError(422, "Gitlab already has this account or email.",
                                  error=apiError.already_used())
    logger.info('Account name not used in Gitlab or force is True.')

    # Check Kubernetes has this Service Account (login), if has, return error 400(if force remove it.)
    sa_list = kubernetesClient.list_service_account()
    login_sa_name = util.encode_k8s_sa(login_name)
    if login_sa_name in sa_list:
        if force:
            kubernetesClient.delete_service_account(login_sa_name)
            logger.info('Force is True, so delete this kubernetes account.')
        else:
            raise DevOpsError(422, "Kubernetes already has this Kubernetes account.",
                              error=apiError.already_used())
    logger.info('Account name not used in kubernetes or force is True.')

    # Check Harbour has this login, email, if has, raise error(if force remove it.)
    page = 1
    page_size = 10
    total_size = 20
    while total_size > 0:
        params = {'page': page, 'page_size': page_size}
        output = harbor.hb_list_user(params)
        for user in output.json():
            if user['username'] == args['login'] or user['email'] == args['email']:
                if force:
                    harbor.hb_delete_user(user["user_id"])
                    logger.info('Force is True, so delete this Harbour account.')
                else:
                    raise DevOpsError(422, "Harbour already has this account or email.",
                                      error=apiError.already_used())
        if output.headers.get('X-Total-Count', None):
            total_size = int(output.headers['X-Total-Count']) - (page * page_size)
            page += 1
        else:
            total_size = -1
    logger.info('Account name not used in Harbour or force is True.')

    # Check SonarQube has this login, if has, raise error(if force deactivate it.)
    page = 1
    page_size = 50
    total_size = 20
    while total_size > 0:
        params = {'p': page, 'ps': page_size}
        output = sonarqube.sq_list_user(params).json()
        for user in output["users"]:
            if user["login"] == args['login']:
                if force:
                    sonarqube.sq_deactivate_user(args["login"])
                    logger.info('Force is True, so deactivate this SonarQube account.')
                else:
                    raise DevOpsError(422, "SonarQube already has this account.",
                                      error=apiError.already_used())
        total_size = int(output['paging']['total']) - (page * page_size)
        page += 1
    logger.info('Account name not used in SonarQube or force is True.')

    # plan software user create
    red_user = redmine.rm_create_user(
        args, user_source_password, is_admin=is_admin)
    redmine_user_id = red_user['user']['id']
    logger.info(f'Redmine user created, id={redmine_user_id}')

    # gitlab software user create
    try:
        git_user = gitlab.gl_create_user(
            args, user_source_password, is_admin=is_admin)
    except Exception as e:
        redmine.rm_delete_user(redmine_user_id)
        raise e
    gitlab_user_id = git_user['id']
    logger.info(f'Gitlab user created, id={gitlab_user_id}')

    # kubernetes service account create
    try:
        kubernetes_sa = kubernetesClient.create_service_account(login_sa_name)
    except Exception as e:
        redmine.rm_delete_user(redmine_user_id)
        gitlab.gl_delete_user(gitlab_user_id)
        raise e
    kubernetes_sa_name = kubernetes_sa.metadata.name
    logger.info(f'Kubernetes user created, sa_name={kubernetes_sa_name}')

    # Harbor user create
    try:
        harbor_user_id = harbor.hb_create_user(args, is_admin=is_admin)
    except Exception as e:
        gitlab.gl_delete_user(gitlab_user_id)
        redmine.rm_delete_user(redmine_user_id)
        kubernetesClient.delete_service_account(login_sa_name)
        raise e
    logger.info(f'Harbor user created, id={harbor_user_id}')

    # Sonarqube user create
    # Caution!! Sonarqube cannot delete a user, can only deactivate
    try:
        sonarqube.sq_create_user(args)
    except Exception as e:
        gitlab.gl_delete_user(gitlab_user_id)
        redmine.rm_delete_user(redmine_user_id)
        kubernetesClient.delete_service_account(login_sa_name)
        harbor.hb_delete_user(harbor_user_id)
        raise e
    logger.info(f'Sonarqube user created.')

    try:
        # DB
        title = department = ''
        h = SHA256.new()
        h.update(args["password"].encode())
        args["password"] = h.hexdigest()
        disabled = False

        if args['status'] == "disable":
            disabled = True
        if 'title' in args:
            title = args['title']
        if 'department' in args:
            department = args['department']
        user = model.User(
            name=args['name'],
            email=args['email'],
            phone=args['phone'],
            login=args['login'],
            title=title,
            department=department,
            password=h.hexdigest(),
            create_at=datetime.datetime.utcnow(),
            disabled=disabled,
            from_ad=('from_ad' in args) and (args['from_ad'])
        )
        if 'update_at' in args:
            user.update_at = args['update_at']
        if 'last_login' in args:
            user.last_login = args.get('last_login')
        db.session.add(user)
        db.session.commit()

        user_id = user.id
        logger.info(f'Nexus user created, id={user_id}')

        # insert user_plugin_relation table
        rel = model.UserPluginRelation(user_id=user_id,
                                       plan_user_id=redmine_user_id,
                                       repository_user_id=gitlab_user_id,
                                       harbor_user_id=harbor_user_id,
                                       kubernetes_sa_name=kubernetes_sa_name)
        db.session.add(rel)
        db.session.commit()
        logger.info(f'Nexus user_plugin built.')

        # insert project_user_role
        rol = model.ProjectUserRole(
            project_id=-1, user_id=user_id, role_id=args['role_id'])
        db.session.add(rol)
        db.session.commit()
        logger.info(f'Nexus user project_user_role created.')
    except Exception as e:
        harbor.hb_delete_user(harbor_user_id)
        gitlab.gl_delete_user(gitlab_user_id)
        redmine.rm_delete_user(redmine_user_id)
        kubernetesClient.delete_service_account(kubernetes_sa_name)
        sonarqube.sq_deactivate_user(args["login"])
        raise e

    logger.info('User created.')
    return {
        "user_id": user_id,
        'plan_user_id': redmine_user_id,
        'repository_user_id': gitlab_user_id,
        'harbor_user_id': harbor_user_id,
        'kubernetes_sa_name': kubernetes_sa_name
    }


def user_list(filters):
    per_page = 10
    page_dict = None
    query = model.User.query.filter(model.User.id != 1).order_by(desc(model.User.create_at))
    if 'role_ids' in filters:
        filtered_user_ids = model.ProjectUserRole.query.filter(
            model.ProjectUserRole.role_id.in_(filters['role_ids'])
        ).with_entities(model.ProjectUserRole.user_id).distinct().subquery()
        query = query.filter(model.User.id.in_(filtered_user_ids))
    if 'search' in filters:
        query = query.filter(or_(
            model.User.login.ilike(f'%{filters["search"]}%'),
            model.User.name.ilike(f'%{filters["search"]}%')
        ))
    if 'per_page' in filters:
        per_page = filters['per_page']
    if 'page' in filters:
        paginate_query = query.paginate(
            page=filters['page'],
            per_page=per_page,
            error_out=False
        )
        page_dict = {
            'current': paginate_query.page,
            'prev': paginate_query.prev_num,
            'next': paginate_query.next_num,
            'pages': paginate_query.pages,
            'per_page': paginate_query.per_page,
            'total': paginate_query.total
        }
        rows = paginate_query.items
    else:
        rows = query.all()
    output_array = []
    for row in rows:
        output_array.append(NexusUser()
                            .set_user_row(row)
                            .to_json())
    response = {'user_list': output_array}
    if page_dict:
        response['page'] = page_dict
    return response


def user_list_by_project(project_id, args):
    excluded_roles = [role.BOT.id, role.ADMIN.id, role.QA.id]
    if args.get("exclude") is not None and args["exclude"] == 1:
        # list users not in the project
        users = []
        rows = model.User.query.options(joinedload(model.User.project_role)).all()
        for u in rows:
            for pr in u.project_role:
                if pr.project_id < 0 and pr.role_id in excluded_roles or \
                        pr.project_id == project_id or \
                        pr.user.disabled:
                    break
            else:
                users.append(u)
        users.sort(key=lambda x: x.id, reverse=True)
        arr_ret = []
        for user_row in users:
            user = NexusUser().set_user_row(user_row)
            user_json = user.to_json()
            outer_role_id = user.default_role_id()
            user_json['role_id'] = outer_role_id
            user_json['role_name'] = role.get_role_name(outer_role_id)
            arr_ret.append(user_json)
        return arr_ret
    else:
        # list users in the project
        project_row = model.Project.query.options(
            joinedload(model.Project.user_role).
            joinedload(model.ProjectUserRole.user).
            joinedload(model.User.project_role)
        ).filter_by(id=project_id).one()
        users = list(filter(
            lambda x: x.role_id not in excluded_roles and not x.user.disabled,
            project_row.user_role))
        users.sort(key=lambda x: x.user_id, reverse=True)
        arr_ret = []
        for relation_row in users:
            user_json = NexusUser().set_user_row(relation_row.user).to_json()
            user_json['role_id'] = relation_row.role_id
            user_json['role_name'] = role.get_role_name(
                relation_row.role_id)
            arr_ret.append(user_json)
        return arr_ret


def user_sa_config(user_id):
    ret_users = db.session.query(model.User, model.UserPluginRelation.kubernetes_sa_name). \
        join(model.UserPluginRelation). \
        filter(model.User.id == user_id). \
        filter(model.User.disabled == False).first()
    sa_name = str(ret_users.kubernetes_sa_name)
    sa_config = kubernetesClient.get_service_account_config(sa_name)
    return util.success(sa_config)


def save_last_login(user):

    if user is not None:
        user.last_login = datetime.datetime.utcnow()
        db.session.commit()


def get_am_role_user():
    rows = ProjectUserRole.query.filter_by(role_id=5).with_entities(ProjectUserRole.user_id). \
        distinct()
    return [row.user_id for row in rows]
