import datetime
import json
import re
import secrets

import nexus
import kubernetes
from Cryptodome.Hash import SHA256
from sqlalchemy import inspect, or_
from sqlalchemy.orm import joinedload
from sqlalchemy.exc import NoResultFound

import model
import resources.apiError as apiError
import util as util
from enums.action_type import ActionType
from model import ProjectUserRole, db, UserMessageType
from nexus import nx_get_user_plugin_relation, nx_get_user
from plugins.sonarqube import sonarqube_main as sonarqube
from plugins.ad.ad_main import ldap_api
from resources import harbor, role
from resources import kubernetesClient
from resources.activity import record_activity
from resources.apiError import DevOpsError
from resources.gitlab import gitlab
from resources.logger import logger
from resources.redmine import redmine, update_user_mail_mail_notification_option
from resources.project import get_project_list

from resources.keycloak import key_cloak
from resources.handler.jwt import get_jwt_identity
import resources
from sqlalchemy import desc, nullslast
import gitlab as gitlab_pack
from resources.mail import mail_server_is_open
from resources.notification_message import create_notification_message
import base64
from typing import Any

# Make a regular expression
default_role_id = 3


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
            raise DevOpsError(500, "User id or row is not set!")
        return self.__user_id

    def get_user_row(self):
        if self.__user_row is None:
            self.set_user_row(model.User.query.filter_by(id=self.get_user_id()).one())
        return self.__user_row

    def to_json(self):
        ret = json.loads(str(self.get_user_row()))
        ret["default_role"] = {
            "id": self.default_role_id(),
            "name": role.get_role_name(self.default_role_id()),
        }
        return ret

    def default_role_id(self):
        for row in self.get_user_row().project_role:
            if row.project_id == -1:
                return row.role_id
        raise DevOpsError(
            500,
            "This user does not have project -1 role.",
            error=apiError.invalid_code_path("This user does not have project -1 role."),
        )

    def fill_dummy_user(self):
        self.set_user_row(model.User(id=0, name="No One"))


def get_user_id_name_by_plan_user_id(plan_user_id):
    return (
        db.session.query(model.User.id, model.User.name, model.User.login)
        .filter(
            model.UserPluginRelation.plan_user_id == plan_user_id,
            model.UserPluginRelation.user_id == model.User.id,
        )
        .first()
    )


def get_all_user_info():
    return (
        db.session.query(
            model.User.id,
            model.User.name,
            model.User.login,
            model.UserPluginRelation.plan_user_id,
        )
        .filter(model.UserPluginRelation.user_id == model.User.id)
        .all()
    )

def get_user_id_from_redmine_id(redmin_user_id: int):
    user = model.UserPluginRelation.query.filter_by(plan_user_id=redmin_user_id).first()
    return user.user_id

def get_role_id(user_id, project_id: int = -1):
    row = model.ProjectUserRole.query.filter_by(project_id=project_id, user_id=user_id).first()
    if row is not None:
        return row.role_id
    else:
        raise apiError.DevOpsError(404, "Error while getting role id", apiError.user_not_found(user_id))


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


def verify_password(db_password, login_password):
    is_verify = True
    h = SHA256.new()
    h.update(login_password.encode())
    hex_login_password = h.hexdigest()
    if db_password != hex_login_password:
        is_verify = False
    return is_verify, hex_login_password


def login(username: str, password: str) -> dict[str, Any]:
    wrong_pwd_or_username_error_res = util.respond(401, "Error when logging in.", error=apiError.wrong_password())
    user_query = model.User.query.filter_by(login=username).first()

    if user_query is None:
        return wrong_pwd_or_username_error_res
    token_info = key_cloak.get_token_by_account_pwd(username, password)
    access_token = token_info.get("access_token")
    if access_token is None:
        return wrong_pwd_or_username_error_res
    return util.success({"token": access_token})


def logout() -> None:
    user_id = get_jwt_identity()["user_id"]
    user_plugin_relation_query = model.UserPluginRelation.query.filter_by(user_id=user_id).first()
    if user_plugin_relation_query is None:
        logger.info(f"User id {user_id} not found")
        return

    key_cloak_user_id = user_plugin_relation_query.key_cloak_user_id
    key_cloak.logout_user(key_cloak_user_id)


def user_forgot_password(args):
    return "dummy_response", 200


def get_sysadmin_info(login):
    system_user = model.User.query.filter_by(login=login).first()
    if system_user is not None:
        return NexusUser().set_user_id(system_user.id).to_json()
    return {"id": 1}


@record_activity(ActionType.UPDATE_USER)
def update_user(user_id, args, from_ad=False, is_restore: bool = False):
    if is_restore:
        server_user_id_mapping = create_user_in_servers(args, is_restore)
    user = model.User.query.filter_by(id=user_id).first()
    if "role_id" in args:
        update_user_role(user_id, args.get("role_id"))
    user_role_id = -1
    if not from_ad:
        jwt_token = get_jwt_identity()
        if jwt_token is not None:
            user_role_id = jwt_token.get("role_id")
    new_email = None
    new_password = None
    # Change Password
    res = {}
    if args.get("password") is not None:
        if args["old_password"] == args["password"]:
            return util.respond(400, "Password is not changed.", error=apiError.wrong_password())
        # Only Update password from ad trigger or sysadmin can skip verify password
        if role.ADMIN.id != user_role_id and not from_ad:
            is_password_verify, hex_login_password = verify_password(user.password, args["old_password"])
            if args["old_password"] is None:
                return util.respond(400, "old_password is empty", error=apiError.wrong_password())
            if is_password_verify is False:
                return util.respond(400, "Password is incorrect", error=apiError.wrong_password())
        res = update_external_passwords(user_id, args["password"])
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
            err = update_external_email(user_id, user.name, args["email"])
            if err is not None:
                logger.exception(err)
            new_email = args["email"]
        if new_email is not None:
            user.email = new_email
        if args["name"] is not None:
            user.name = args["name"]
            update_external_name(user_id, args["name"])
        if args["phone"] is not None:
            user.phone = args["phone"]
        if args["title"] is not None:
            user.title = args["title"]
        if args["department"] is not None:
            user.department = args["department"]
        if args.get("status") is not None:
            status = args.get("status") == "disable"
            user.disabled = status
        if from_ad:
            user.update_at = args["update_at"]
        else:
            user.update_at = util.date_to_str(datetime.datetime.utcnow())

        if user.from_ad and not from_ad:
            return util.respond(400, "Error when updating Message", error=apiError.user_from_ad(user_id))
        db.session.commit()
        # Putting here to avoid not commit session error
        if args.get("status") is not None:
            operate_external_user(user_id, status)
    return util.success(res)


def update_user_role(user_id, role_id):
    if role_id is None:
        return
    role.require_admin("Only admin can update role.")
    role.update_role(user_id, role_id)


def generate_random_password() -> str:
    password = secrets.token_urlsafe(16)
    return password


def update_external_passwords(user_id, new_pwd):
    """
    The only server needs to update pwd is `key_cloak`,
    while updating `redmine` is necessary because it does't connect with `keyclock` server for now.
    """

    def update_error_handle(service: str):
        """
        In case new_pwd not valid in certain service, setting a default_ad_service as new_pwd in that service and send mail to them.
        """
        service_mapping = {
            "key_cloak": {
                "args_generator": lambda pwd: (user_relation.key_cloak_user_id, pwd),
                "update_func": key_cloak.update_user_password,
            },
            "redmine": {
                "args_generator": lambda pwd: (user_relation.plan_user_id, pwd),
                "update_func": redmine.rm_update_password,
            },
        }
        GENERATE_CREATE_NOTIFY_MSG = lambda service: {
            "alert_level": 1,
            "title": f"{service} password recreate automation",
            "message": f"password:{default_ad_service}",
            "type_ids": [3],
            "type_parameters": {"user_ids": [user_id]},
        }
        service_func_info_mapping = service_mapping[service]
        args = service_func_info_mapping["args_generator"](new_pwd)
        reset_args = service_func_info_mapping["args_generator"](default_ad_service)

        update_pwd_func = service_func_info_mapping["update_func"]
        ret = update_pwd_func(*args)
        error = int(ret.status_code / 100) != 2 if service != "key_cloak" else not ret["status"]

        if error:
            logger.info(f"Update Password error, service: {service}, set to default_ad_pwd, {ret.text}")
            update_pwd_func(*reset_args)
            updated_fail_service_pwd_mapping[service] = "default_pwd"
            create_notification_message(**GENERATE_CREATE_NOTIFY_MSG(service))
            update_error_handle_db(service)

    def update_error_handle_db(service: str):
        row = model.UpdatePasswordError.query.filter_by(user_id=user_id, server=service).first()
        current_time = datetime.datetime.utcnow()
        h = SHA256.new()
        h.update(new_pwd.encode())
        pwd = h.hexdigest()
        if row:
            row.created_at = current_time
            row.password = pwd
        else:
            row = model.UpdatePasswordError(
                user_id=user_id,
                server=service,
                password=pwd,
                created_at=current_time,
            )
            db.session.add(row)
        db.session.commit()

    default_ad_service = generate_random_password()
    login_account = model.User.query.filter_by(id=user_id).first().login
    updated_fail_service_pwd_mapping = {}
    try:
        user_relation = nx_get_user_plugin_relation(user_id=user_id)
        if user_relation is None:
            return util.respond(
                400,
                "Error when updating password",
                error=apiError.user_not_found(user_id),
            )
        services = ["key_cloak", "redmine"]
        for service in services:
            update_error_handle(service)
            logger.info(f"Account:{login_account} update {service} finish.")
        return updated_fail_service_pwd_mapping
    except Exception as e:
        logger.exception(f"user:{user_id} update failed, reason: {e}.")
        return e


def is_json(string):
    try:
        json.loads(string)
    except ValueError:
        return False
    return True


def row_to_dict(row):
    ret = {}
    if row is None:
        return row
    for key in type(row).__table__.columns.keys():
        value = getattr(row, key)
        if type(value) is datetime or type(value) is datetime.date:
            ret[key] = str(value)
        elif isinstance(value, str) and is_json(value):
            ret[key] = json.loads(value)
        else:
            ret[key] = value
    return ret


def get_decode_password(user_id):
    rows = model.UpdatePasswordError.query.filter_by(user_id=user_id).all()
    ret = []
    if rows:
        for row in rows:
            password = row_to_dict(row)["password"]
            decode_password = base64.b64decode(f"{password}".encode("UTF-8"))
            result_dict = {
                "server": row.server,
                "status": 0,
                "password": decode_password.decode("UTF-8"),
            }
            ret.append(result_dict)
    server_list = [data["server"] for data in ret]
    for server in ["redmine", "gitlab", "harbor", "sonarqube"]:
        if server not in server_list:
            ret.append({"server": server, "status": 1})
    return ret


def checker(kwargs):
    import string

    valid_dict = {}
    valid = True
    msg = "check"
    for i in string.ascii_uppercase:
        if i in kwargs.get("new_pwd"):
            valid_dict.update({"uppercase_check": True})
            msg = "check pass"
            break
        else:
            valid_dict.update({"uppercase_check": False})
            msg = "password didn't contain uppercase letter"
    for i in string.ascii_lowercase:
        if re.search("%s{3,}" % i, kwargs.get("new_pwd")):
            if re.search("[A-Za-z]%s{3,}" % i, kwargs.get("new_pwd")) or re.search(
                "%s{3,}[A-Za-z]" % i, kwargs.get("new_pwd")
            ):
                valid_dict.update({"continuously_check": True})
            else:
                valid_dict.update({"continuously_check": False})
                msg = "exist only 3 continuously letter"
    for i in string.ascii_uppercase:
        if re.search("%s{3,}" % i, kwargs.get("new_pwd")):
            if re.search("[A-Za-z]%s{3,}" % i, kwargs.get("new_pwd")) or re.search(
                "%s{3,}[A-Za-z]" % i, kwargs.get("new_pwd")
            ):
                valid_dict.update({"continuously_check": True})
                break
            else:
                valid_dict.update({"continuously_check": False})
                msg = "exist only 3 continuously letter"
    if len(kwargs.get("new_pwd")) >= 8:
        valid_dict.update({"nine_word_check": True})
    else:
        valid_dict.update({"nine_word_check": False})
        msg = "password less than nine word"
    if kwargs.get("new_pwd") != kwargs.get("old_pwd"):
        valid_dict.update({"same_password_check": True})
    else:
        valid_dict.update({"same_password_check": False})
        msg = "new password same as old password"
    for key, value in valid_dict.items():
        if not value:
            valid = False
            break
        else:
            valid = True
    return valid, msg


def update_newpassword(user_id, kwargs):
    valid = False
    msg = "Default msg"
    user_login = nx_get_user(id=user_id).login
    user_relation = nx_get_user_plugin_relation(user_id=user_id)
    try:
        if user_relation is None:
            return util.respond(
                400,
                "Error when updating password",
                error=apiError.user_not_found(user_id),
            )
        if kwargs.get("server") == "redmine":
            redmine_user_id = user_relation.plan_user_id
            result = redmine.rm_update_password(redmine_user_id, kwargs.get("new_pwd"))
            if int(result.status_code / 100) == 2:
                valid = True
        elif kwargs.get("server") == "gitlab":
            gitlab_user_id = user_relation.repository_user_id
            result = gitlab.gl_update_password(gitlab_user_id, kwargs.get("new_pwd"))
            if int(result.status_code / 100) == 2:
                valid = True
        elif kwargs.get("server") == "harbor":
            harbor_user_id = user_relation.harbor_user_id
            check_valid, msg = checker(kwargs)
            if check_valid:
                try:
                    result = harbor.hb_update_user_password(
                        harbor_user_id, kwargs.get("new_pwd"), kwargs.get("old_pwd")
                    )
                    if int(result.status_code / 100) == 2:
                        valid = True
                except Exception:
                    msg = "harbor fail"
                    valid = False
        elif kwargs.get("server") == "sonarqube":
            result = sonarqube.sq_update_password(user_login, kwargs.get("new_pwd"))
            if int(result.status_code / 100) == 2:
                valid = True
        if valid:
            encode_password = base64.b64encode(f"{kwargs.get('new_pwd')}".encode("UTF-8"))
            print(encode_password.decode("UTF-8"))
            update = {"password": encode_password.decode("UTF-8")}
            db.session.query(model.UpdatePasswordError).filter_by(user_id=user_id, server=kwargs.get("server")).update(
                update
            )
            db.session.commit()
        result_dict = {"valid": valid, "msg": msg}
        return msg, valid
    except Exception as e:
        return e


def update_external_email(user_id, user_name, new_email):
    user_relation = nx_get_user_plugin_relation(user_id=user_id)
    if user_relation is None:
        return util.respond(400, "Error when updating email", error=apiError.user_not_found(user_id))
    redmine_user_id = user_relation.plan_user_id
    redmine.rm_update_email(redmine_user_id, new_email)

    key_cloak_id = user_relation.key_cloak_user_id
    key_cloak.update_user(key_cloak_id, {"email": new_email})


def update_external_name(user_id, new_name):
    relation = nx_get_user_plugin_relation(user_id=user_id)
    redmine.rm_update_user_name(relation.plan_user_id, new_name)

    key_cloak_id = relation.key_cloak_user_id
    key_cloak.update_user(key_cloak_id, {"lastName": new_name})


def operate_external_user(user_id, disabled):
    active_id = 3 if disabled else 1
    relation = nx_get_user_plugin_relation(user_id=user_id)
    redmine.rm_update_user_active(relation.plan_user_id, active_id)

    key_cloak_id = relation.key_cloak_user_id
    key_cloak.update_user(key_cloak_id, {"enabled": not disabled})


def try_to_delete(delete_method, obj):
    try:
        delete_method(obj)
    except DevOpsError as e:
        if e.status_code != 404:
            raise e


@record_activity(ActionType.DELETE_USER)
def delete_user(user_id):
    if user_id == 1:
        raise apiError.NotAllowedError("You cannot delete the system admin.")
    pj_list = get_project_list(user_id)
    for pj in pj_list:
        if pj["owner_id"] == user_id:
            nexus.nx_update_project(pj["id"], {"owner_id": 1})

    relation = nx_get_user_plugin_relation(user_id=user_id)
    user_login = model.User.query.filter_by(id=user_id).one().login
    pj_ur_rls = (
        db.session.query(model.Project, model.ProjectUserRole)
        .join(model.ProjectUserRole)
        .filter(
            model.ProjectUserRole.user_id == user_id,
            model.ProjectUserRole.project_id != -1,
            model.ProjectUserRole.project_id == model.Project.id,
        )
        .all()
    )

    # change owner_id to system admin
    rows = model.Project.query.filter_by(owner_id=user_id).all()
    if rows:
        for row in rows:
            row.owner_id = 1
        db.session.commit()

    try_to_delete(gitlab.gl_delete_user, relation.repository_user_id)
    try_to_delete(redmine.rm_delete_user, relation.plan_user_id)
    try_to_delete(key_cloak.delete_user, relation.key_cloak_user_id)
    try_to_delete(sonarqube.sq_deactivate_user, user_login)
    try:
        for pur_row in pj_ur_rls:
            kubernetesClient.delete_role_binding(pur_row.Project.name, f"{util.encode_k8s_sa(user_login)}-rb")
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
    return None


def delete_db_user(user_id: int):
    del_user = model.User.query.filter_by(id=user_id).one()
    db.session.delete(del_user)
    db.session.commit()


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
            404,
            "Error when change user status.",
            error=apiError.user_not_found(user_id),
        )


########## Create User ##########


@record_activity(ActionType.CREATE_USER)
def create_user(args: dict[str, Any], is_restore: bool = False) -> dict[str, Any]:
    """Due to keyclock issue, do not need to create harbor's user."""
    logger.info("Creating user...")
    if not is_restore:
        check_create_user_args(args)
    server_user_id_mapping = create_user_in_servers(args, is_restore)
    logger.info("User created.")

    return {
        "user_id": server_user_id_mapping["db"]["id"],
        "key_cloak_user_id": server_user_id_mapping.get("key_cloak", {}).get("id"),
        "plan_user_id": server_user_id_mapping["redmine"]["id"],
        "repository_user_id": server_user_id_mapping["gitlab"]["id"],
        "kubernetes_sa_name": server_user_id_mapping["k8s"]["id"],
    }


def check_create_user_args(args: dict[str, Any]) -> None:
    check_create_user_login_valid(args["login"])
    check_create_user_pwd_valid(args["password"], args.get("from_ad", False))
    check_create_user_login_email_unique(args["login"], args["email"], args.get("force", False))


def check_create_user_login_valid(login_name: str) -> None:
    if re.fullmatch(r"^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,58}[a-zA-Z0-9]$", login_name) is None:
        raise apiError.DevOpsError(
            400,
            "Error when creating new user",
            error=apiError.invalid_user_name(login_name),
        )
    logger.info("Name is valid.")


def check_create_user_pwd_valid(user_source_password: str, from_ad: bool) -> None:
    #  User created by AD skip password check
    need_password_check = not from_ad
    if (
        need_password_check is True
        and re.fullmatch(
            r"(?=.*\d)(?=.*[a-z])(?=.*[A-Z])" r"^[\w!@#$%^&*()+|{}\[\]`~\-\'\";:/?.\\>,<]{8,20}$",
            user_source_password,
        )
        is None
    ):
        raise apiError.DevOpsError(400, "Error when creating new user", error=apiError.invalid_user_password())
    logger.info("Password is valid.")


def check_create_user_login_email_unique(login_name: str, email: str, force: bool) -> None:
    check_create_user_login_email_unique_db(login_name, email)
    check_create_user_login_email_unique_keycloak(login_name, email, force)
    check_create_user_login_email_unique_redmine(login_name, email, force)
    check_create_user_login_email_unique_gitlab(login_name, email, force)
    check_create_user_login_email_unique_k8s(login_name, email, force)
    check_create_user_login_email_unique_sonarqube(login_name, force)


def check_create_user_login_email_unique_db(login_name: str, email: str) -> None:
    # Check DB has this login, email, if has, raise error
    check_count = model.User.query.filter(
        db.or_(
            model.User.login == login_name,
            model.User.email == email,
        )
    ).count()
    if check_count > 0:
        raise DevOpsError(
            422,
            "System already has this account or email.",
            error=apiError.already_used(),
        )
    logger.info("Account is unique.")


def check_create_user_login_email_unique_keycloak(login_name: str, email: str, force: bool) -> None:
    # Check Keycloak has this login, email, if has, raise error(if force remove it.)
    same_email_in_keycloak_users = key_cloak.get_users({"email": email})
    same_username_in_keycloak_users = key_cloak.get_users({"username": login_name})
    if same_email_in_keycloak_users or same_username_in_keycloak_users:
        if not force:
            raise DevOpsError(
                422,
                "Keycloak already has this account or email.",
                error=apiError.already_used(),
            )
        logger.info("Force is True, so delete this Redmine account.")
        for keycloak_user_info in same_email_in_keycloak_users + same_username_in_keycloak_users:
            key_cloak.delete_user(keycloak_user_info["id"])
    logger.info("Account name not used in Keycloak or force is True.")


def check_create_user_login_email_unique_hb(login_name: str, email: str, force: bool) -> None:
    # Check Harbour has this login, email, if has, raise error(if force remove it.)
    hb_login_list = harbor.hb_search_user(login_name)
    if hb_login_list:
        for hb_login in hb_login_list:
            hb_user = harbor.hb_get_user(hb_login["user_id"])
            if hb_user["username"] == login_name or hb_user["email"] == email:
                if force:
                    harbor.hb_delete_user(hb_user["user_id"])
                    logger.info("Force is True, so delete this Harbour account.")
                else:
                    raise DevOpsError(
                        422,
                        "Harbour already has this account or email.",
                        error=apiError.already_used(),
                    )
    logger.info("Account name not used in Harbour or force is True.")


def check_create_user_login_email_unique_redmine(login_name: str, email: str, force: bool) -> None:
    # Check Redmine has this login, email, if has, raise error(if force remove it.)
    offset = 0
    limit = 25
    total_count = 1
    while offset < total_count:
        params = {"offset": offset, "limit": limit}
        user_list_output = redmine.rm_get_user_list(params)
        total_count = user_list_output["total_count"]
        for user in user_list_output["users"]:
            if user["login"] == login_name or user["mail"] == email:
                if force:
                    redmine.rm_delete_user(user["id"])
                    logger.info("Force is True, so delete this Redmine account.")
                else:
                    raise DevOpsError(
                        422,
                        "Redmine already has this account or email.",
                        error=apiError.already_used(),
                    )
        offset += limit
    logger.info("Account name not used in Redmine or force is True.")


def check_create_user_login_email_unique_gitlab(login_name: str, email: str, force: bool) -> None:
    # Check Gitlab has this login, email, if has, raise error(if force remove it.)
    login_users = gitlab.gl.search(gitlab_pack.const.SEARCH_SCOPE_USERS, login_name)
    for login_user in login_users:
        gl_user = gitlab.gl.users.get(login_user["id"])
        if gl_user.name == login_name or gl_user.email == email:
            if force:
                gitlab.gl_delete_user(gl_user.id)
                logger.info("Force is True, so delete this Gitlab account.")
            else:
                raise DevOpsError(
                    422,
                    "Gitlab already has this account or email.",
                    error=apiError.already_used(),
                )
    logger.info("Account name not used in Gitlab or force is True.")


def check_create_user_login_email_unique_k8s(login_name: str, email: str, force: bool) -> None:
    # Check Kubernetes has this Service Account (login), if has, return error 400(if force remove it.)
    sa_list = kubernetesClient.list_service_account()
    login_sa_name = util.encode_k8s_sa(login_name)
    if login_sa_name in sa_list:
        if force:
            kubernetesClient.delete_service_account(login_sa_name)
            logger.info("Force is True, so delete this kubernetes account.")
        else:
            raise DevOpsError(
                422,
                "Kubernetes already has this Kubernetes account.",
                error=apiError.already_used(),
            )
    logger.info("Account name not used in kubernetes or force is True.")


def check_create_user_login_email_unique_sonarqube(login_name: str, force: bool) -> None:
    # Check SonarQube has this login, if has, raise error(if force deactivate it.)
    page = 1
    page_size = 50
    total_size = 20
    while total_size > 0:
        params = {"p": page, "ps": page_size}
        output = sonarqube.sq_list_user(params).json()
        for user in output["users"]:
            if user["login"] == login_name:
                if force:
                    sonarqube.sq_deactivate_user(login_name)
                    logger.info("Force is True, so deactivate this SonarQube account.")
                else:
                    raise DevOpsError(
                        422,
                        "SonarQube already has this account.",
                        error=apiError.already_used(),
                    )
        total_size = int(output["paging"]["total"]) - (page * page_size)
        page += 1
    logger.info("Account name not used in SonarQube or force is True.")


def create_user_in_servers(args: dict[str, Any], is_restore: bool = False) -> dict[str, dict[str:Any]]:
    """
    k8s: Use name to delete instead of id
    Sonarqube: Can not be delete, can only deactivate(and use name instead)
    """
    server_user_id_mapping = {
        "redmine": {"id": None, "delete_func": redmine.rm_delete_user, "is_add": True},
        "gitlab": {"id": None, "delete_func": gitlab.gl_delete_user, "is_add": True},
        "k8s": {"id": None, "delete_func": kubernetesClient.delete_service_account, "is_add": True},
        "key_cloak": {"id": None, "delete_func": key_cloak.delete_user, "is_add": True},
        "sonarqube": {"id": None, "delete_func": sonarqube.sq_deactivate_user, "is_add": True},
        "db": {"id": None, "delete_func": delete_db_user, "is_add": True},
    }
    role_id = args["role_id"]
    is_admin = role_id == role.ADMIN.id
    logger.info(f"is_admin is {is_admin}")
    try:
        kc_id = None
        if is_restore:
            kc_id = get_user_id_in_key_cloak(args.get("login"))
        if kc_id:
            server_user_id_mapping["key_cloak"]["id"] = kc_id
            server_user_id_mapping["key_cloak"]["is_add"] = False
        else:
            server_user_id_mapping["key_cloak"]["id"] = create_user_in_key_cloak(args, is_admin)
        rm_id = None
        if is_restore:
            rm_id = get_user_id_in_redmine(args.get("login"))
            print(rm_id)
        if rm_id:
            server_user_id_mapping["redmine"]["id"] = rm_id
            server_user_id_mapping["redmine"]["is_add"] = False
        else:
            server_user_id_mapping["redmine"]["id"] = create_user_in_redmine(args, is_admin)
        gl_id = None
        if is_restore:
            gl_id = get_user_id_in_gitlab(args.get("login"), args.get("email"))
        if gl_id:
            server_user_id_mapping["gitlab"]["id"] = gl_id
            server_user_id_mapping["gitlab"]["is_add"] = False
        else:
            server_user_id_mapping["gitlab"]["id"] = create_user_in_gitlab(args, is_admin)
        sa_name = None
        if is_restore:
            sa_name = get_sa_name_in_k8s(args.get("login"))
            print(sa_name)
        if sa_name:
            server_user_id_mapping["k8s"]["id"] = sa_name
            server_user_id_mapping["k8s"]["is_add"] = False
        else:
            server_user_id_mapping["k8s"]["id"] = create_user_in_k8s(args, is_admin)
        sq_login = None
        if is_restore:
            sq_login = get_login_in_sonarqube(args.get("login"))
        if sq_login:
            server_user_id_mapping["sonarqube"]["id"] = sq_login
            server_user_id_mapping["sonarqube"]["is_add"] = False
        else:
            server_user_id_mapping["sonarqube"]["id"] = create_user_in_sonarqube(args)
        user_id = None
        if is_restore:
            if args.get("id"):
                user_id = args.get("id")
        if user_id:
            server_user_id_mapping["db"] = {"id": user_id, "is_add": False}
        else:
            server_user_id_mapping["db"] = {"id": create_user_in_db(args)}
        create_user_in_other_dbs(server_user_id_mapping, role_id, is_restore)
    except Exception as e:
        for _, id_delete_func_mapping in server_user_id_mapping.items():
            user_id = id_delete_func_mapping["id"]
            if id_delete_func_mapping["is_add"] and id_delete_func_mapping["id"] is not None and _ != "db":
                id_delete_func_mapping["delete_func"](user_id)
        if is_restore:
            logger.info({
                "api": "user restore",
                "id": args.get('id'),
                "login": args.get("login"),
                "service": _,
                "error_message": e,
            })
        else:
            raise e
    return server_user_id_mapping


def create_user_in_key_cloak(args: dict[str, Any], is_admin: bool) -> int:
    """
    Create user with admin role
    """
    key_cloak_id = key_cloak.create_user(args, is_admin=is_admin)
    logger.info(f"Keycloak user created, id={key_cloak_id}")
    return key_cloak_id


def get_user_id_in_key_cloak(user_name: str) -> int or None:
    kc_list = key_cloak.get_users({"username": user_name})
    for kc in kc_list:
        if kc.get("username") == user_name:
            return kc.get("id")
    return None


def create_user_in_redmine(args: dict[str, Any], is_admin: bool) -> int:
    red_user = redmine.rm_create_user(args, args["password"], is_admin=is_admin)
    redmine_user_id = red_user["user"]["id"]
    logger.info(f"Redmine user created, id={redmine_user_id}")
    return redmine_user_id


def get_user_id_in_redmine(user_name: str) -> int or None:
    rm_list = redmine.rm_get_user_list({"name": user_name}).get("users")
    for rm in rm_list:
        if rm.get("login") == user_name:
            return rm.get("id")
    return None


def create_user_in_gitlab(args: dict[str, Any], is_admin: bool) -> int:
    """
    Due to users always log in using Keycloak.
    automatically generating a default password to set in gitlab for avoiding
    not matching to Gitlab's password policy.
    """
    pwd = generate_random_password()
    git_user = gitlab.gl_create_user(args, pwd, is_admin=is_admin)
    gitlab_user_id = git_user["id"]
    logger.info(f"Gitlab user created, id={gitlab_user_id}")
    return gitlab_user_id


def get_user_id_in_gitlab(user_name: str, user_email: str) -> int or None:
    gl_list = gitlab.gl_get_user_list({"username": user_name}).json()
    if len(gl_list) == 0:
        gl_list = gitlab.gl_get_user_list({"search": user_email}).json()
    for gl in gl_list:
        if gl.get("username") == user_name or gl.get("email") == user_email:
            return gl.get("id")
    return None


def create_user_in_k8s(args: dict[str, Any], is_admin: bool) -> int:
    login_sa_name = util.encode_k8s_sa(args["login"])
    kubernetes_sa = kubernetesClient.create_service_account(login_sa_name)
    kubernetes_sa_name = kubernetes_sa.metadata.name
    logger.info(f"Kubernetes user created, sa_name={kubernetes_sa_name}")
    return kubernetes_sa_name


def get_sa_name_in_k8s(user_name: str) -> str or None:
    login_sa_name = util.encode_k8s_sa(user_name)
    sa_list = kubernetesClient.list_service_account()
    for sa in sa_list:
        if sa == login_sa_name:
            return sa
    return None


def create_user_in_sonarqube(args: dict[str, Any]) -> str:
    sonarqube.sq_create_user(args)
    sonarqube.sq_update_identity_provider(args)
    logger.info(f"Sonarqube user created.")
    return args["login"]


def get_login_in_sonarqube(user_name: str) -> str or None:
    sq_list = sonarqube.sq_list_user({}).json().get("users")
    for sq in sq_list:
        if sq.get("login") == user_name:
            return sq.get("login")
    return None


def create_user_in_db(args: dict[str, Any]) -> int:
    title = department = ""
    h = SHA256.new()
    h.update(args["password"].encode())
    args["password"] = h.hexdigest()
    disabled = False

    if args["status"] == "disable":
        disabled = True
    if "title" in args:
        title = args["title"]
    if "department" in args:
        department = args["department"]
    user = model.User(
        name=args["name"],
        email=args["email"],
        phone=args["phone"],
        login=args["login"],
        title=title,
        department=department,
        password=h.hexdigest(),
        create_at=datetime.datetime.utcnow(),
        disabled=disabled,
        from_ad=("from_ad" in args) and (args["from_ad"]),
    )
    if "update_at" in args:
        user.update_at = args["update_at"]
    if "last_login" in args:
        user.last_login = args.get("last_login")
    db.session.add(user)
    db.session.commit()
    user_id = user.id
    logger.info(f"Nexus user created, id={user_id}")
    return user_id


def create_user_in_other_dbs(server_user_id_mapping: dict[str, dict[str, Any]], role_id: int, is_restore: bool = False):
    # insert user_plugin_relation table
    user_id = server_user_id_mapping["db"]["id"]
    rel = None
    if is_restore:
        rel = model.UserPluginRelation.query.filter_by(user_id=user_id).first()
    if rel:
        rel.plan_user_id = server_user_id_mapping["redmine"]["id"]
        rel.repository_user_id = server_user_id_mapping["gitlab"]["id"]
        rel.kubernetes_sa_name = server_user_id_mapping["k8s"]["id"]
        rel.key_cloak_user_id = server_user_id_mapping["key_cloak"]["id"]
    else:
        rel = model.UserPluginRelation(
            user_id=user_id,
            plan_user_id=server_user_id_mapping["redmine"]["id"],
            repository_user_id=server_user_id_mapping["gitlab"]["id"],
            kubernetes_sa_name=server_user_id_mapping["k8s"]["id"],
            key_cloak_user_id=server_user_id_mapping["key_cloak"]["id"],
        )
        db.session.add(rel)
    db.session.commit()
    logger.info(f"Nexus user_plugin built.")

    # insert project_user_role
    rol = None
    if is_restore:
        rol = model.ProjectUserRole.query.filter_by(project_id=-1, user_id=user_id).first()
    if rol:
        rol.role_id = role_id
    else:
        rol = model.ProjectUserRole(project_id=-1, user_id=user_id, role_id=role_id)
        db.session.add(rol)
    db.session.commit()
    logger.info(f"Nexus user project_user_role created.")

    # insert user_message_type
    if not is_restore:
        row = model.UserMessageType(user_id=user_id, teams=False, notification=True, mail=False)
        db.session.add(row)
        db.session.commit()
        logger.info(f"Nexus user_message_type created.")


########## Create User End ##########


def user_list(filters):
    per_page = 10
    page_dict = None
    query = model.User.query.filter(model.User.id != 1).order_by(nullslast(model.User.last_login.desc()))
    if "role_ids" in filters:
        filtered_user_ids = (
            model.ProjectUserRole.query.filter(model.ProjectUserRole.role_id.in_(filters["role_ids"]))
            .with_entities(model.ProjectUserRole.user_id)
            .distinct()
            .subquery()
        )
        query = query.filter(model.User.id.in_(filtered_user_ids))
    if "search" in filters:
        query = query.filter(
            or_(
                model.User.login.ilike(f'%{filters["search"]}%'),
                model.User.name.ilike(f'%{filters["search"]}%'),
            )
        )
    if "per_page" in filters:
        per_page = filters["per_page"]
    if "page" in filters:
        paginate_query = query.paginate(page=filters["page"], per_page=per_page, error_out=False)
        page_dict = {
            "current": paginate_query.page,
            "prev": paginate_query.prev_num,
            "next": paginate_query.next_num,
            "pages": paginate_query.pages,
            "per_page": paginate_query.per_page,
            "total": paginate_query.total,
        }
        rows = paginate_query.items
    else:
        rows = query.all()
    output_array = []
    for row in rows:
        output_array.append(NexusUser().set_user_row(row).to_json())
    response = {"user_list": output_array}
    if page_dict:
        response["page"] = page_dict
    return response


def user_list_by_project(project_id, args):
    excluded_roles = [role.BOT.id, role.ADMIN.id, role.QA.id]
    if args.get("exclude") is not None and args["exclude"] == 1:
        # list users not in the project
        users = []
        rows = model.User.query.options(joinedload(model.User.project_role)).all()
        for u in rows:
            for pr in u.project_role:
                if (
                    pr.project_id < 0
                    and pr.role_id in excluded_roles
                    or pr.project_id == project_id
                    or pr.user.disabled
                ):
                    break
            else:
                users.append(u)
        users.sort(key=lambda x: x.id, reverse=True)
        arr_ret = []
        for user_row in users:
            user = NexusUser().set_user_row(user_row)
            user_json = user.to_json()
            outer_role_id = user.default_role_id()
            user_json["role_id"] = outer_role_id
            user_json["role_name"] = role.get_role_name(outer_role_id)
            arr_ret.append(user_json)
        return arr_ret
    else:
        # list users in the project
        project_row = (
            model.Project.query.options(
                joinedload(model.Project.user_role)
                .joinedload(model.ProjectUserRole.user)
                .joinedload(model.User.project_role)
            )
            .filter_by(id=project_id)
            .one()
        )
        users = list(
            filter(
                lambda x: x.role_id not in excluded_roles and not x.user.disabled,
                project_row.user_role,
            )
        )
        users.sort(key=lambda x: x.user_id, reverse=True)
        arr_ret = []
        for relation_row in users:
            user_json = NexusUser().set_user_row(relation_row.user).to_json()
            user_json["role_id"] = relation_row.role_id
            user_json["role_name"] = role.get_role_name(relation_row.role_id)
            arr_ret.append(user_json)
        return arr_ret


def user_sa_config(user_id):
    ret_users = (
        db.session.query(model.User, model.UserPluginRelation.kubernetes_sa_name)
        .join(model.UserPluginRelation)
        .filter(model.User.id == user_id)
        .filter(model.User.disabled == False)
        .first()
    )
    sa_name = str(ret_users.kubernetes_sa_name)
    sa_config = kubernetesClient.get_service_account_config(sa_name)
    return util.success(sa_config)


def save_last_login(user):

    if user is not None:
        user.last_login = datetime.datetime.utcnow()
        db.session.commit()


def get_am_role_user():
    rows = ProjectUserRole.query.filter_by(role_id=5).with_entities(ProjectUserRole.user_id).distinct()
    return [row.user_id for row in rows]


# user message type
def row_to_dict(row):
    if row is None:
        return {}
    ret = {key: getattr(row, key) for key in type(row).__table__.columns.keys()}
    if ret.get("user_id") is not None:
        user_id = ret.pop("user_id")
        user = model.User.query.get(user_id)
        ret["user"] = {"id": user_id, "name": user.name, "login": user.login}
    return ret


def get_user_message_types(limit=None, offset=None):
    ret, page_dict = [], None
    users_message_type = UserMessageType.query
    if limit is not None and offset is not None:
        users_message_type, page_dict = util.orm_pagination(users_message_type, limit, offset)

    for user_message_type in users_message_type.all():
        ret.append(row_to_dict(user_message_type))

    if page_dict is not None:
        ret = {"user_message_type": ret, "page": page_dict}
    return ret


def get_user_message_type(user_id):
    return row_to_dict(UserMessageType.query.filter_by(user_id=user_id).first())


def get_user_json_by_login(login_name: str) -> dict:
    return row_to_dict(model.User.query.filter(model.User.login == login_name).first())


def get_user_json_by_email(email: str) -> dict:
    return row_to_dict(model.User.query.filter(model.User.email == email).first())


def update_user_message_types(user_id, args):
    users_message_type = UserMessageType.query.filter_by(user_id=user_id).first()
    if users_message_type is not None:
        teams, notification, mail = (
            args.get("teams"),
            args.get("notification"),
            args.get("mail"),
        )
        if teams is not None:
            users_message_type.teams = teams
        if notification is not None and get_jwt_identity()["role_id"] != 5:
            users_message_type.notification = notification
        if mail is not None:
            if not mail_server_is_open() and mail:
                raise DevOpsError(
                    400,
                    "Mail notification setting can not be opened, when mail server is disable.",
                    error=apiError.argument_error("mail"),
                )
            users_message_type.mail = mail
        db.session.commit()
