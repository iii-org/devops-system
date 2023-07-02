from flask import _request_ctx_stack, request, make_response
from resources import apiError
from model import User, db, ProjectUserRole
from resources import role
from resources.keycloak import (
    key_cloak,
    set_tokens_in_cookies_and_return_response,
    set_ui_origin_in_cookie_and_return_response,
    REFRESH_TOKEN,
)

from resources import apiError
from typing import Any
from util import get_random_alphanumeric_string


# def __calculate_token_expired_datetime(sec: int):
#     now = datetime.datetime.now()
#     expired_datetime = now + datetime.timedelta(seconds=sec)
#     return expired_datetime


def return_jwt_token_if_exist():
    bearer_token = request.headers.get("Authorization")
    if bearer_token is None:
        return None

    token = bearer_token.split(" ")[-1]
    return token


def ad_login_if_not_exist_then_create_user(token_info: dict[str, Any]) -> dict[str, Any]:
    account = token_info.get("preferred_username")
    user_model = User.query.filter_by(login=account).first()
    if user_model is None:
        from resources.user import recreate_user

        # Login by AD, but not exist in DB.
        depart, title, key_clock_id, email = (
            token_info.get("department"),
            token_info.get("title"),
            token_info.get("sid"),
            token_info.get("email"),
        )

        """
        if ad login, keycloack must provide the following key: name / email / department / title.
        """
        args = {
            "name": account,
            "password": get_random_alphanumeric_string(6, 3),
            "email": email,
            "department": depart,
            "title": title,
            "login": account,
            "from_ad": True,
            "role_id": role.PM.id,
            "key_cloak_user_id": key_clock_id,
        }
        server_user_ids_mapping = recreate_user(args, ["db", "redmine", "gitlab", "k8s", "sonarqube"])
        user_id = server_user_ids_mapping["user_id"]
    else:
        user_id = user_model.id
    return user_id


def __generate_jwt_identity_info_by_access_token(access_token: str) -> dict[str, Any]:
    key_cloak_token_info = key_cloak.get_user_info_by_token(access_token)
    account = key_cloak_token_info.get("preferred_username")
    user_model = User.query.filter_by(login=account).first()

    if user_model is None:
        source = key_cloak_token_info.get("source")
        is_ad_login_condition = source == "LDAP"
        if not is_ad_login_condition:
            raise apiError.DevOpsError(
                401, "Invalid token.", error=apiError.decode_token_user_not_found(access_token, account)
            )
        user_id, from_ad = ad_login_if_not_exist_then_create_user(key_cloak_token_info), is_ad_login_condition
    else:
        user_id, from_ad = user_model.id, user_model.from_ad

    project_user_role = db.session.query(ProjectUserRole).filter(ProjectUserRole.user_id == user_id).first()
    role_id = project_user_role.role_id

    jwt_identity = {
        "user_id": user_id,
        "user_account": account,
        "role_id": role_id,
        "role_name": role.get_role_name(role_id),
        "from_ad": from_ad,
    }
    return jwt_identity


def jwt_required_cronjob(fn):
    def wrapper(*args, **kwargs):
        refresh_token = return_jwt_token_if_exist()

        token = key_cloak.get_token_by_refresh_token(refresh_token)
        if not token or token.get("access_token") is None:
            raise apiError.DevOpsError(
                401,
                "Invalid refresh token.",
                error=apiError.invalid_token(refresh_token, key_cloak.generate_login_url()),
            )

        access_token = token.get("access_token")
        jwt_identity = __generate_jwt_identity_info_by_access_token(access_token)
        _request_ctx_stack.top.jwt = jwt_identity

        return fn(*args, **kwargs)

    return wrapper


def jwt_required(fn):
    def wrapper(*args, **kwargs):
        access_token = return_jwt_token_if_exist()
        if access_token is None:
            resp = make_response(apiError.authorization_not_found(key_cloak.generate_login_url()), 401)
            return set_ui_origin_in_cookie_and_return_response(resp)

        token_info = check_login_status_and_return_refresh_token(access_token)

        if not token_info["account_exist"] or token_info["from_ad"]:
            if token_info["token_invalid"]:
                resp = make_response(apiError.invalid_token(access_token, key_cloak.generate_login_url()), 401)
                return set_ui_origin_in_cookie_and_return_response(resp)

            jwt_identity = __generate_jwt_identity_info_by_access_token(token_info.get("access_token", access_token))
            _request_ctx_stack.top.jwt = jwt_identity

            response_content = fn(*args, **kwargs)
            return set_tokens_in_cookies_and_return_response(
                token_info["access_token"], token_info["refresh_token"], response_content
            )

        jwt_identity = __generate_jwt_identity_info_by_access_token(access_token)
        _request_ctx_stack.top.jwt = jwt_identity

        return fn(*args, **kwargs)

    return wrapper


def check_login_status_and_return_refresh_token(access_token: str) -> dict[str, Any]:
    user_info = key_cloak.get_user_info_by_token(access_token)
    account = user_info.get("preferred_username")
    account_exist = account is not None
    ret = {"account_exist": account_exist, "token_invalid": False, "from_ad": user_info.get("source") == "LDAP"}

    if not account_exist:
        refresh_token = request.cookies.get(REFRESH_TOKEN)
        if refresh_token:
            token_info = key_cloak.get_token_by_refresh_token(refresh_token)
            if not token_info:
                ret["token_invalid"] = True

            ret.update(
                {"access_token": token_info.get("access_token"), "refresh_token": token_info.get("refresh_token")}
            )
        else:
            ret["token_invalid"] = True
    return ret


def get_jwt_identity():
    decoded_jwt = getattr(_request_ctx_stack.top, "jwt", None)
    if decoded_jwt is None:
        raise RuntimeError("You must call `@jwt_required` before using this method")
    return decoded_jwt
