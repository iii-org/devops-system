from flask import _request_ctx_stack, request, make_response
from resources import apiError
from model import User, db, ProjectUserRole
from resources import role
import util
from resources.keycloak import key_cloak,  set_tokens_in_cookies_and_return_response
import datetime
from resources import apiError
from typing import Any


REDIRECT_URL = key_cloak.generate_login_url()


# def __calculate_token_expired_datetime(sec: int):
#     now = datetime.datetime.now()
#     expired_datetime = now + datetime.timedelta(seconds=sec)
#     return expired_datetime


def return_jwt_token_if_exist():
    bearer_token = request.headers.get("Authorization")
    if bearer_token is None:
        raise apiError.DevOpsError(401, "Missing Authorization Header.", error=apiError.authorization_not_found(REDIRECT_URL))

    token = bearer_token.split(" ")[-1]
    return token


def __generate_jwt_identity_info_by_access_token(access_token: str) -> dict[str, Any]:
    account = key_cloak.get_user_info_by_token(access_token).get("preferred_username")
    user_model = User.query.filter_by(login=account).first()
    if user_model is None:
        raise apiError.DevOpsError(
            401, "Invalid token.", error=apiError.decode_token_user_not_found(access_token, account)
        )

    project_user_role = db.session.query(ProjectUserRole).filter(ProjectUserRole.user_id == user_model.id).first()
    role_id = project_user_role.role_id

    jwt_identity = {
        "user_id": user_model.id,
        "user_account": account,
        "role_id": role_id,
        "role_name": role.get_role_name(role_id),
        "from_ad": user_model.from_ad,
    }
    return jwt_identity


def jwt_required_cronjob(fn):
    def wrapper(*args, **kwargs):
        refresh_token = return_jwt_token_if_exist()

        token = key_cloak.get_token_by_refresh_token(refresh_token)
        if not token or token.get("access_token") is None:
            raise apiError.DevOpsError(401, "Invalid refresh token.", error=apiError.invalid_token(refresh_token, REDIRECT_URL))

        access_token = token.get("access_token")
        jwt_identity = __generate_jwt_identity_info_by_access_token(access_token)
        _request_ctx_stack.top.jwt = jwt_identity

        return fn(*args, **kwargs)

    return wrapper


def jwt_required(fn):
    def wrapper(*args, **kwargs):
        access_token = return_jwt_token_if_exist()
        token_info = check_login_status_and_return_refresh_token(access_token)
        if token_info:
            response_content = fn(*args, **kwargs)
            return set_tokens_in_cookies_and_return_response(token_info["access_token"], token_info["refresh_token"], response_content)

        jwt_identity = __generate_jwt_identity_info_by_access_token(access_token)
        _request_ctx_stack.top.jwt = jwt_identity

        return fn(*args, **kwargs)

    return wrapper


def check_login_status_and_return_refresh_token(access_token: str = None):
    if access_token is None:
        access_token = return_jwt_token_if_exist()
    user_info = key_cloak.get_user_info_by_token(access_token)
    account = user_info.get("preferred_username")

    if account is None:
        refresh_token = request.cookies.get("refresh_token")
        if refresh_token:
            token_info = key_cloak.get_token_by_refresh_token(refresh_token)
            if not token_info:
                raise apiError.DevOpsError(401, "Invalid token.", error=apiError.invalid_token(access_token, REDIRECT_URL))
            
            return {
                "access_token": token_info.get("access_token"),
                "refresh_token": token_info.get("refresh_token")
            }
            
        else:
            raise apiError.DevOpsError(401, "Invalid token.", error=apiError.invalid_token(access_token, REDIRECT_URL))
    return {}


def get_jwt_identity():
    decoded_jwt = getattr(_request_ctx_stack.top, "jwt", None)
    if decoded_jwt is None:
        raise RuntimeError("You must call `@jwt_required` before using this method")
    return decoded_jwt
