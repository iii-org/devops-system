from typing import Any
from keycloak import KeycloakAdmin, KeycloakOpenID
from keycloak.exceptions import KeycloakGetError, KeycloakAuthenticationError
from resources.logger import logger
import config
import re
import uuid
from werkzeug.wrappers import Response

KEYCLOAK_URL = config.get("KEYCLOAK_URL")
REALM_NAME = "IIIdevops"
CLIENT_SECRET_KEY = config.get("KEYCLOAK_SECRET_KEY")
CLIENT_ID = "iiidevops"
AM_REALM_ROLE_NAME = "admin"
KEYCLOAK_ADMIN_ACCOUNT = config.get("KEYCLOAK_ADMIN_ACCOUNT")
KEYCLOAK_ADMIN_PASSWORD = config.get("KEYCLOAK_ADMIN_PASSWORD")

REDIRECT_URL = f'{config.get("III_BASE_URL")}/v2/user/generate_token'
TOKEN = "jwtToken"
REFRESH_TOKEN = "refreshToken"
UI_ORIGIN = "ui_origin"
# Root url: change to dev4


class KeyCloak:
    def __init__(self):
        self.keycloak_admin = KeycloakAdmin(
            server_url=KEYCLOAK_URL,
            username=KEYCLOAK_ADMIN_ACCOUNT,
            password=KEYCLOAK_ADMIN_PASSWORD,
            realm_name=REALM_NAME,
            user_realm_name="master",
            auto_refresh_token=["get", "put", "post", "delete"],
        )
        self.keycloak_openid = KeycloakOpenID(
            server_url=KEYCLOAK_URL,
            client_id=CLIENT_ID,
            realm_name=REALM_NAME,
            client_secret_key=CLIENT_SECRET_KEY,
        )

    ##### auth url ######
    def generate_login_url(self):
        random_string = generate_random_state()
        keycloak_login_url = self.keycloak_openid.auth_url(
            redirect_uri=REDIRECT_URL, scope="openid", state=random_string
        )
        logger.info(f"redirect_url: {REDIRECT_URL}")
        return keycloak_login_url

    ##### user ######
    def create_user(self, args: dict[str, Any], force: bool = False, is_admin: bool = False) -> int:
        """
        should adjust create_user's param 'enable'
        """
        new_user_id = self.keycloak_admin.create_user(
            {
                "email": args["email"],
                "username": args["login"],
                "enabled": True,
                "emailVerified": True,
                "firstName": "#",
                "lastName": args["name"],
                "credentials": [
                    {
                        "value": args["password"],
                        "type": "password",
                    }
                ],
            },
            exist_ok=force,
        )
        if is_admin:
            self.assign_role(new_user_id, "admin")
        return new_user_id

    def get_users(self, query: dict[str, str] = {}):
        """
        :param query: available key(for now): name
        """
        ret = self.keycloak_admin.get_users(query)

        return ret

    def get_user(self, key_cloak_user_id: int) -> dict[str, Any]:
        try:
            user = self.keycloak_admin.get_user(key_cloak_user_id)
        except KeycloakGetError as e:
            return e
        return user

    def update_user(self, key_cloak_user_id: int, args: dict[str, Any]):
        """
        :param args: available keys: name, email, enabled(bool)
        """
        self.keycloak_admin.update_user(user_id=key_cloak_user_id, payload=args)

    def set_user_password(self, key_cloak_user_id: int, pwd: str) -> dict[str, Any]:
        ret = self.keycloak_admin.set_user_password(user_id=key_cloak_user_id, password=pwd, temporary=False)
        return {"status": not ret, "msg": ret.get("msg") or ret}

    def delete_user(self, key_cloak_user_id: int) -> None:
        return self.keycloak_admin.delete_user(user_id=key_cloak_user_id)

    def logout_user(self, key_cloak_user_id: int) -> None:
        """
        Remove all user sessions associated with the user.
        """
        return self.keycloak_admin.user_logout(user_id=key_cloak_user_id)

    def update_user_password(self, key_cloak_user_id: int, pwd: str) -> dict[str, Any]:
        """
        Add logger maybe.
        """
        ret = self.set_user_password(key_cloak_user_id, pwd)
        # user_sessions = self.get_sessions(key_cloak_user_id)
        # if not user_sessions:
        #     logger.info(f"Key cloak user:{key_cloak_user_id} has not session. Don't need to log out.")
        # else:
        #     logger.info(f"Log out all sessions of Key cloak user:{key_cloak_user_id}.")
        #     self.logout_user(key_cloak_user_id)
        return ret

    ##### token ######
    def get_token_by_code(self, code: str, scope: str = "openid") -> dict[str, Any]:
        try:
            token = self.keycloak_openid.token(code=code, grant_type="authorization_code", redirect_uri=REDIRECT_URL)
        except KeycloakAuthenticationError as e:
            logger.exception("Fail to authorize token, error_msg: {str(e)}")
            token = {}
        return token


    def get_token_by_account_pwd(self, account: str, pwd: str, scope: str = "openid") -> dict[str, Any]:
        try:
            token = self.keycloak_openid.token(account, pwd, scope=scope)
        except KeycloakAuthenticationError as e:
            logger.exception("Fail to authorize token, error_msg: {str(e)}")
            token = {}
        return token

    def get_user_info_by_token(self, access_token: str) -> dict[str, Any]:
        try:
            ret = self.keycloak_openid.introspect(access_token)
        except Exception as e:
            logger.exception("Fail to authorize token, error_msg: {str(e)}")
            ret = {}
        return ret

    def get_token_by_refresh_token(self, refresh_token: str) -> dict[str, Any]:
        try:
            token = self.keycloak_openid.refresh_token(refresh_token)
        except Exception as e:
            logger.exception("Fail to refresh token, error_msg: {str(e)}")
            token = {}
        return token

    ##### role ######
    def get_roles(self, query: dict[str, str] = {}) -> list[dict[str, Any]]:
        """
        :param query: available key(for now): name
        """
        all_role_infos = self.keycloak_admin.get_realm_roles()
        name = query.get("name", "")
        if not name:
            return all_role_infos

        match_role_info = []
        for role_info in all_role_infos:
            if role_info.get("name") == name:
                match_role_info = [role_info]
        return match_role_info

    def assign_role(self, key_cloak_user_id: int, role: str):
        """
        :param role: admin
        """
        if role == "admin":
            ad_role_info = self.get_roles({"name": AM_REALM_ROLE_NAME})
        else:
            logger.exception(f"Fail to assign role on {key_cloak_user_id}, because role_name {role} has not defined")
            return
        return self.keycloak_admin.assign_realm_roles(user_id=key_cloak_user_id, roles=ad_role_info)

    ##### session ######
    def get_sessions(self, key_cloak_group_id: int):
        return self.keycloak_admin.get_sessions(key_cloak_group_id)

    ##### group ######
    ##### One project one group #####
    def get_group(self, key_cloak_group_id: int):
        try:
            group = self.keycloak_admin.get_group(key_cloak_group_id)
        except KeycloakGetError as e:
            raise e
        return group

    def get_groups(self, query: dict[str, str] = {}):
        """
        :param query: available key(for now): name
        """
        return self.keycloak_admin.get_groups(query)

    def create_group(self, args: dict[str, Any]) -> int:
        """
        :param args: must give keys: name
        """
        new_group_id = self.keycloak_admin.create_group(payload={"name": args["name"]})
        return new_group_id

    def delete_group(self, key_cloak_group_id: int):
        return self.keycloak_admin.delete_group(key_cloak_group_id)

    def delete_group_by_name(self, name: str):
        groups = self.get_groups(query={"name": name})

        match = False
        for group in groups:
            if group["name"] == name:
                self.delete_group(group["id"])
                match = True

        if not match:
            logger.exception("Can not find the match key_clock group.")
            return

    def assign_group(self, key_cloak_group_id: int, key_cloak_user_id: int):
        user_info = self.get_user(key_cloak_user_id)
        group_info = self.get_group(key_cloak_group_id)
        return self.keycloak_admin.group_user_add(key_cloak_user_id, key_cloak_group_id)


key_cloak = KeyCloak()


def generate_random_state():
    '''
    Generate random string to match xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
    '''
    uuid_string = str(uuid.uuid4())
    pattern = r'(\w{8})(\w{4})(\w{4})(\w{4})(\w{12})'
    formatted_uuid = re.sub(pattern, r'\1-\2-\3-\4-\5', uuid_string)
    return formatted_uuid


def set_tokens_in_cookies_and_return_response(access_token: str, refresh_token: str, response_content: Any = None) -> Response:
    '''
    - Need to return make_response object. otherwse cookie might not set successuflly.
    - Set the UI origin in this API in order to redirect to the correct UI URL after logging in.
    '''
    from flask import make_response, redirect, request
    iii_base_url = config.get("III_BASE_URL")
    if response_content is None:
        base_url = request.cookies.get(UI_ORIGIN) or iii_base_url
        response_content =  redirect(base_url)
    
    domain = iii_base_url.split("://")[-1]
    domain = domain.split(":")[0]
    resp = make_response(response_content)
    resp.set_cookie(TOKEN, access_token, domain=domain)
    resp.set_cookie(REFRESH_TOKEN, refresh_token, domain=domain)

    if response_content is not None:
        ui_origin = request.referrer or iii_base_url
        resp.set_cookie(UI_ORIGIN, ui_origin, domain=domain)
    logger.info("Setting cookie successfully.")
    return resp


def generate_token_by_code_and_set_cookie(code: str) -> Response:
    logger.info(f"code: {code}")
    token_info = key_cloak.get_token_by_code(code)
    access_token, refresh_token = token_info.get("access_token", ""), token_info.get("refresh_token", "")
    return set_tokens_in_cookies_and_return_response(access_token, refresh_token)

