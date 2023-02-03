from typing import Any
from keycloak import KeycloakAdmin
from keycloak.exceptions import KeycloakGetError
from resources.logger import logger


KEYCLOAK_URL = "https://10.20.0.75:32110"
REALM_NAME = "IIIdevops"
CLIENT_ID = "IIIdevops"
CLIENT_SECRET_KEY = "OPkQ6b2pm9BhWG3EUUIhH4uK4Hg9G88O"
AM_REALM_ROLE_NAME = "admin"

# Root url: change to dev4


class KeyCloak:
    def __init__(self):
        self.keycloak_admin = KeycloakAdmin(
            server_url=KEYCLOAK_URL,
            username="admin",
            password="IIIdevops123!",
            realm_name=REALM_NAME,
            user_realm_name="master",
            auto_refresh_token=["get", "put", "post", "delete"],
            verify=False,
        )

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

    def get_users(self, args: dict[str, str] = {}):
        ret = self.keycloak_admin.get_users(args)

        return ret

    def get_user(self, key_cloak_user_id: int) -> dict[str, Any]:
        try:
            user = self.keycloak_admin.get_user(key_cloak_user_id)
        except KeycloakGetError as e:
            raise e
        return user

    def delete_user(self, key_cloak_user_id: int) -> None:
        return self.keycloak_admin.delete_user(user_id=key_cloak_user_id)

    def get_role_info(self, name: str = "") -> list[dict[str, Any]]:
        all_role_infos = self.keycloak_admin.get_realm_roles()
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
            ad_role_info = self.get_role_info(AM_REALM_ROLE_NAME)
        else:
            logger.exception(f"Fail to assign role on {key_cloak_user_id}, because role_name {role} has not definded")
            return
        return self.keycloak_admin.assign_realm_roles(user_id=key_cloak_user_id, roles=ad_role_info)


key_cloak = KeyCloak()
