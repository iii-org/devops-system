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

    ##### User ######
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

    def delete_user(self, key_cloak_user_id: int) -> None:
        return self.keycloak_admin.delete_user(user_id=key_cloak_user_id)

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
            logger.exception(f"Fail to assign role on {key_cloak_user_id}, because role_name {role} has not definded")
            return
        return self.keycloak_admin.assign_realm_roles(user_id=key_cloak_user_id, roles=ad_role_info)

    ##### group ######
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
        new_group_id = self.keycloak_admin.create_group(paylload={"name": args["name"]})
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

    def assign_group(self, key_cloak_user_id: int, key_cloak_group_id: int):
        user_info = self.get_user(key_cloak_user_id)
        group_info = self.get_group(key_cloak_group_id)
        return self.keycloak_admin.group_user_add(key_cloak_user_id, key_cloak_group_id)


key_cloak = KeyCloak()
