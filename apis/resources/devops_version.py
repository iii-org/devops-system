import uuid
from typing import Optional

from flask_restful import Resource
from requests import Response
from sqlalchemy.sql import and_

import config
import model
import resources.kubernetesClient as kubernetesClient
import util
from resources import role, apiError
from resources.apiError import DevOpsError
from resources.handler.jwt import jwt_required
from resources.logger import logger
from resources.notification_message import (
    check_message_exist,
    create_notification_message,
    close_notification_message,
)
from resources.redis import delete_template_cache
from resources.system import system_git_commit_id


class VersionCenter:
    CENTER_TOKEN: Optional[str] = None

    def __init__(self):
        self._get_token()

    def _get_token(self) -> None:
        """
        Check if token exist, if not, get token from version center.

        Returns:
            None
        """
        if not self.CENTER_TOKEN:
            self.login()

    def login(self) -> None:
        """
        Get token from version center if not exist.

        Returns:
            None
        """
        dp_uuid: str = model.NexusVersion.query.one().deployment_uuid
        response: Response = self.post(
            "/login",
            params={"uuid": dp_uuid, "name": config.get("DEPLOYMENT_NAME") or config.get("DEPLOYER_NODE_IP")},
            with_token=False,
        )

        self.CENTER_TOKEN = response.json().get("data", {}).get("access_token", None)

    def register(self, force: bool = False):
        """
        Register current deployment to version center.

        Args:
            force: Force to register even if already registered.

        Returns:
            None
        """
        nexus_version: Optional[model.NexusVersion] = model.NexusVersion.query.first()

        if not nexus_version:
            raise DevOpsError(500, "NexusVersion table is empty.")

        _version: Optional[str] = nexus_version.deploy_version
        _uuid: Optional[str] = nexus_version.deployment_uuid

        logger.info(f"Before deploy_version: {_version}, deployment_uuid: {_uuid}.")

        if _version is None or force:
            _version = system_git_commit_id().get("git_tag")
            logger.info(f"After deploy_version: {_version}.")

            nexus_version.deploy_version = _version
            model.db.session.commit()
            logger.info(f"Updating deploy_version to {_version}.")

        return self.post("/report_info", data={"iiidevops": {"deploy_version": _version}, "uuid": _uuid})

    def _call_api(
        self,
        path: str,
        method: str,
        *,
        headers: dict = None,
        params: dict = None,
        data: dict = None,
        with_token: bool = True,
        retry: bool = False,
    ) -> Response:
        """
        Call version center API.

        Args:
            path: The path of API, e.g. /login
            method: The method of API, only support GET and POST.
            headers: The headers of API.
            params: The params of API.
            data: The data of API.
            with_token: If True, add token to headers.
            retry: If True, retry once when token expire.

        Returns:
            Response: The response of API.
        """
        if headers is None:
            headers = dict()

        if params is None:
            params = dict()

        if with_token:
            headers["Authorization"] = f"Bearer {self.CENTER_TOKEN}"

        if path.startswith("/"):
            path = path[1:]

        if method not in ["GET", "POST"]:
            raise DevOpsError(500, "Only GET and POST method are supported.")

        url: str = f"{config.get('VERSION_CENTER_BASE_URL')}/{path}"
        output: Response = util.api_request(method, url, headers, params, data)

        # When token expire
        if output.status_code == 401 and not retry:
            self.login()
            return self._call_api(method, path, headers=headers, params=params, data=data, with_token=True, retry=True)

        if int(output.status_code / 100) != 2:
            raise DevOpsError(
                output.status_code,
                "Got non-2xx response from Version center.",
                error=apiError.error_3rd_party_api("Version Center", output),
            )
        return output

    def get(
        self,
        path: str,
        *,
        headers: dict = None,
        params: dict = None,
        data: dict = None,
        with_token: bool = True,
        retry: bool = False,
    ) -> Response:
        """
        Call version center GET API.

        Args:
            path: The path of API, e.g. /login
            headers: The headers of API.
            params: The params of API.
            data: The data of API.
            with_token: If True, add token to headers.
            retry: If True, retry once when token expire.

        Returns:
            Response: The response of API.
        """
        return self._call_api(
            path, "GET", headers=headers, params=params, data=data, with_token=with_token, retry=retry
        )

    def post(
        self,
        path: str,
        *,
        headers: dict = None,
        params: dict = None,
        data: dict = None,
        with_token: bool = True,
        retry: bool = False,
    ) -> Response:
        """
        Call version center POST API.

        Args:
            path: The path of API, e.g. /login
            headers: The headers of API.
            params: The params of API.
            data: The data of API.
            with_token: If True, add token to headers.
            retry: If True, retry once when token expire.

        Returns:
            Response: The response of API.
        """
        return self._call_api(
            path, "POST", headers=headers, params=params, data=data, with_token=with_token, retry=retry
        )


def set_deployment_uuid():
    my_uuid = uuid.uuid1()
    row = model.NexusVersion.query.first()
    row.deployment_uuid = my_uuid
    model.db.session.commit()
    return my_uuid


def has_devops_update():
    current_version = current_devops_version()
    try:
        versions = VersionCenter().get("/current_version").json().get("data", None)
    except Exception:
        return {
            "has_update": False,
            "latest_version": {
                "version_name": "N/A",
                "api_image_tag": "N/A",
                "ui_image_tag": "N/A",
                "create_at": "1970-01-01 00:00:00.000000",
            },
        }
    if versions is None:
        raise DevOpsError(500, "/current_version returns no data.")
    # Has new version, send notificaation message to administrators
    if current_version != versions["version_name"] and check_message_exist(versions["version_name"], 101) is False:
        args = {
            "alert_level": 101,
            "title": f"New version: {versions['version_name']}",
            "type_ids": [4],
            "type_parameters": {"role_ids": [5]},
            "message": f"New version: {versions['version_name']}",
        }
        # close old version notification message
        close_version_notification()
        create_notification_message(args, user_id=1)
    return {
        "has_update": current_version != versions["version_name"],
        "latest_version": versions,
    }


def update_deployment(versions):
    version_name = versions["version_name"]
    logger.info(f"Update deployment to {version_name}...")

    delete_template_cache()
    close_version_notification()

    api_image_tag = versions["api_image_tag"]
    ui_image_tag = versions["ui_image_tag"]

    kubernetesClient.update_deployment_image_tag("iiidevops", "devops-api", api_image_tag)
    kubernetesClient.update_deployment_image_tag("iiidevops", "devops-ui", ui_image_tag)
    # Record update done
    model.NexusVersion.query.one().deploy_version = version_name
    model.db.session.commit()
    VersionCenter().post("/report_update", data={"version_name": version_name})


def close_version_notification():
    rows = model.NotificationMessage.query.filter(
        and_(
            model.NotificationMessage.alert_level == 101,
            model.NotificationMessage.close == False,
        )
    ).all()
    if len(rows) > 0:
        for row in rows:
            close_notification_message(row.id)


def current_devops_version():
    return model.NexusVersion.query.one().deploy_version


def get_deployment_info():
    row = model.NexusVersion.query.one()
    return {
        "version_name": row.deploy_version,
        "deployment_name": config.get("DEPLOYMENT_NAME"),
        "deployment_uuid": row.deployment_uuid,
    }


# ------------------ Resources ------------------
class DevOpsVersion(Resource):
    @jwt_required
    def get(self):
        return util.success(get_deployment_info())


class DevOpsVersionCheck(Resource):
    @jwt_required
    def get(self):
        role.require_admin()
        return util.success(has_devops_update())


class DevOpsVersionUpdate(Resource):
    @jwt_required
    def patch(self):
        role.require_admin()
        versions = has_devops_update()["latest_version"]
        update_deployment(versions)
        return util.success(versions)
