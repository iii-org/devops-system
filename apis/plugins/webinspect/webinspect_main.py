import json
from datetime import datetime, timedelta

from flask import make_response
from flask_jwt_extended import jwt_required
from flask_restful import Resource, reqparse
from sqlalchemy import desc
from flask_apispec import marshal_with, doc, use_kwargs

import model
import base64
import util
from model import db, WebInspect
from . import router_model

from resources import role
from resources import apiError
from resources.logger import logger
from plugins import get_plugin_config
from typing import Any, Union
import requests
from requests.cookies import RequestsCookieJar
from requests.models import Response


WIE_CONFIG = {}


def wie_get_config(key):
    global WIE_CONFIG
    if not WIE_CONFIG:
        WIE_CONFIG = {config["key"]: config for config in get_plugin_config("webinspect")["arguments"]}
    if key in WIE_CONFIG:
        return WIE_CONFIG[key]["value"]
    return None


class WIESCC:
    def __init__(self):
        self.url = wie_get_config("wi_scc_url")
        self.username = wie_get_config("wi-username")
        self.password = wie_get_config("wi-password")
        self.cookie_jar = RequestsCookieJar()
        self.auth_token = self.__generate_auth_token()
        self.scc_token = self.__generate_scc_token()
        self.headers = {"Authorization": self.scc_token, "Content-Type": "application/json"}

    def __generate_auth_token(self) -> str:
        login_pwd_str = f"{self.username}:{self.password}"
        b_login_pwd_str = base64.b64encode(login_pwd_str.encode("utf-8"))
        return b_login_pwd_str.decode("utf-8")

    def __generate_scc_token(self) -> str:
        ret = self.post(
            "/ssc/api/v1/tokens",
            headers={"Authorization": f"Basic {self.auth_token}", "Content-Type": "application/json"},
            data={
                "type": "UnifiedLoginToken",
                "terminalDate": self.__generate_expire_timestamp(),
                "description": "api",
            },
        )
        self.cookie_jar.update(ret.cookies)
        return ret.json()["data"]["token"]

    def __generate_expire_timestamp(self) -> str:
        current_timestamp = datetime.utcnow()
        current_timestamp += timedelta(hours=11)
        return current_timestamp.isoformat()

    def __api_request(
        self,
        method: str,
        path: str,
        headers: dict[str, Any] = {},
        params: dict[str, Any] = {},
        data: dict[str, Any] = {},
        cookie: Union[dict, RequestsCookieJar] = {},
    ):
        url = f"{self.url}{path}"
        if method == "GET":
            output = self.__api_get(path, headers, params, cookie)
        elif method == "POST":
            output = self.__api_post(path, headers, data, cookie)
        elif method == "PUT":
            output = self.__api_put(path, headers, data, cookie)
        elif method == "PATCH":
            output = self.__api_patch(path, headers, data, cookie)

        if int(output.status_code / 100) != 2:
            logger.exception(
                f"WebInspect api {method} {url}, header={str(headers)}, params={str(params)}, body={data},"
                f" response={output.status_code} {output.text}"
            )
            raise apiError.DevOpsError(
                output.status_code,
                "Got non-2xx response from WebInspect.",
                apiError.error_3rd_party_api("WebInspect", output),
            )
        return output

    def __api_get(
        self,
        path: str,
        headers: dict[str, Any] = {},
        params: dict[str, Any] = {},
        cookies: Union[dict, RequestsCookieJar] = {},
    ) -> Response:
        return requests.get(f"{self.url}{path}", headers=headers, params=params, verify=False, cookies=cookies)

    def __api_post(
        self,
        path: str,
        headers: dict[str, Any] = {},
        data: dict[str, Any] = {},
        cookies: Union[dict, RequestsCookieJar] = {},
    ) -> Response:
        data = json.dumps(data)
        res = requests.post(f"{self.url}{path}", headers=headers, data=data, verify=False, cookies=cookies)
        return res

    def __api_put(
        self,
        path: str,
        headers: dict[str, Any] = {},
        data: dict[str, Any] = {},
        cookies: Union[dict, RequestsCookieJar] = {},
    ) -> Response:
        data = json.dumps(data)
        res = requests.put(f"{self.url}{path}", headers=headers, data=data, verify=False, cookies=cookies)
        return res

    def __api_patch(
        self,
        path: str,
        headers: dict[str, Any] = {},
        data: dict[str, Any] = {},
        cookies: Union[dict, RequestsCookieJar] = {},
    ) -> Response:
        data = json.dumps(data)
        res = requests.patch(f"{self.url}{path}", headers=headers, data=data, verify=False, cookies=cookies)
        return res


# -------------- Regular methods --------------
"""
0 = Created
1 = Queued
2 = Pending
3 = Paused
4 = Running
5 = Complete
"""


def get_webinspect_query(scan_id: str) -> WebInspect:
    web_inspect_query = WebInspect.query.filter_by(scan_id=scan_id)
    if web_inspect_query.first() is None:
        raise apiError.DevOpsError(400, "Scan not found", apiError.resource_not_found())
    return web_inspect_query


def create_scan(args: dict[str, Any]) -> None:
    new = WebInspect(
        scan_id=args["scan_id"],
        project_name=args["project_name"],
        branch=args["branch"],
        commit_id=args["commit_id"],
        run_at=datetime.utcnow(),
        status="Created",
        finished=False,
    )
    db.session.add(new)
    db.session.commit()


def update_scan(scan_id: str, args: dict[str, Any]) -> None:
    args = {k: v for k, v in args.items() if v is not None}
    wie = get_webinspect_query(scan_id)
    wie.update(args)
    db.session.commit()


def list_scans(project_id: int, limit: int = 10, offset: int = 0) -> list[dict[str, Any]]:
    project_name = model.Project.query.filter_by(id=project_id).first().name
    return [
        json.loads(str(task))
        for task in WebInspect.query.filter_by(project_name=project_name)
        .order_by(desc(WebInspect.run_at))
        .limit(limit)
        .offset(offset)
        .all()
    ]


# --------------------- Resources ---------------------


class WebInspectPostScan(Resource):
    @doc(tags=["WebInspect"], description="Create WebInspect scan.")
    @use_kwargs(router_model.WIEScanPostSchema, location="json")
    @jwt_required()
    def post(self, **kwargs):
        return util.success(create_scan(kwargs))


class WebInspectListScan(Resource):
    @doc(tags=["WebInspect"], description="List project's WebInspect scans.")
    @use_kwargs(router_model.WIEScanGetSchema, location="query")
    @jwt_required()
    def get(self, project_id, **kwargs):
        role.require_in_project(project_id=project_id)
        return util.success(list_scans(project_id, kwargs.get("limit", 10), kwargs.get("offset", 0)))


class WebInspectScan(Resource):
    @doc(tags=["WebInspect"], description="Update specific WebInspect scan.")
    @use_kwargs(router_model.WIEScanUpdateSchema, location="json")
    @jwt_required()
    def patch(self, s_id, **kwargs):
        return util.success(update_scan(s_id, kwargs))
