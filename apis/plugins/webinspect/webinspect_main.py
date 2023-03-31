import json
from datetime import datetime, timedelta

from flask_jwt_extended import jwt_required
from flask_restful import Resource, reqparse
from sqlalchemy import desc
from flask_apispec import marshal_with, doc, use_kwargs
import base64

import model
import util
from model import db, WebInspect
from . import router_model

from resources import role
from resources import apiError
from resources.logger import logger
from plugins import get_plugin_config
from typing import Any, Union
import requests
from requests.models import Response
from requests.cookies import RequestsCookieJar


WIE_CONFIG = {}
# wiescc_obj = None


def wie_get_config(key):
    global WIE_CONFIG
    if not WIE_CONFIG:
        WIE_CONFIG = {config["key"]: config for config in get_plugin_config("webinspect")["arguments"]}
    if key in WIE_CONFIG:
        return WIE_CONFIG[key]["value"]
    return None


class Request:
    def api_request(
        self,
        method: str,
        path: str,
        headers: dict[str, Any] = {},
        params: dict[str, Any] = {},
        data: dict[str, Any] = {},
        cookies: Union[dict, RequestsCookieJar] = {},
    ):
        url = f"{self.url}{path}"
        if method == "GET":
            output = self.__api_get(path, headers, params, cookies=cookies)
        elif method == "POST":
            output = self.__api_post(path, headers, data, cookies=cookies)
        elif method == "PUT":
            output = self.__api_put(path, headers, data, cookies=cookies)
        elif method == "PATCH":
            output = self.__api_patch(path, headers, data, cookies=cookies)

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


class WebinspectScc(Request):
    def __init__(self):
        self.url = wie_get_config("wi_scc_url")
        self.cookie_jar = RequestsCookieJar()
        self.auth_token = self.__generate_auth_token()
        self.scc_token = self.__generate_scc_token()
        self.headers = {
            "Authorization": self.scc_token,
            "Content-Type": "application/json",
        }

    def __generate_auth_token(self) -> str:
        login_pwd_str = f'{wie_get_config("wi-username")}:{wie_get_config("wi-password")}'
        b_login_pwd_str = base64.b64encode(login_pwd_str.encode("utf-8"))
        return b_login_pwd_str.decode("utf-8")

    def __generate_scc_token(self) -> str:
        ret = self.post(
            "/ssc/api/v1/tokens",
            headers={
                "Authorization": f"Basic {self.auth_token}",
                "Content-Type": "application/json",
            },
            data={
                "type": "UnifiedLoginToken",
                "terminalDate": self.__generate_expire_timestamp(),
                "description": "",
            },
        )
        self.cookie_jar.update(ret.cookies)
        return ret.json()["data"]["token"]

    def __generate_expire_timestamp(self) -> str:
        current_timestamp = datetime.utcnow()
        current_timestamp += timedelta(hours=11)
        return current_timestamp.isoformat()

    # def


class WIEDAST(Request):
    def __init__(self):
        self.url = wie_get_config("wi_dast_url")
        self.token = self.__generate_token()
        self.headers = {"Authorization": self.token, "Content-Type": "application/json"}

    def __generate_token(self) -> str:
        ret = self.__api_request(
            "POST",
            "/api/v2/auth",
            headers={"Content-Type": "application/json"},
            data={"username": wie_get_config("wi-username"), "password": wie_get_config("wi-password")},
        )
        return ret.json()["token"]

    def get_scan_summary(self, scan_id: str) -> dict[str, Any]:
        ret = self.__api_request(
            method="GET", path=f"/api/v2/scans/{int(scan_id)}/scan-summary", headers=self.headers
        ).json()
        return ret

    def publish_scan_report(self, scan_id: str) -> dict[str, Any]:
        ret = self.__api_request(
            method="POST",
            path=f"/api/v2/scans/{int(scan_id)}/scan-action",
            headers=self.headers,
            data={"ScanActionType": 5},
        ).json()
        return ret


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


def get_scan_summary(scan_id: str):
    wie_scc = WIEDAST()
    ret = wie_scc.get_scan_summary(scan_id)

    scan_info = {
        "id": scan_id,
        "state": {
            "critical": ret["criticalCount"],
            "high": ret["highCount"],
            "medium": ret["mediumCount"],
            "low": ret["lowCount"],
        },
        "status": ret["scanStatusTypeDescription"],
        "publish_status": ret["publishStatusTypeDescription"],
    }

    wie = get_webinspect_query(scan_id=scan_id).first()
    if wie.finished:
        return json.loads(str(wie))

    if scan_info["status"] == "Complete":
        if scan_info["publish_status"] == "Published":
            wie.finished = True
            wie.finished_at = datetime.utcnow()
            db.session.commit()
        elif scan_info["publish_status"] == "NotPublished":
            wie_scc.publish_scan_report(scan_id)
        return json.loads(str(wie))

    else:
        needed_update_info = {"state": scan_info["state"], "status": scan_info["status"]}
        if {"state": wie.state, "status": wie.status} != needed_update_info:
            update_scan(needed_update_info)

    ret = json.loads(str(get_webinspect_query(scan_id=scan_id).first()))
    return ret


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
    @doc(tags=["WebInspect"], description="Get WebInspect scan summary.")
    # @use_kwargs(router_model.WIEScanUpdateSchema, location="json")
    @jwt_required()
    def get(self, s_id):
        return util.success(get_scan_summary(s_id))

    @doc(tags=["WebInspect"], description="Update specific WebInspect scan.")
    @use_kwargs(router_model.WIEScanUpdateSchema, location="json")
    @jwt_required()
    def patch(self, s_id, **kwargs):
        return util.success(update_scan(s_id, kwargs))
