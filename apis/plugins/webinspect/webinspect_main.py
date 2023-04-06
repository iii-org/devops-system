import json
from datetime import datetime, timedelta

from flask_jwt_extended import jwt_required
from flask_restful import Resource, reqparse
from sqlalchemy import desc
from flask_apispec import doc, use_kwargs
import base64
import os
from pathlib import Path

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
WIE_REPORT_PATH = "./logs/wie_report"

scc_report_data_generator = lambda report_name, project_info: {
    "name": report_name,
    "note": "",
    "format": "PDF",
    "inputReportParameters": [
        {
            "name": "Application Version",
            "identifier": "projectversionid",
            "paramValue": project_info["id"],
            "type": "SINGLE_PROJECT",
        },
        {"name": "Include OWASP Top Ten 2021", "identifier": "includeOWASP2021", "paramValue": True, "type": "BOOLEAN"},
        {"name": "Include PCI DSS 3.2.1", "identifier": "includePCI321", "paramValue": True, "type": "BOOLEAN"},
        {"name": "Include PCI SSF 1.0", "identifier": "includePCISSF10", "paramValue": True, "type": "BOOLEAN"},
        {"name": "Include CWE", "identifier": "includeCWE", "paramValue": True, "type": "BOOLEAN"},
        {"name": "Include WASC 2.00", "identifier": "includeWASC2", "paramValue": True, "type": "BOOLEAN"},
        {"name": "Include DISA STIG 5.1", "identifier": "includeSTIG51", "paramValue": True, "type": "BOOLEAN"},
        {"name": "Include Appendix A", "identifier": "includeAppendixA", "paramValue": True, "type": "BOOLEAN"},
        {"name": "Include Appendix B", "identifier": "includeAppendixB", "paramValue": True, "type": "BOOLEAN"},
        {"name": "Include Appendix C", "identifier": "includeAppendixC", "paramValue": True, "type": "BOOLEAN"},
        {"name": "Include Appendix D", "identifier": "includeAppendixD", "paramValue": True, "type": "BOOLEAN"},
        {"name": "Include Appendix E", "identifier": "includeAppendixE", "paramValue": True, "type": "BOOLEAN"},
        {"name": "Include Appendix F", "identifier": "includeAppendixF", "paramValue": True, "type": "BOOLEAN"},
    ],
    "reportDefinitionId": 1,
    "type": "PROJECT",
    "project": project_info,
}


def wie_get_config(key):
    global WIE_CONFIG
    if not WIE_CONFIG:
        WIE_CONFIG = {config["key"]: config for config in get_plugin_config("webinspect")["arguments"]}
    if key in WIE_CONFIG:
        return WIE_CONFIG[key]["value"]
    return None


class Request:
    def __api_request(
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
        ret = self.api_request(
            "POST",
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

    def wie_get_project_info(self, project_name: str = ""):
        """
        if it needs fuzzy search, use * e.q. name="*test*"
        """
        if project_name:
            params = {"q": f'name="{project_name}"'}
        ret = self.__api_request(
            "POST", "/ssc/api/v1/projects", headers=self.headers, params=params, cookies=self.cookie_jar
        ).json()
        return ret

    def wie_get_version_info(self, project_id: int, version_name: str = ""):
        """
        if it needs fuzzy search, use * e.q. name="*test*"
        """
        if version_name:
            params = {"q": f'name="{version_name}"'}
        ret = self.__api_request(
            "POST",
            f"/ssc/api/v1/projects/{project_id}/versions",
            headers=self.headers,
            params=params,
            cookies=self.cookie_jar,
        ).json()
        return ret

    def wie_create_report(self, report_name: str, project_info: dict[str, Any]):
        datas = scc_report_data_generator(report_name, project_info)
        ret = self.__api_request(
            "POST",
            "/ssc/api/v1/reports",
            headers=self.headers,
            data=datas,
            cookies=self.cookie_jar,
        ).json()
        return ret

    def create_report(self, project_name: str, version_name: str, commit_id: str) -> int:
        project_infos = self.wie_get_project_info(project_name)["data"]
        if not project_infos:
            raise apiError.DevOpsError(
                404,
                f"Application: {project_name} not found.",
                error=apiError.wie_project_not_exist(project_name),
            )
        version_infos = self.wie_get_version_info(project_infos[0]["id"], version_name)["data"]
        if not version_infos:
            raise apiError.DevOpsError(
                404,
                f"Project version: {version_name} not found.",
                error=apiError.wie_project_version_not_exist(version_name),
            )
        project_info = {
            "id": version_infos[0]["id"],
            "name": version_infos[0]["name"],
            "version": {
                "id": version_infos[0]["project"]["id"],
                "name": version_infos[0]["project"]["name"],
            },
        }
        ret = self.wie_create_report(f"{project_name}-{version_name}-{commit_id}", project_info)

        return ret["data"]["id"]

    def wie_get_report_token(self) -> dict[str, str]:
        ret = self.__api_request(
            "POST", "/ssc/api/v1/fileTokens", headers=self.headers, data={"fileTokenType": "3"}, cookies=self.cookie_jar
        )
        return ret.json().get("data", {})

    def wie_get_report(self, report_id: int, token: str) -> None:
        params = {"mat": token, "id": report_id}
        ret = self.__api_request(
            "GET",
            "/ssc/transfer/reportDownload.html",
            headers=self.headers,
            params=params,
        )

    def wie_get_report_status(self, report_id: int) -> dict[str, Any]:
        ret = self.__api_request(
            "GET",
            f"/ssc/api/v1/reports/{report_id}",
            headers=self.headers,
        ).json()
        return ret

    # def get_report(self, project_name: int):
    #     # create report

    #     # get report by id and token
    #     report_token = self.wie_get_report_token()["token"]
    #     self.wie_get_report(report_id, report_token)


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

    def wie_get_scan_summary(self, scan_id: str) -> dict[str, Any]:
        ret = self.__api_request(
            method="GET", path=f"/api/v2/scans/{int(scan_id)}/scan-summary", headers=self.headers
        ).json()
        return ret

    def wie_publish_scan_report(self, scan_id: str) -> dict[str, Any]:
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
6 = Generating Report
7 = Finished
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
    wie_dast = WIEDAST()
    ret = wie_dast.wie_get_scan_summary(scan_id)

    return {
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


"""
0 = Created
1 = Queued
2 = Pending
3 = Paused
4 = Running
5 = Complete
6 = Generating Report
7 = Finished
"""


def update_scan_summary(scan_id: str):
    wie = get_webinspect_query(scan_id=scan_id).first()
    if wie.finished:
        return

    if wie.status not in ["Complete", "Generating Report", "Finished"]:
        wie_scan_info = get_scan_summary(scan_id)
        needed_update_info = {"state": wie_scan_info["state"], "status": wie_scan_info["status"]}
        if {"state": wie.state, "status": wie.status} != needed_update_info:
            update_scan(needed_update_info)


def generate_report(scan_id: str):
    """
    !! here1: Get report status, to check report is ready or not
    !! here2: Get report status, to check report is ready or not
    """
    wie = get_webinspect_query(scan_id=scan_id).first()
    if wie.finished:
        return
    if wie.status not in ["Complete", "Generating Report", "Finished"]:
        update_scan_summary(scan_id)
        return
    elif wie.status == "Complete":
        wie_scan_info = get_scan_summary(scan_id)
        # !! handle Fail to publish error !!
        if wie_scan_info["publish_status"] == "NotPublished":
            wie_dast = WIEDAST()
            wie_dast.wie_publish_scan_report(scan_id)
        wie_scc = WebinspectScc()
        report_id = wie_scc.create_report(wie.project_name, wie.version_name, wie.commit_id)
        update_scan({"report_id": report_id, "status": "Generating Report"})
        # here1
        wie_scc.wie_get_report_status(report_id)
    elif wie.status == "Generating Report":
        # here2
        pass


def __remove_older_than_four_wie_report(wie_pj_path: str):
    """
    Keep only five reports, which means you should retain only four old reports since one of them is for the new report
    """
    files = sorted(Path(wie_pj_path).iterdir(), key=os.path.getmtime)
    if len(files) >= 4:
        for file in files[:-4]:
            file.unlink()


def get_report(scan_id: str):
    """
    !! Remove extra project report, when get scan_id.
    """
    wie = get_webinspect_query(scan_id).first()
    scan_commit, scan_pj_name = wie.commit_id, wie.project_name
    wie_pj_path = f"{WIE_REPORT_PATH}/{scan_pj_name}"

    if not os.path.isdir(wie_pj_path):
        os.makedirs(wie_pj_path, exist_ok=True)
    else:
        __remove_older_than_four_wie_report(wie_pj_path)


# --------------------- Resources ---------------------

# ------------------------------------------------------ Runner API ----------------------------------------------------------
class WebInspectPostScan(Resource):
    @doc(tags=["WebInspect"], description="Create WebInspect scan.")
    @use_kwargs(router_model.WIEScanPostSchema, location="json")
    @jwt_required()
    def post(self, **kwargs):
        return util.success(create_scan(kwargs))


class WebInspectScan(Resource):
    @doc(tags=["WebInspect"], description="Update specific WebInspect scan.")
    @use_kwargs(router_model.WIEScanUpdateSchema, location="json")
    @jwt_required()
    def patch(self, s_id, **kwargs):
        return util.success(update_scan(s_id, kwargs))

    # ------------------------------------------------------ III API ----------------------------------------------------------

    # @doc(tags=["WebInspect"], description="Get WebInspect scan summary.")
    # # @use_kwargs(router_model.WIEScanUpdateSchema, location="json")
    # @jwt_required()
    # def get(self, s_id):
    #     return util.success(get_scan_summary(s_id))


class WebInspectListScan(Resource):
    @doc(tags=["WebInspect"], description="List project's WebInspect scans.")
    @use_kwargs(router_model.WIEScanGetSchema, location="query")
    @jwt_required()
    def get(self, project_id, **kwargs):
        role.require_in_project(project_id=project_id)
        return util.success(list_scans(project_id, kwargs.get("limit", 10), kwargs.get("offset", 0)))
