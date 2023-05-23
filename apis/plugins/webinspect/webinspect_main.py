import json
from datetime import datetime, timedelta
from time import sleep
from pathlib import Path

from resources.handler.jwt import jwt_required
from flask_restful import Resource
from sqlalchemy import desc
from flask_apispec import doc, use_kwargs
import base64
import os
from flask import send_file

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
import threading


WIE_CONFIG = {}
WIE_REPORT_PATH = "./logs/wie_report"
WIE_DAST_TOKEN = ""

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
        elif method == "DELETE":
            output = self.__api_delete(path, headers, data, cookies=cookies)

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

    def __api_delete(
        self,
        path: str,
        headers: dict[str, Any] = {},
        data: dict[str, Any] = {},
        cookies: Union[dict, RequestsCookieJar] = {},
    ) -> Response:
        data = json.dumps(data)
        res = requests.delete(f"{self.url}{path}", headers=headers, data=data, verify=False, cookies=cookies)
        return res


class WIESCC(Request):
    def __init__(self):
        self.url = wie_get_config("WIE_SCC_URL")
        self.cookie_jar = RequestsCookieJar()
        self.auth_token = self.__generate_auth_token()
        self.scc_token = self.__generate_scc_token()
        self.headers = {
            "Authorization": self.scc_token,
            "Content-Type": "application/json",
        }

    def __generate_auth_token(self) -> str:
        login_pwd_str = f'{wie_get_config("WIE_USERNAME")}:{wie_get_config("WIE_PASSWORD")}'
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
        if it needs fuzzy search, use * e.q. name:"*test*"
        """
        if project_name:
            params = {"q": f'name:"{project_name}"'}
        ret = self.api_request(
            "GET", "/ssc/api/v1/projects", headers=self.headers, params=params, cookies=self.cookie_jar
        ).json()
        return ret

    def wie_get_version_info(self, project_id: int, version_name: str = ""):
        """
        if it needs fuzzy search, use * e.q. name:"*test*"
        """
        if version_name:
            params = {"q": f'name:"{version_name}"'}
        ret = self.api_request(
            "GET",
            f"/ssc/api/v1/projects/{project_id}/versions",
            headers=self.headers,
            params=params,
            cookies=self.cookie_jar,
        ).json()
        return ret

    def wie_create_report(self, report_name: str, project_info: dict[str, Any]):
        datas = scc_report_data_generator(report_name, project_info)
        ret = self.api_request(
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
        ret = self.api_request(
            "POST", "/ssc/api/v1/fileTokens", headers=self.headers, data={"fileTokenType": "3"}, cookies=self.cookie_jar
        )
        return ret.json().get("data", {})

    def wie_get_report(self, report_id: int, token: str) -> str:
        params = {"mat": token, "id": report_id}
        ret = self.api_request(
            "GET", "/ssc/transfer/reportDownload.html", headers=self.headers, params=params, cookies=self.cookie_jar
        )
        return ret.content

    def wie_remove_report(self, report_id: int) -> None:
        return self.api_request(
            "DELETE", f"/ssc/api/v1/reports/{report_id}", headers=self.headers, cookies=self.cookie_jar
        )

    def wie_get_report_status(self, report_id: int) -> dict[str, Any]:
        """
        response: status: [SCHED_PROCESSING, PROCESSING, PROCESS_COMPLETE, ERROR_PROCESSING]
        """
        ret = self.api_request(
            "GET", f"/ssc/api/v1/reports/{report_id}", headers=self.headers, cookies=self.cookie_jar
        ).json()
        return ret

    def get_report_content(self, report_id: int) -> None:
        report_token = self.wie_get_report_token()["token"]
        ret = self.wie_get_report(report_id, report_token)
        return ret

    def delete_report_if_exist(self, report_id: int) -> None:
        try:
            if self.wie_get_report_status(report_id):
                self.wie_remove_report(report_id)
        except Exception as e:
            logger.info("Fail to delete report_id {report_id}, error_msg: {e}")
            return


class WIEDAST(Request):
    def __init__(self):
        self.url = wie_get_config("WIE_DAST_URL")
        self.__check_dast_token()

    def __check_dast_token(self):
        global WIE_DAST_TOKEN
        if not WIE_DAST_TOKEN:
            WIE_DAST_TOKEN = self.__generate_token()
            self.headers = {"Authorization": WIE_DAST_TOKEN, "Content-Type": "application/json"}
            return

        self.headers = {"Authorization": WIE_DAST_TOKEN, "Content-Type": "application/json"}
        is_valid = self.wie_check_auth_token()
        if not is_valid:
            WIE_DAST_TOKEN = self.__generate_token()
            self.headers = {"Authorization": WIE_DAST_TOKEN, "Content-Type": "application/json"}
            return

    def __generate_token(self) -> str:
        ret = self.api_request(
            "POST",
            "/api/v2/auth",
            headers={"Content-Type": "application/json"},
            data={"username": wie_get_config("WIE_USERNAME"), "password": wie_get_config("WIE_PASSWORD")},
        )
        return ret.json()["token"]

    def wie_check_auth_token(self):
        ret = self.api_request(method="GET", path="/api/v2/auth/check", headers=self.headers)
        return int(ret.status_code / 100) == 2

    def wie_get_scan_summary(self, scan_id: str) -> dict[str, Any]:
        ret = self.api_request(
            method="GET", path=f"/api/v2/scans/{int(scan_id)}/scan-summary", headers=self.headers
        ).json()
        return ret

    def wie_scan_action(self, scan_id: str, scan_action_type: int) -> dict[str, Any]:
        """
        param: scan_action_type
        1 = PauseScan / 2 = ResumeScan / 3 = DeleteScan / 4 = ClearTrackedScan
        5 = RetryImportScanResults / 6 = CompleteScan / 7 = RetryImportScanFinding
        """
        ret = self.api_request(
            method="POST",
            path=f"/api/v2/scans/{scan_id}/scan-action",
            headers=self.headers,
            data={"ScanActionType": scan_action_type},
        )
        return ret

    def wie_publish_scan_report(self, scan_id: str) -> dict[str, Any]:
        return self.wie_scan_action(scan_id, 5)

    def wie_resume_scan_from_interrupted(self, scan_id: str) -> dict[str, Any]:
        return self.wie_scan_action(scan_id, 2)


# -------------- Regular methods --------------
"""
status
- Failed
- Created
- Queued
- Pending
- Paused
- Running
- Interrupted
- ResumeScanQueued
- Complete


report_status
- Started
- Error Publishing Scan
- Generating Report
- Error Generating Report
- Finished
"""


def get_webinspect_query(scan_id: str) -> WebInspect:
    web_inspect_query = WebInspect.query.filter_by(scan_id=scan_id)
    if web_inspect_query.first() is None:
        raise apiError.DevOpsError(400, "Scan not found", apiError.resource_not_found())
    return web_inspect_query


"""
def get_scan_by_commit(project_id: int, commit_id: str):
    project_name = model.Project.query.filter_by(id=project_id).first().name
    scan = WebInspect.query.filter_by(project_name=project_name, commit_id=commit_id).first()

    if scan.status != "Complete":
"""


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


def get_latest_scan_by_project_name_and_update(project_id: int) -> dict[str, Any]:
    scans = list_scans(project_id, limit=1)
    if not scans:
        return {}
    scan_id = scans[0]["scan_id"]
    update_scan_summary(scan_id)

    return WebInspect.query.filter_by(scan_id=scan_id).first().dict()


def get_scan_by_commit_and_update(project_id: int, commit_id: str) -> dict[str, Any]:
    project_name = model.Project.query.filter_by(id=project_id).first().name
    scan = WebInspect.query.filter_by(project_name=project_name, commit_id=commit_id).first()
    if scan is None:
        return {}
    scan_id = scan.scan_id
    update_scan_summary(scan_id)
    return WebInspect.query.filter_by(scan_id=scan_id).first().dict()


def list_scans(project_id: int, limit: int = 10, offset: int = 0) -> list[dict[str, Any]]:
    project_name = model.Project.query.filter_by(id=project_id).first().name
    return [
        task.dict()
        for task in WebInspect.query.filter_by(project_name=project_name)
        .order_by(desc(WebInspect.run_at))
        .limit(limit)
        .offset(offset)
        .all()
    ]


def __is_named_threading_is_running(name):
    for th in threading.enumerate():
        if th.name == name:
            return True
    return False


def get_project_scans_and_update_status(project_id: int, limit: int = 10, offset: int = 0, force_update: bool = False):
    """
    Only need to generate the five latest scan's report.
    param: offset: multiples of 5
    param: limit: multiples of 10
    """
    project_name = model.Project.query.filter_by(id=project_id).first().name
    if offset <= 5:
        a_limit, a_offset = limit - 5, 5
        need_generate_report = True
    else:
        a_limit, a_offset = limit, offset
        need_generate_report = False
    for scan in (
        WebInspect.query.filter_by(project_name=project_name)
        .order_by(desc(WebInspect.run_at))
        .limit(a_limit)
        .offset(a_offset)
        .all()
    ):
        update_scan_summary(scan.scan_id)
        if scan.report_status is not None:
            scan.report_status = None
            db.session.commit()
    if need_generate_report:
        # Use project_name as thread name.
        # if is not force_update, it won't not run another same name threading.
        is_running = __is_named_threading_is_running(project_name)
        if force_update or not is_running:
            threading.Thread(
                name=project_name,
                target=generate_project_scan_reports,
                args=(project_name,),
            ).start()

    return list_scans(project_id, limit, offset)


def generate_project_scan_reports(project_name: str):
    scans = (
        WebInspect.query.filter_by(project_name=project_name).order_by(desc(WebInspect.run_at)).limit(5).offset(0).all()
    )
    for scan in scans[::-1]:
        generate_report(scan.scan_id)


def get_scan_summary(scan_id: str):
    wie_dast = WIEDAST()
    ret = wie_dast.wie_get_scan_summary(scan_id)["item"]
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


def update_scan_summary(scan_id: str):
    wie = get_webinspect_query(scan_id=scan_id).first()
    if wie.finished or wie.status in ["Complete", "Failed"]:
        return

    wie_scan_info = get_scan_summary(scan_id)
    current_scan_status = wie_scan_info["status"]
    needed_update_info = {"state": wie_scan_info["state"], "status": current_scan_status}

    # Sometime scan would be interrupted, need to resume it.
    if current_scan_status == "Interrupted":
        WIEDAST().wie_resume_scan_from_interrupted(scan_id)

    if {"state": wie.state, "status": wie.status} != needed_update_info:
        update_scan(scan_id, needed_update_info)


def generate_report(scan_id: str):
    logger.info(f"Start generating wie report of scan_id: {scan_id}.")
    wie = get_webinspect_query(scan_id=scan_id).first()
    if wie.finished or wie.report_status in ["Error Publishing Scan", "Error Generating Report", "Finished"]:
        logger.info(f"Stop generating report due to scan_id: {scan_id} is finished or report_status is error")
        return
    if wie.status != "Complete":
        logger.info(f"Stop generating report due to scan_id: {scan_id} is scaning.")
        update_scan_summary(scan_id)
        return

    wie_scc = WIESCC()
    if wie.report_status != "Generating Report":
        wie_dast = WIEDAST()
        wie_scan_info = get_scan_summary(scan_id)
        if wie_scan_info["publish_status"] == "NotPublished":
            wie_dast.wie_publish_scan_report(scan_id)
            is_pulbich = __check_scan_is_publish(scan_id)
            if not is_pulbich:
                update_scan(scan_id, {"report_status": "Error Publishing Scan"})
                logger.info(f"Stop generating report due to scan_id: {scan_id} error to publish.")
                return
        print(wie.project_name, wie.branch, wie.commit_id)
        report_id = wie_scc.create_report(wie.project_name, wie.branch, wie.commit_id)
        update_scan(scan_id, {"report_id": report_id, "report_status": "Generating Report"})
        logger.info(f"Generating report of scan: {scan_id}.")
        handle_download_store_report(scan_id, report_id, wie_scc, wie)
    else:
        report_id = wie.report_id
        handle_download_store_report(scan_id, report_id, wie_scc, wie)


def __check_scan_is_publish(scan_id):
    num, is_published = 0, False
    while num < 15:
        wie_scan_info = get_scan_summary(scan_id)
        if wie_scan_info["publish_status"] == "Published":
            is_published = True
            break
        sleep(2)
    return is_published


def handle_download_store_report(
    scan_id: str,
    report_id: int,
    wie_scc: WIESCC,
    wie_query: WebInspect,
):
    is_finished = __check_scan_report_is_finished(wie_scc, report_id)
    if not is_finished:
        update_scan(scan_id, {"status": "Error Generating Report", "finished": True})
        logger.info(f"Stop generating report due to scan_id: {scan_id} error to generate.")
        return
    else:
        report_content = wie_scc.get_report_content(report_id)
    __store_report_in_local(wie_query, wie_scc, report_content)
    update_scan(scan_id, {"report_status": "Finished", "finished": True, "finished_at": datetime.utcnow()})
    logger.info(f"Scan_id: {scan_id}'s report is ready to download.")


def __check_scan_report_is_finished(wie_scc: WIESCC, report_id: int):
    # [ SCHED_PROCESSING, PROCESSING, PROCESS_COMPLETE, ERROR_PROCESSING ]
    num, is_finished = 0, False
    while num < 15:
        status = wie_scc.wie_get_report_status(report_id).get("data", {}).get("status", "ERROR_PROCESSING")
        if status == "ERROR_PROCESSING":
            break
        elif status == "PROCESS_COMPLETE":
            is_finished = True
            break
        else:
            sleep(2)
    return is_finished


def __store_report_in_local(wie_query: WebInspect, wie_scc: WIESCC, report_content: str):
    scan_commit, scan_pj_name = wie_query.commit_id, wie_query.project_name
    wie_pj_path = f"{WIE_REPORT_PATH}/{scan_pj_name}"

    if not os.path.isdir(wie_pj_path):
        os.makedirs(wie_pj_path, exist_ok=True)
    else:
        __remove_older_than_four_wie_report(wie_scc, wie_pj_path)
    file_name = Path(f"{wie_pj_path}/{scan_commit}.pdf")
    file_name.write_bytes(report_content)


def __remove_older_than_four_wie_report(wie_scc: WIESCC, wie_pj_path: str):
    """
    - Keep only five reports, which means you should retain only four old reports since one of them is for the new report.
    - Delete report in WIE server as the same time.
    """
    files = sorted(Path(wie_pj_path).iterdir(), key=os.path.getmtime)
    if len(files) >= 4:
        for file in files[:-4]:
            file.unlink()
            query = WebInspect.query.filter_by(
                project_name=wie_pj_path.split("/")[-1], commit_id=file.name.split(".")[0]
            )
            if query.first() is not None:
                report_id = query.first().report_id
                query.update({"report_status": None})
                db.session.commit()
                wie_scc.delete_report_if_exist(report_id)


def donwload_pdf(scan_id: str):
    wie = get_webinspect_query(scan_id).first()
    pj_name, commit_id = wie.project_name, wie.commit_id
    file_path = f"{WIE_REPORT_PATH}/{pj_name}/{commit_id}.pdf"
    if not os.path.isfile(file_path):
        raise apiError.DevOpsError(400, "File not found", apiError.file_not_found(f"{commit_id}.pdf", file_path))
    return send_file(
        f".{file_path}",
        attachment_filename="report.pdf",
        mimetype="application/pdf",
    )


# ------------------------------------------------------ Runner API ----------------------------------------------------------
class WebInspectPostScan(Resource):
    @doc(tags=["WebInspect"], description="Create WebInspect scan.")
    @use_kwargs(router_model.WIEScanPostSchema, location="json")
    @jwt_required
    def post(self, **kwargs):
        return util.success(create_scan(kwargs))


class WebInspectScan(Resource):
    @doc(tags=["WebInspect"], description="Update specific WebInspect scan.")
    @use_kwargs(router_model.WIEScanUpdateSchema, location="json")
    @jwt_required
    def patch(self, s_id, **kwargs):
        return util.success(update_scan(s_id, kwargs))

    # ------------------------------------------------------ III API ----------------------------------------------------------


class WebInspectListScan(Resource):
    @doc(tags=["WebInspect"], description="List project's WebInspect scans.")
    @use_kwargs(router_model.WIEScanGetSchema, location="query")
    @jwt_required
    def get(self, project_id, **kwargs):
        role.require_in_project(project_id=project_id)
        return util.success(
            get_project_scans_and_update_status(
                project_id, kwargs.get("limit", 10), kwargs.get("offset", 0), kwargs.get("force_update", False)
            )
        )


class WebInspectDownloadReport(Resource):
    @doc(tags=["WebInspect"], description="List project's WebInspect scans.")
    @use_kwargs(router_model.WebInspectDownloadReportSchema, location="query")
    @jwt_required
    def get(self, project_id, **kwargs):
        role.require_in_project(project_id=project_id)
        return donwload_pdf(kwargs["scan_id"])
