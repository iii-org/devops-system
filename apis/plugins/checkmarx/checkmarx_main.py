import datetime
import json
import time
from io import BytesIO

import requests
from flask import send_file
from flask_jwt_extended import jwt_required
from flask_restful import Resource, reqparse
from sqlalchemy import desc, or_, func
from sqlalchemy.exc import NoResultFound

import nexus
import util
from model import Checkmarx as Model
from model import db
from plugins import get_plugin_config
from resources import apiError, gitlab
from resources.apiError import DevOpsError
from datetime import date
from resources import logger
import pandas as pd


def cm_get_config(key):
    for arg in get_plugin_config("checkmarx")["arguments"]:
        if arg["key"] == key:
            return arg["value"]
    return None


def build_url(path):
    return f'{cm_get_config("cm-url")}{path}'


class CheckMarx(object):
    def __init__(self):
        self.access_token = None
        self.expire_at = 0

    def token(self):
        if time.time() > self.expire_at:
            self.login()
        return self.access_token

    def login(self):
        url = build_url("/auth/identity/connect/token")
        data = {
            "userName": cm_get_config("username"),
            "password": cm_get_config("password"),
            "grant_type": "password",
            "scope": "sast_rest_api",
            "client_id": "resource_owner_client",
            "client_secret": cm_get_config("client-secret"),
        }
        self.access_token = requests.post(url, data).json().get("access_token")
        self.expire_at = time.time() + 1800  # 0.5 hour

    def __api_request(self, method, path, headers=None, data=None):
        if data is None:
            data = {}
        if headers is None:
            headers = {}
        url = build_url(path)
        headers["Authorization"] = "Bearer " + self.token()
        if method.upper() == "GET":
            res = requests.get(url, headers=headers, allow_redirects=True)
        elif method.upper() == "POST":
            res = requests.post(url, headers=headers, data=data, allow_redirects=True)
        else:
            raise DevOpsError(
                500,
                "Only GET and POST is allowed.",
                error=apiError.invalid_code_path("Only GET and POST is allowed, but" "{0} provided.".format(method)),
            )
        if int(res.status_code / 100) != 2:
            raise apiError.DevOpsError(
                res.status_code,
                "Got non-2xx response from Checkmarx.",
                apiError.error_3rd_party_api("Checkmarx", self.__handle_error_message(res)),
            )
        return res

    def __handle_error_message(self, res):
        if type(res) is str:
            return res
        else:
            try:
                res = res.json()
            except Exception:
                res = res.text

        if type(res) is dict and res.get("messageDetails") is not None:
            return res["messageDetails"]

    def __api_get(self, path, headers=None):
        return self.__api_request("GET", path, headers=headers)

    def __api_post(self, path, data=None, headers=None):
        if data is None:
            data = {}
        if headers is None:
            headers = {}
        url = build_url(path)
        headers["Authorization"] = "Bearer " + self.token()
        res = requests.post(url, headers=headers, data=data, allow_redirects=True)
        return res

    def __api_patch(self, path, data=None, headers=None):
        if data is None:
            data = {}
        if headers is None:
            headers = {}
        url = build_url(path)
        headers["Authorization"] = "Bearer " + self.token()
        res = requests.patch(url, headers=headers, data=data, allow_redirects=True)
        return res

    @staticmethod
    def create_scan(args):
        checkamrx_keep_report(args["repo_id"], 4)
        new = Model(
            cm_project_id=args["cm_project_id"],
            repo_id=args["repo_id"],
            scan_id=args["scan_id"],
            branch=args["branch"],
            commit_id=args["commit_id"],
            scan_final_status=None,
            run_at=datetime.datetime.utcnow(),
        )
        db.session.add(new)
        db.session.commit()
        # # if Model.query.filter_by(repo_id=args["repo_id"]).order_by(desc(Model.run_at)).count() > 5:
        # update_row = (
        #     Model.query.filter_by(repo_id=args["repo_id"])
        #     .filter(Model.report_id != -1
        #
        #     .order_by(Model.run_at)
        #     .first()
        # )
        # if update_row:
        #     update_row.report_id = -1
        #     if update_row.finished is None:
        #         update_row.finished = True
        #         if update_row.finished_at is None:
        #             update_row.scan_final_status = "Canceled"
        #     if update_row.scan_final_status is None:
        #         update_row.scan_final_status = "Deleted"
        #     if update_row.scan_final_status == "Scanning" or update_row.scan_final_status == "Queued":
        #         update_row.scan_final_status = "Canceled"
        #     db.session.commit()
        #     logger.logger.info(f'[scan_id: {update_row.scan_id}] ' +
        #                        f'[report_id: {update_row.report_id}] ' +
        #                        f'[scan_final_status: {update_row.scan_final_status}]')
        return util.success()

    # Need to write into db if see a final scan status
    def get_scan_status(self, scan_id, save2db=True):
        try:
            status = self.__api_get("/sast/scans/{0}".format(scan_id)).json().get("status")
        except Exception as e:
            error_mes = None
            # if e.status_code == 404 and hasattr(e, "error_value"):
            if e.status_code == 404:
                scan = Model.query.filter_by(scan_id=scan_id).one()
                scan.scan_final_status = "Deleted"
                if hasattr(e, "error_value"):
                    error_mes = e.error_value.get("message")

            error_mes = error_mes if error_mes is not None else str(e)
            raise apiError.DevOpsError(
                e.status_code,
                "Got non-2xx response from Checkmarx.",
                apiError.error_3rd_party_api("Checkmarx", error_mes),
            )

        status_id = status.get("id")
        status_name = status.get("name")
        if save2db:
            if status_id in {7, 8, 9}:
                scan = Model.query.filter_by(scan_id=scan_id).one()
                if status_id == 7:
                    scan.stats = json.dumps(self.get_scan_statistics(scan_id))
                if status_id == 9:
                    scan.logs = json.dumps(status.get("details"))
                scan.scan_final_status = status_name
                db.session.commit()
            return status_id, status_name
        return status_id, status_name, status.get("details")

    def get_scan_statistics(self, scan_id):
        return self.__api_get("/sast/scans/%s/resultsStatistics" % scan_id).json()

    def register_report(self, scan_id, save2db=True):
        r = self.__api_post("/reports/sastScan", {"reportType": "PDF", "scanId": scan_id})
        report_id = r.json().get("reportId")
        if save2db:
            scan = Model.query.filter_by(scan_id=scan_id).one()
            scan.report_id = report_id
            db.session.commit()
            return util.respond(
                r.status_code,
                "Report registered.",
                data={"scanId": scan_id, "reportId": report_id},
            )
        return report_id

    def get_report_status(self, report_id, save2db=True):
        resp = self.__api_get("/reports/sastScan/%s/status" % report_id)
        status = resp.json().get("status")
        if status.get("id") == 2 and save2db:
            row = Model.query.filter_by(report_id=report_id).one()
            row.finished_at = datetime.datetime.utcnow()
            row.finished = True
            db.session.commit()
        return status.get("id"), status.get("value")

    def get_report(self, report_id):
        row = Model.query.filter_by(report_id=report_id).one()
        if not row.finished:
            status, _ = self.get_report_status(report_id)
            if status != 2:
                return {"message": "Report is not available yet"}, 400
        r = self.__api_get("/reports/sastScan/{0}".format(report_id))
        file_obj = BytesIO(r.content)
        return send_file(
            file_obj,
            attachment_filename="report.pdf",
            mimetype="Content-Type: application/pdf; charset={r.encoding}",
        )

    def get_report_content(self, report_id):
        row = Model.query.filter_by(report_id=report_id).one()
        if not row.finished:
            status, _ = self.get_report_status(report_id)
            if status != 2:
                return {"message": "Report is not available yet"}, 400
        r = self.__api_get("/reports/sastScan/{0}".format(report_id))
        return r.content

    def get_queue_scan_position(self, scan_id):
        res = self.__api_get(f"/sast/scansQueue/{scan_id}").json()
        return res.get("queuePosition")

    def cancel_scan(self, scan_id):
        data = {"status": "Canceled"}
        res = self.__api_patch(f"/sast/scansQueue/{scan_id}", data=data)
        return res.status_code

    @staticmethod
    def get_latest(column, project_id):
        try:
            repo_id = nexus.nx_get_repository_id(project_id)
        except NoResultFound:
            return -1
        row = Model.query.filter_by(repo_id=repo_id).order_by(desc(Model.run_at)).limit(1).first()
        if row is None:
            return -1
        return getattr(row, column)

    def get_result(self, project_id):
        ret = {
            "message": "",
            "status": -1,
            "result": {},
            "run_at": None,
        }
        scan_id = self.get_latest("scan_id", project_id)
        row = Model.query.filter_by(scan_id=scan_id).first()
        if scan_id < 0 or row is None:
            ret["status"] = 0
            ret["message"] = "This project does not have any scan."
            return ret
        st_id, st_name = self.get_scan_status(scan_id)
        if st_id != 7:
            if st_id in [8, 9]:
                st_mapping = {8: "The scan is canceled.", 9: "The scan failed."}
                ret["status"] = -1
                ret["message"] = st_mapping[st_id]
            else:
                ret["status"] = 2
                ret["message"] = "The scan is not completed yet."
            return ret

        report_id = row.report_id
        if report_id is not None and report_id < 0:
            data_json, status_code = self.register_report(scan_id)
            report_id = data_json["data"]["reportId"]
        rst_id, rst_name = self.get_report_status(report_id)

        data = self.get_scan_statistics(scan_id)
        data.pop("statisticsCalculationDate", "")
        if rst_id != 2:
            ret["message"] = "In the process of generating report."
        ret["message"] = "success"
        ret["status"] = 1
        ret["result"] = data
        ret["run_at"] = str(row.run_at) if row.run_at is not None else None
        ret["report_id"] = report_id
        return ret

    @staticmethod
    def list_scans(project_id):
        rows = Model.query.filter_by(repo_id=nexus.nx_get_repository_id(project_id)).order_by(desc(Model.run_at)).all()
        ret = [CheckMarx.to_json(row, project_id) for row in rows]
        return ret

    @staticmethod
    def get_scan(project_id, commit_id):
        row = (
            Model.query.filter(
                Model.repo_id == nexus.nx_get_repository_id(project_id),
                Model.commit_id.like(f"{commit_id}%"),
            )
            .order_by(desc(Model.scan_id))
            .first()
        )
        if row is not None:
            scan_id = row.scan_id
            ret = CheckMarx.to_json(row, project_id)
            if not row.finished:
                status_id, status_name = checkmarx.get_scan_status(scan_id)
                if status_id == 7:
                    ret["stats"] = checkmarx.get_scan_statistics(scan_id)
                ret["scan_final_status"] = status_name
            return ret
        else:
            return {}

    @staticmethod
    def to_json(row, project_id):
        if row.stats is None:
            stats = None
        else:
            stats = json.loads(row.stats)
        if row.logs is None:
            logs = None
        else:
            logs = json.loads(row.logs)
        return {
            "scan_id": row.scan_id,
            "branch": row.branch,
            "commit_id": row.commit_id[0:7],
            "commit_url": gitlab.commit_id_to_url(project_id, row.commit_id),
            "status": row.scan_final_status,
            "stats": stats,
            "run_at": str(row.run_at),
            "report_id": row.report_id,
            "report_ready": row.finished is True and row.report_id != -1,
            "logs": logs,
        }


checkmarx = CheckMarx()


# --------------------- Resources ---------------------
class GetCheckmarxProject(Resource):
    @jwt_required()
    def get(self, project_id):
        cm_project_id = checkmarx.get_latest("cm_project_id", project_id)
        return util.success({"cm_project_id": cm_project_id})


class CreateCheckmarxScan(Resource):
    @jwt_required()
    def post(self):
        parser = reqparse.RequestParser()
        parser.add_argument("cm_project_id", type=int, required=True)
        parser.add_argument("repo_id", type=int, required=True)
        parser.add_argument("scan_id", type=int, required=True)
        parser.add_argument("branch", type=str, required=True)
        parser.add_argument("commit_id", type=str, required=True)
        args = parser.parse_args()
        return checkmarx.create_scan(args)


class GetCheckmarxScans(Resource):
    @jwt_required()
    def get(self, project_id):
        return util.success(checkmarx.list_scans(project_id))


class GetCheckmarxLatestScan(Resource):
    @jwt_required()
    def get(self, project_id):
        scan_id = checkmarx.get_latest("scan_id", project_id)
        if scan_id >= 0:
            return util.success({"scan_id": scan_id})
        else:
            return util.respond(204)


class GetCheckmarxLatestScanStats(Resource):
    @jwt_required()
    def get(self, project_id):
        scan_id = checkmarx.get_latest("scan_id", project_id)
        if scan_id < 0:
            return util.respond(204)
        stats = checkmarx.get_scan_statistics(scan_id)
        if "statisticsCalculationDate" in stats:
            return util.success(stats)
        else:
            raise DevOpsError(400, stats)


class GetCheckmarxLatestReport(Resource):
    @jwt_required()
    def get(self, project_id):
        report_id = checkmarx.get_latest("report_id", project_id)
        if report_id < 0:
            return util.respond(204)
        return checkmarx.get_report(report_id)


class GetCheckmarxReport(Resource):
    @jwt_required()
    def get(self, report_id):
        return checkmarx.get_report(report_id)


class GetCheckmarxScanStatus(Resource):
    @jwt_required()
    def get(self, scan_id):
        status_id, name = checkmarx.get_scan_status(scan_id)

        # Merge id 2 and 10 as same status
        if status_id == 10:
            status_id, name = 2, "PreScan"

        result = {"id": status_id, "name": name}
        if status_id in [1, 2, 3]:
            result.update({"queue_position": checkmarx.get_queue_scan_position(scan_id)})
        return util.success(result)


class RegisterCheckmarxReport(Resource):
    @jwt_required()
    def post(self, scan_id):
        return checkmarx.register_report(scan_id)


class GetCheckmarxReportStatus(Resource):
    @jwt_required()
    def get(self, report_id):
        status_id, value = checkmarx.get_report_status(report_id)
        return util.success({"id": status_id, "value": value})


class GetCheckmarxScanStatistics(Resource):
    @jwt_required()
    def get(self, scan_id):
        stats = checkmarx.get_scan_statistics(scan_id)
        if "statisticsCalculationDate" in stats:
            return util.success(stats)
        else:
            raise DevOpsError(400, stats)


class CancelCheckmarxScan(Resource):
    @jwt_required()
    def post(self, scan_id):
        status_code = checkmarx.cancel_scan(scan_id)
        status = "success" if status_code == 200 else "failure"
        return {"status": status, "status_code": status_code}


def is_json(string):
    try:
        json.loads(string)
    except ValueError:
        return False
    return True


def row_to_dict(row):
    ret = {}
    if row is None:
        return row
    for key in type(row).__table__.columns.keys():
        value = getattr(row, key)
        if type(value) is datetime or type(value) is date:
            ret[key] = str(value)
        elif isinstance(value, str) and is_json(value):
            ret[key] = json.loads(value)
        else:
            ret[key] = value
    return ret


class CronjobScan(Resource):
    def get(self):
        querys_all = Model.query.with_entities(Model.repo_id
                                               ).filter(Model.repo_id is not None
                                                        ).group_by(Model.repo_id
                                                                   ).order_by(Model.repo_id
                                                                              ).all()
        rec_no = 0
        for query in querys_all:
            rec_no += 1
            logger.logger.info(f"rec no: {rec_no}, repo_id:{query.repo_id}, run CronjobScan")
            checkamrx_keep_report(query.repo_id)
        return util.success()


def checkamrx_keep_report(repo_id, keep_record: int = 5):
    scan = Model.query.with_entities(func.min(Model.run_at).label("run_at")
                                     ).filter(Model.repo_id == repo_id,
                                              Model.report_id > 0
                                              ).group_by(Model.repo_id).first()
    if scan:
        rows = Model.query.filter(Model.repo_id == repo_id,
                                  Model.run_at >= scan.run_at
                                  ).order_by(desc(Model.run_at)
                                             ).all()
    else:
        rows = Model.query.filter_by(repo_id=repo_id).order_by(desc(Model.run_at)).all()
    utcnow = datetime.datetime.utcnow()
    if rows:
        report_count = 0
        scan_list =[row.scan_id for row in rows]
        for scan_id in scan_list:
            row = Model.query.filter_by(scan_id=scan_id).one()
            # 原始的pdf檔可能已經失效,將scan_final_status改成null後,將觸發前端重新去要pdf檔
            # 最近30天內及最新的五筆
            if report_count < keep_record and utcnow - datetime.timedelta(days=30) <= row.run_at:
                try:
                    status_id, status_name, details = checkmarx.get_scan_status(row.scan_id, False)
                    # Merge id 2 and 10 as same status
                    if status_id == 10:
                        status_id, status_name = 2, "PreScan"
                    if status_id in {7, 8, 9}:
                        if status_id == 7:  # Finished
                            row.stats = json.dumps(checkmarx.get_scan_statistics(row.scan_id))
                            # report_change = False
                            if row.report_id is None or row.report_id < 0:
                                row.report_id = checkmarx.register_report(row.scan_id, False)
                                logger.logger.info(f"scan: {row.scan_id}, report_id: {row.report_id}")
                            if row.report_id is not None and row.report_id > 0:
                                rep_status_id, value = checkmarx.get_report_status(str(row.report_id), False)
                                if rep_status_id == 2:  # 1:InProcess, 2:Created
                                    row.finished_at = datetime.datetime.utcnow()
                                    row.finished = True
                                    logger.logger.info(f"scan: {row.scan_id}, rep_status_id: {rep_status_id}")
                        if status_id == 9:  # Failed
                            row.logs = json.dumps(details)
                        row.scan_final_status = status_name
                    logger.logger.info(f"scan_id: {row.scan_id}, status_id: {status_id}, ststus_name: {status_name}" +
                                       f", details: {details}")
                    if row.report_id is None:
                        row.report_id = -1
                        logger.logger.info(f"Updating checkmarx scan: {row.scan_id}'s report_id {row.report_id}")
                    if status_id in [1, 2, 3] or (status_id == 7 and row.report_id < 0 and row.finished):
                        logger.logger.info(f"Updating checkmarx scan: {row.scan_id}'s status")
                        row.report_id = checkmarx.register_report(row.scan_id, False)
                        report_count += 1
                        logger.logger.info(f"Updating checkmarx scan: {row.scan_id}'s report")
                    elif status_id == 7 and row.report_id < 0 and row.finished is None:
                        row.scan_final_status = None
                        report_count += 1
                        logger.logger.info(f"Updating checkmarx scan: {row.scan_id}'s status {row.scan_final_status}")
                    elif status_id == 7 and row.report_id != -1:
                        report_count += 1
                except Exception as e:
                    logger.logger.exception(str(e))
            else:
                logger.logger.info(f"scan: {row.scan_id}, rep_status_id: {row.report_id}")
                # 將report_id改成-1,前端就不會產生下載的icon,也無法進行下載
                row.report_id = -1
                if row.finished is None:
                    row.finished = True
                    if row.finished_at is None:
                        row.scan_final_status = "Canceled"
                if row.scan_final_status is None:
                    row.scan_final_status = "Deleted"
                if row.scan_final_status == "Scanning" or row.scan_final_status == "Queued":
                    row.scan_final_status = "Canceled"
                logger.logger.info(f"scan: {row.scan_id}, rep_status_id: {row.report_id}")
            if row not in db.session:
                db.session.merge(row)
            db.session.commit()
