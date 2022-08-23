import datetime
import json
import time
from io import BytesIO

import requests
from flask import send_file
from flask_jwt_extended import jwt_required
from flask_restful import Resource, reqparse
from sqlalchemy import desc
from sqlalchemy.orm.exc import NoResultFound

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
        if arg['key'] == key:
            return arg['value']
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
        url = build_url('/auth/identity/connect/token')
        data = {'userName': cm_get_config("username"),
                'password': cm_get_config("password"),
                'grant_type': 'password',
                'scope': 'sast_rest_api',
                'client_id': 'resource_owner_client',
                'client_secret': cm_get_config("client-secret")
                }
        self.access_token = requests.post(url, data).json().get('access_token')
        self.expire_at = time.time() + 1800  # 0.5 hour

    def __api_request(self, method, path, headers=None, data=None):
        if data is None:
            data = {}
        if headers is None:
            headers = {}
        url = build_url(path)
        headers['Authorization'] = 'Bearer ' + self.token()
        if method.upper() == 'GET':
            res = requests.get(url, headers=headers, allow_redirects=True)
        elif method.upper() == 'POST':
            res = requests.post(url, headers=headers, data=data, allow_redirects=True)
        else:
            raise DevOpsError(500, 'Only GET and POST is allowed.',
                              error=apiError.invalid_code_path('Only GET and POST is allowed, but'
                                                               '{0} provided.'.format(method)))
        if int(res.status_code / 100) != 2:
            raise apiError.DevOpsError(
                res.status_code, 'Got non-2xx response from Checkmarx.',
                apiError.error_3rd_party_api('Checkmarx', self.__handle_error_message(res)))
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
        return self.__api_request('GET', path, headers=headers)

    def __api_post(self, path, data=None, headers=None):
        if data is None:
            data = {}
        if headers is None:
            headers = {}
        url = build_url(path)
        headers['Authorization'] = 'Bearer ' + self.token()
        res = requests.post(url, headers=headers, data=data, allow_redirects=True)
        return res

    def __api_patch(self, path, data=None, headers=None):
        if data is None:
            data = {}
        if headers is None:
            headers = {}
        url = build_url(path)
        headers['Authorization'] = 'Bearer ' + self.token()
        res = requests.patch(url, headers=headers, data=data, allow_redirects=True)
        return res

    @staticmethod
    def create_scan(args):
        new = Model(
            cm_project_id=args['cm_project_id'],
            repo_id=args['repo_id'],
            scan_id=args['scan_id'],
            branch=args['branch'],
            commit_id=args['commit_id'],
            scan_final_status=None,
            run_at=datetime.datetime.now())
        db.session.add(new)
        db.session.commit()
        return util.success()

    # Need to write into db if see a final scan status
    def get_scan_status(self, scan_id):
        try:
            status = self.__api_get('/sast/scans/{0}'.format(scan_id)).json().get('status')
        except Exception as e:
            error_mes = None
            if e.status_code == 404 and hasattr(e, "error_value"):
                scan = Model.query.filter_by(scan_id=scan_id).one()
                scan.scan_final_status = "Deleted"
                error_mes = e.error_value.get("message")
            
            error_mes = error_mes if error_mes is not None else str(e)
            raise apiError.DevOpsError(
                e.status_code, 'Got non-2xx response from Checkmarx.',
                apiError.error_3rd_party_api('Checkmarx', error_mes)) 

        status_id = status.get('id')
        status_name = status.get('name')
        if status_id in {7, 8, 9}:
            scan = Model.query.filter_by(scan_id=scan_id).one()
            if status_id == 7:
                scan.stats = json.dumps(self.get_scan_statistics(scan_id))
            scan.scan_final_status = status_name
            db.session.commit()
        return status_id, status_name

    def get_scan_statistics(self, scan_id):
        return self.__api_get('/sast/scans/%s/resultsStatistics' % scan_id).json()

    def register_report(self, scan_id):
        r = self.__api_post('/reports/sastScan', {'reportType': 'PDF', 'scanId': scan_id})
        report_id = r.json().get('reportId')
        scan = Model.query.filter_by(scan_id=scan_id).one()
        scan.report_id = report_id
        db.session.commit()
        return util.respond(r.status_code, 'Report registered.',
                            data={'scanId': scan_id, 'reportId': report_id})

    def get_report_status(self, report_id):
        resp = self.__api_get('/reports/sastScan/%s/status' % report_id)
        status = resp.json().get('status')
        if status.get('id') == 2:
            row = Model.query.filter_by(report_id=report_id).one()
            row.finished_at = datetime.datetime.now()
            row.finished = True
            db.session.commit()
        return status.get('id'), status.get('value')

    def get_report(self, report_id):
        row = Model.query.filter_by(report_id=report_id).one()
        if not row.finished:
            status, _ = self.get_report_status(report_id)
            if status != 2:
                return {'message': 'Report is not available yet'}, 400
        r = self.__api_get('/reports/sastScan/{0}'.format(report_id))
        file_obj = BytesIO(r.content)
        return send_file(
            file_obj,
            attachment_filename='report.pdf',
            mimetype="Content-Type: application/pdf; charset={r.encoding}"
        )

    def get_report_content(self, report_id):
        row = Model.query.filter_by(report_id=report_id).one()
        if not row.finished:
            status, _ = self.get_report_status(report_id)
            if status != 2:
                return {'message': 'Report is not available yet'}, 400
        r = self.__api_get('/reports/sastScan/{0}'.format(report_id))
        return r.content

    def get_queue_scan_position(self, scan_id):
        res = self.__api_get(f'/sast/scansQueue/{scan_id}').json()
        return res.get("queuePosition")

    def cancel_scan(self, scan_id):
        data = {"status": "Canceled"}
        res = self.__api_patch(f'/sast/scansQueue/{scan_id}', data=data)
        return res.status_code

    @staticmethod
    def get_latest(column, project_id):
        try:
            repo_id = nexus.nx_get_repository_id(project_id)
        except NoResultFound:
            return -1
        row = Model.query.filter_by(repo_id=repo_id).order_by(
            desc(Model.run_at)).limit(1).first()
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
        scan_id = self.get_latest('scan_id', project_id)
        row = Model.query.filter_by(scan_id=scan_id).first()
        if scan_id < 0 or row is None:
            ret["status"] = 0
            ret["message"] = 'This project does not have any scan.'
            return ret
        st_id, st_name = self.get_scan_status(scan_id)
        if st_id != 7:
            if st_id in [8, 9]:
                st_mapping = {
                    8: "The scan is canceled.",
                    9: "The scan failed."
                }
                ret["status"] = -1
                ret["message"] = st_mapping[st_id]
            else:
                ret["status"] = 2
                ret["message"] = "The scan is not completed yet."
            return ret

        report_id = row.report_id
        if report_id < 0:
            data_json, status_code = self.register_report(scan_id)
            report_id = data_json['data']['reportId']
        rst_id, rst_name = self.get_report_status(report_id)

        data = self.get_scan_statistics(scan_id)
        data.pop("statisticsCalculationDate", "")
        if rst_id != 2:
            ret["message"] = 'In the process of generating report.'
        ret["message"] = 'success'
        ret["status"] = 1
        ret["result"] = data
        ret["run_at"] = str(row.run_at) if row.run_at is not None else None
        ret["report_id"] = report_id
        return ret

    @staticmethod
    def list_scans(project_id):
        rows = Model.query.filter_by(repo_id=nexus.nx_get_repository_id(project_id)).order_by(
            desc(Model.scan_id)).all()
        ret = []
        if rows:
            df = pd.DataFrame([CheckMarx.to_json(row, project_id) for row in rows])
            df.sort_values(by="run_at", ascending=False)
            df_five_download = df[(df.status == "Finished") & (df.report_id != -1)][0:5]
            df.report_id = -1
            df.loc[df_five_download.index] = df_five_download
            update_list = list(df.drop(list(df_five_download.index)).index)
            for i in update_list:
                Model.query.filter_by(repo_id=nexus.nx_get_repository_id(project_id)).filter_by(scan_id=i).update({"report_id": -1})
            db.session.commit()
            df = df_five_download.append(df[df["report_id"] == -1].sort_values(by="run_at", ascending=False))
            ret = [value for key, value in df.T.to_dict().items()]
        return ret

    @staticmethod
    def get_scan(project_id, commit_id):
        row = Model.query.filter(
            Model.repo_id == nexus.nx_get_repository_id(project_id),
            Model.commit_id.like(f'{commit_id}%')
        ).order_by(
            desc(Model.scan_id)).first()
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
        return {
            'scan_id': row.scan_id,
            'branch': row.branch,
            'commit_id': row.commit_id[0:7],
            'commit_url': gitlab.commit_id_to_url(project_id, row.commit_id),
            'status': row.scan_final_status,
            'stats': stats,
            'run_at': str(row.run_at),
            'report_id': row.report_id,
            'report_ready': row.finished is True and row.report_id != -1
        }


checkmarx = CheckMarx()


# --------------------- Resources ---------------------
class GetCheckmarxProject(Resource):
    @jwt_required()
    def get(self, project_id):
        cm_project_id = checkmarx.get_latest('cm_project_id', project_id)
        return util.success({'cm_project_id': cm_project_id})


class CreateCheckmarxScan(Resource):
    @jwt_required()
    def post(self):
        parser = reqparse.RequestParser()
        parser.add_argument('cm_project_id', type=int, required=True)
        parser.add_argument('repo_id', type=int, required=True)
        parser.add_argument('scan_id', type=int, required=True)
        parser.add_argument('branch', type=str, required=True)
        parser.add_argument('commit_id', type=str, required=True)
        args = parser.parse_args()
        return checkmarx.create_scan(args)


class GetCheckmarxScans(Resource):
    @jwt_required()
    def get(self, project_id):
        return util.success(checkmarx.list_scans(project_id))


class GetCheckmarxLatestScan(Resource):
    @jwt_required()
    def get(self, project_id):
        scan_id = checkmarx.get_latest('scan_id', project_id)
        if scan_id >= 0:
            return util.success({'scan_id': scan_id})
        else:
            return util.respond(204)


class GetCheckmarxLatestScanStats(Resource):
    @jwt_required()
    def get(self, project_id):
        scan_id = checkmarx.get_latest('scan_id', project_id)
        if scan_id < 0:
            return util.respond(204)
        stats = checkmarx.get_scan_statistics(scan_id)
        if 'statisticsCalculationDate' in stats:
            return util.success(stats)
        else:
            raise DevOpsError(400, stats)


class GetCheckmarxLatestReport(Resource):
    @jwt_required()
    def get(self, project_id):
        report_id = checkmarx.get_latest('report_id', project_id)
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

        result = {'id': status_id, 'name': name}
        if status_id in [1, 2, 3]:
            result.update({"queue_position": checkmarx.get_queue_scan_position(scan_id)})
        return util.success(result)


class RegisterCheckmarxReport(Resource):
    @jwt_required()
    def post(self, scan_id):
        return checkmarx.register_report(scan_id)


class GetCheckmarxReportStatus(Resource):
    @jwt_required()
    def get(self, scan_id):
        status_id, value = checkmarx.get_report_status(scan_id)
        return util.success({'id': status_id, 'value': value})


class GetCheckmarxScanStatistics(Resource):
    @jwt_required()
    def get(self, scan_id):
        stats = checkmarx.get_scan_statistics(scan_id)
        if 'statisticsCalculationDate' in stats:
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
        query = Model.query.filter(Model.report_id != -1).filter(Model.stats == None).all()
        id_list = [row_to_dict(doc)["scan_id"] for doc in query]
        for id in id_list:
            try:
                GetCheckmarxReportStatus().get(id)
                time.sleep(3)
            except Exception as e:
                logger.logger.info(str(e))
        return util.success()

