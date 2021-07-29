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

import config
import nexus
import util
from model import Checkmarx as Model
from model import db
from resources import apiError, gitlab
from resources.apiError import DevOpsError


def build_url(path):
    return config.get('CHECKMARX_ORIGIN') + path


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
        data = {'userName': config.get('CHECKMARX_USERNAME'),
                'password': config.get('CHECKMARX_PASSWORD'),
                'grant_type': 'password',
                'scope': 'sast_rest_api',
                'client_id': 'resource_owner_client',
                'client_secret': config.get('CHECKMARX_SECRET')
                }
        self.access_token = requests.post(url, data).json().get('access_token')
        self.expire_at = time.time() + 43700  # 0.5 day

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
                apiError.error_3rd_party_api('Checkmarx', res))
        return res

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
        status = self.__api_get('/sast/scans/{0}'.format(scan_id)).json().get('status')
        status_id = status.get('id')
        status_name = status.get('name')
        if status_id in {7, 8, 9}:
            scan = Model.query.filter_by(scan_id=scan_id).one()
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
        scan_id = self.get_latest('scan_id', project_id)
        row = Model.query.filter_by(scan_id=scan_id).first()
        if scan_id < 0 or row is None:
            return {'message': 'This project does not have any scan.', 'status': -1}, 400
        st_id, st_name = self.get_scan_status(scan_id)
        if st_id == 8:
            return {'message': 'The scan is canceled.', 'status': 4}, 200
        if st_id == 9:
            return {'message': 'The scan failed.', 'status': 5}, 200
        if st_id != 7:
            return {'message': 'The scan is not completed yet.', 'status': 1}, 200
        report_id = row.report_id
        if report_id < 0:
            data_json, status_code = self.register_report(scan_id)
            report_id = data_json['data']['reportId']
        rst_id, rst_name = self.get_report_status(report_id)
        if rst_id != 2:
            return {'message': 'The report is not ready yet.', 'status': 2,
                    'data': {'stats': self.get_scan_statistics(scan_id)}}, 200
        return {'message': 'success', 'status': 3, 'data': {
            'stats': self.get_scan_statistics(scan_id),
            'run_at': str(row.run_at),
            'report_id': report_id
        }}, 200

    @staticmethod
    def list_scans(project_id):
        rows = Model.query.filter_by(repo_id=nexus.nx_get_repository_id(project_id)).order_by(
            desc(Model.scan_id)).all()
        ret = []
        for row in rows:
            if row.stats is None:
                stats = None
            else:
                stats = json.loads(row.stats)
            ret.append({
                'scan_id': row.scan_id,
                'branch': row.branch,
                'commit_id': row.commit_id[0:7],
                'commit_url': gitlab.commit_id_to_url(project_id, row.commit_id),
                'status': row.scan_final_status,
                'stats': stats,
                'run_at': str(row.run_at),
                'report_id': row.report_id,
                'report_ready': row.finished is True
            })
        return ret


checkmarx = CheckMarx()


# --------------------- Resources ---------------------
class GetCheckmarxProject(Resource):
    @jwt_required
    def get(self, project_id):
        cm_project_id = checkmarx.get_latest('cm_project_id', project_id)
        return util.success({'cm_project_id': cm_project_id})


class CreateCheckmarxScan(Resource):
    @jwt_required
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
    @jwt_required
    def get(self, project_id):
        return util.success(checkmarx.list_scans(project_id))


class GetCheckmarxLatestScan(Resource):
    @jwt_required
    def get(self, project_id):
        scan_id = checkmarx.get_latest('scan_id', project_id)
        if scan_id >= 0:
            return util.success({'scan_id': scan_id})
        else:
            return util.respond(204)


class GetCheckmarxLatestScanStats(Resource):
    @jwt_required
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
    @jwt_required
    def get(self, project_id):
        report_id = checkmarx.get_latest('report_id', project_id)
        if report_id < 0:
            return util.respond(204)
        return checkmarx.get_report(report_id)


class GetCheckmarxReport(Resource):
    @jwt_required
    def get(self, report_id):
        return checkmarx.get_report(report_id)


class GetCheckmarxScanStatus(Resource):
    @jwt_required
    def get(self, scan_id):
        status_id, name = checkmarx.get_scan_status(scan_id)
        return util.success({'id': status_id, 'name': name})


class RegisterCheckmarxReport(Resource):
    @jwt_required
    def post(self, scan_id):
        return checkmarx.register_report(scan_id)


class GetCheckmarxReportStatus(Resource):
    @jwt_required
    def get(self, report_id):
        status_id, value = checkmarx.get_report_status(report_id)
        return util.success({'id': status_id, 'value': value})


class GetCheckmarxScanStatistics(Resource):
    @jwt_required
    def get(self, scan_id):
        stats = checkmarx.get_scan_statistics(scan_id)
        if 'statisticsCalculationDate' in stats:
            return util.success(stats)
        else:
            raise DevOpsError(400, stats)
