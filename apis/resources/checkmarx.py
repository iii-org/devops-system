import datetime
import time
from io import BytesIO

import requests
from flask import send_file
from flask_jwt_extended import jwt_required
from flask_restful import Resource, reqparse
from sqlalchemy import desc
from sqlalchemy.orm.exc import NoResultFound

from model import Checkmarx as Model, ProjectPluginRelation

import config
from model import db
from resources import util, apiError, project, gitlab


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

    def __api_get(self, path, headers=None):
        if headers is None:
            headers = {}
        url = build_url(path)
        headers['Authorization'] = 'Bearer ' + self.token()
        return requests.get(url, headers=headers, allow_redirects=True)

    def __api_post(self, path, data=None, headers=None):
        if data is None:
            data = {}
        if headers is None:
            headers = {}
        url = build_url(path)
        headers['Authorization'] = 'Bearer ' + self.token()
        return requests.post(url, headers=headers, data=data, allow_redirects=True)

    @staticmethod
    def create_scan(args):
        new = Model(
            cm_project_id=args['cm_project_id'],
            repo_id=args['repo_id'],
            scan_id=args['scan_id'],
            run_at=datetime.datetime.now())
        db.session.add(new)
        db.commit()
        return util.success()

    def get_scan_status(self, scan_id):
        status = self.__api_get('/sast/scans/{0}'.format(scan_id)).json().get('status')
        return status.get('id'), status.get('name')

    def get_scan_status_wrapped(self, scan_id):
        status_id, name = self.get_scan_status(scan_id)
        return CheckMarx.wrap({'id': status_id, 'name': name}, 200)

    def get_scan_statistics(self, scan_id):
        return self.__api_get('/sast/scans/%s/resultsStatistics' % scan_id).json()

    def get_scan_statistics_wrapped(self, scan_id):
        stats = self.get_scan_statistics(scan_id)
        if 'statisticsCalculationDate' in stats:
            return CheckMarx.wrap(stats, 200)
        else:
            return CheckMarx.wrap(stats, 400)

    def register_report(self, scan_id):
        r = self.__api_post('/reports/sastScan', {'reportType': 'PDF', 'scanId': scan_id})
        if r.status_code % 100 != 2:
            return util.respond(r.status_code, 'Error when registering checkmarx report.',
                                error=apiError.checkmarx_error(r))
        report_id = r.json().get('reportId')
        scan = Model.query.filter_by(scan_id=scan_id).one()
        scan.report_id = report_id
        db.session.commit()
        return util.respond(r.status_code, data={'scanId': scan_id, 'reportId': report_id})

    def get_report_status(self, report_id):
        status = self.__api_get('/reports/sastScan/%s/status' % report_id).json().get('status')
        if status.get('id') == 2:
            row = Model.query.filter_by(report_id=report_id).one()
            row.finished_at = datetime.datetime.now()
            row.finished = True
            db.session.commit()
        return status.get('id'), status.get('value')

    def get_report_status_wrapped(self, report_id):
        status_id, value = self.get_report_status(report_id)
        return CheckMarx.wrap({'id': status_id, 'value': value}, 200)

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
            repo_id = project.get_repository_id(project_id)
        except NoResultFound:
            return -1
        row = Model.query.filter_by(repo_id=repo_id).order_by(
            desc(Model.run_at)).limit(1).first()
        if row is None:
            return -1
        return getattr(row, column)

    def get_latest_scan_wrapped(self, project_id):
        scan_id = self.get_latest('scan_id', project_id)
        if scan_id >= 0:
            return CheckMarx.wrap({'scan_id': scan_id}, 200)
        else:
            return CheckMarx.wrap(None, 400, 'No scan found!')

    def get_latest_scan_stats_wrapped(self, project_id):
        scan_id = self.get_latest('scan_id', project_id)
        if scan_id < 0:
            return CheckMarx.wrap(None, 400, 'No scan in project')
        return self.get_scan_statistics_wrapped(scan_id)

    def get_latest_report_wrapped(self, project_id):
        report_id = self.get_latest('report_id', project_id)
        if report_id < 0:
            return CheckMarx.wrap(None, 400, 'No report in project')
        return self.get_report(report_id)

    @staticmethod
    def wrap(json, status_code, error=None):
        if status_code / 100 == 2:
            return {'message': 'success', 'data': json}, status_code
        else:
            if error is None:
                return {'message': 'error', 'data': json}, status_code
            else:
                return {'message': error}, status_code

    def get_result(self, project_id):
        scan_id = self.get_latest('scan_id', project_id)
        if scan_id < 0:
            return {'message': 'This project does not have any scan.', 'status': -1}, 400
        st_id, st_name = self.get_scan_status(scan_id)
        if st_id == 8:
            return {'message': 'The scan is canceled.', 'status': 4}, 200
        if st_id == 9:
            return {'message': 'The scan failed.', 'status': 5}, 200
        if st_id != 7:
            return {'message': 'The scan is not completed yet.', 'status': 1}, 200
        report_id = self.get_latest('report_id', project_id)
        if report_id < 0:
            json, status_code = self.register_report(scan_id)
            if status_code % 100 != 2:
                return json, status_code
            report_id = json['data']['reportId']
        rst_id, rst_name = self.get_report_status(report_id)
        if rst_id != 2:
            return {'message': 'The report is not ready yet.', 'status': 2,
                    'data': {'stats': self.get_scan_statistics(scan_id)}}, 200
        return {'message': 'success', 'status': 3, 'data': {
            'stats': self.get_scan_statistics(scan_id),
            'report_id': report_id
        }
                }, 200


checkmarx = CheckMarx()


# --------------------- Resources ---------------------
class CreateCheckmarxScan(Resource):
    @jwt_required
    def post(self):
        parser = reqparse.RequestParser()
        parser.add_argument('cm_project_id', type=int, required=True)
        parser.add_argument('repo_id', type=int, required=True)
        parser.add_argument('scan_id', type=int, required=True)
        args = parser.parse_args()
        return checkmarx.create_scan(args)


class GetCheckmarxLatestScan(Resource):
    @jwt_required
    def get(self, project_id):
        return checkmarx.get_latest_scan_wrapped(project_id)


class GetCheckmarxLatestScanStats(Resource):
    @jwt_required
    def get(self, project_id):
        return checkmarx.get_latest_scan_stats_wrapped(project_id)


class GetCheckmarxLatestReport(Resource):
    @jwt_required
    def get(self, project_id):
        return checkmarx.get_latest_report_wrapped(project_id)


class GetCheckmarxReport(Resource):
    @jwt_required
    def get(self, report_id):
        return checkmarx.get_report(report_id)


class GetCheckmarxScanStatus(Resource):
    @jwt_required
    def get(self, scan_id):
        return checkmarx.get_scan_status_wrapped(scan_id)


class RegisterCheckmarxReport(Resource):
    @jwt_required
    def post(self, scan_id):
        return checkmarx.register_report(scan_id)


class GetCheckmarxReportStatus(Resource):
    @jwt_required
    def get(self, report_id):
        return checkmarx.get_report_status_wrapped(report_id)


class GetCheckmarxScanStatistics(Resource):
    @jwt_required
    def get(self, scan_id):
        return checkmarx.get_scan_statistics_wrapped(scan_id)
