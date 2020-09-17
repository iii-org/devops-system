from model import db
import datetime
import logging
import requests
from flask import send_file
from io import BytesIO
import time

logger = logging.getLogger('devops.api')


class CheckMarx(object):
    headers = {'Content-Type': 'application/json'}

    def __init__(self, app):
        self.app = app
        self.access_token = None
        self.expire_at = 0

    def token(self):
        if time.time() > self.expire_at:
            self.login()
        return self.access_token

    def build_url(self, path):
        return self.app.config['CHECKMARX_ORIGIN'] + path

    def login(self):
        url = self.build_url('/auth/identity/connect/token')
        data = {'userName': self.app.config['CHECKMARX_USERNAME'],
                'password': self.app.config['CHECKMARX_PASSWORD'],
                'grant_type': 'password',
                'scope': 'sast_rest_api',
                'client_id': 'resource_owner_client',
                'client_secret': self.app.config['CHECKMARX_SECRET']
                }
        self.access_token = requests.post(url, data).json().get('access_token')
        self.expire_at = time.time() + 43700  # 0.5 day

    def get(self, path, headers=None):
        if headers is None:
            headers = {}
        url = self.build_url(path)
        headers['Authorization'] = 'Bearer ' + self.token()
        return requests.get(url, headers=headers, allow_redirects=True)

    def post(self, path, data=None, headers=None):
        if data is None:
            data = {}
        if headers is None:
            headers = {}
        url = self.build_url(path)
        headers['Authorization'] = 'Bearer ' + self.token()
        return requests.post(url, headers=headers, data=data, allow_redirects=True)

    def create_scan(self, args):
        try:
            db.engine.execute(
                "INSERT INTO public.checkmarx "
                "(cm_project_id, repo_id, scan_id, run_at) "
                "VALUES ({0}, {1}, {2}, '{3}')"
                .format(
                    args['cm_project_id'],
                    args['repo_id'],
                    args['scan_id'],
                    datetime.datetime.now()
                ))
            return {"message": "success"}, 200
        except Exception as e:
            return {"message": "error", "data": e.__str__()}, 400

    def get_scan_status(self, scan_id):
        status = self.get('/sast/scans/' + scan_id).json().get('status')
        return status.get('id'), status.get('name')

    def get_scan_status_wrapped(self, scan_id):
        status_id, name = self.get_scan_status(scan_id)
        return {'message': 'success', 'data': {'id': status_id, 'name': name}}, 200

    def register_report(self, scan_id):
        r = self.post('/reports/sastScan', {'reportType': 'PDF', 'scanId': scan_id})
        report_id = r.json().get('reportId')
        db.engine.execute(
            "UPDATE public.checkmarx "
            "SET report_id={0}"
            "WHERE scan_id={1}"
            .format(report_id, scan_id)
        )
        if r.status_code % 100 == 2:
            return {'message': 'success', 'data':
                    {'scanId': scan_id, 'reportId': report_id}
                    }, r.status_code
        else:
            return {'message': 'error'}, r.status_code

    def get_report_status(self, report_id):
        status = self.get('/reports/sastScan/%s/status' % report_id).json().get('status')
        if status.get('id') == 2:
            db.engine.execute(
                "UPDATE public.checkmarx "
                "SET finished_at='{0}', finished=true "
                "WHERE report_id={1}"
                .format(datetime.datetime.now(), report_id)
            )
        return status.get('id'), status.get('value')

    def get_report_status_wrapped(self, report_id):
        status_id, value = self.get_report_status(report_id)
        return {'message': 'success', 'data': {'id': status_id, 'value': value}}, 200

    def get_report(self, report_id):
        try:
            row = db.engine.execute(
                'SELECT finished FROM public.checkmarx '
                'WHERE report_id={0}'.format(report_id)
            ).fetchone()
            if not row['finished']:
                status, _ = self.get_report_status(report_id)
                if status != 2:
                    return {'message': 'Report is not available yet'}, 404
        except Exception as e:
            return {"message": "error", "data": e.__str__()}, 500
        try:
            r = self.get('/reports/sastScan/' + report_id)
            file_obj = BytesIO(r.content)
            return send_file(
                file_obj,
                attachment_filename='report.pdf',
                mimetype="Content-Type: application/pdf; charset={r.encoding}"
            )
        except Exception as e:
            return {"message": "error", "data": e.__str__()}, 400

