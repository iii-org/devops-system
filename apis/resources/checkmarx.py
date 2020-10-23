from model import db
import datetime
import logging, config
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
        return config.get('CHECKMARX_ORIGIN') + path

    def login(self):
        url = self.build_url('/auth/identity/connect/token')
        data = {'userName': config.get('CHECKMARX_USERNAME'),
                'password': config.get('CHECKMARX_PASSWORD'),
                'grant_type': 'password',
                'scope': 'sast_rest_api',
                'client_id': 'resource_owner_client',
                'client_secret': config.get('CHECKMARX_SECRET')
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
        status = self.get('/sast/scans/{0}'.format(scan_id)).json().get('status')
        return status.get('id'), status.get('name')

    def get_scan_status_wrapped(self, scan_id):
        status_id, name = self.get_scan_status(scan_id)
        return CheckMarx.wrap({'id': status_id, 'name': name}, 200)

    def get_scan_statistics(self, scan_id):
        return self.get('/sast/scans/%s/resultsStatistics' % scan_id).json()

    def get_scan_statistics_wrapped(self, scan_id):
        stats = self.get_scan_statistics(scan_id)
        if 'statisticsCalculationDate' in stats:
            return CheckMarx.wrap(stats, 200)
        else:
            return CheckMarx.wrap(stats, 400)

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
        return CheckMarx.wrap({'id': status_id, 'value': value}, 200)

    def get_report(self, report_id):
        try:
            row = db.engine.execute(
                'SELECT finished FROM public.checkmarx '
                'WHERE report_id={0}'.format(report_id)
            ).fetchone()
            if not row['finished']:
                status, _ = self.get_report_status(report_id)
                if status != 2:
                    return {'message': 'Report is not available yet'}, 400
        except Exception as e:
            return {"message": "error", "data": e.__str__()}, 500
        try:
            r = self.get('/reports/sastScan/{0}'.format(report_id))
            file_obj = BytesIO(r.content)
            return send_file(
                file_obj,
                attachment_filename='report.pdf',
                mimetype="Content-Type: application/pdf; charset={r.encoding}"
            )
        except Exception as e:
            return {"message": "error", "data": e.__str__()}, 400

    def get_latest(self, column, project_id):
        cursor = db.engine.execute(
            'SELECT git_repository_id FROM public.project_plugin_relation'
            ' WHERE project_id={0}'
                .format(project_id)
        )
        if cursor.rowcount == 0:
            return -1
        row = cursor.fetchone()
        repo_id = row['git_repository_id']
        if repo_id is None:
            return -1
        cursor = db.engine.execute(
            'SELECT {0} FROM public.checkmarx '
            ' WHERE repo_id={1}'
            ' ORDER BY run_at DESC'
            ' LIMIT 1'
                .format(column, repo_id)
        )
        if cursor.rowcount == 0:
            return -1
        return cursor.fetchone()[column]

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
