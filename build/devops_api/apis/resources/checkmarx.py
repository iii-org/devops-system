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
        self.expire_at = time.time() + 86400  # 1 day

    @staticmethod
    def post_report(args):
        try:
            db.engine.execute(
                "INSERT INTO public.checkmarx "
                "(cm_project_id, repo_id, scan_id, report_id, run_at) "
                "VALUES ({0}, {1}, {2}, {3}, '{4}')"
                .format(
                    args['cm_project_id'],
                    args['repo_id'],
                    args['scan_id'],
                    args['report_id'],
                    datetime.datetime.now()
                ))
            return {"message": "success"}, 200
        except Exception as e:
            return {"message": "error", "data": e.__str__()}, 400

    def get_scan_status(self, scan_id):
        url = self.build_url('/sast/scans/' + scan_id)
        status = requests.get(url).json().status
        return status.id, status.name

    def get_report(self, report_id):
        try:
            # Get report
            url = self.app.config['CHECKMARX_ORIGIN'] + '/reports/sastScan/' + report_id
            headers = {'Authorization': 'Bearer ' + self.token()}
            r = requests.get(url, headers=headers, allow_redirects=True)
            file_obj = BytesIO(r.content)
            return send_file(
                file_obj,
                attachment_filename='report.pdf',
                mimetype="Content-Type: application/pdf; charset={r.encoding}"
            )
        except Exception as e:
            return {"message": "error", "data": e.__str__()}, 400
