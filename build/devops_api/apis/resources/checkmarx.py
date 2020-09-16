from model import db
import datetime
import logging
import requests
from flask import send_file
from io import BytesIO

logger = logging.getLogger('devops.api')


class CheckMarx(object):
    headers = {'Content-Type': 'application/json'}

    def post_report(self, logger, args):
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

    def get_report(self, logger, app, report_id):
        try:
            # Get Checkmarx token
            url = app.config['CHECKMARX_ORIGIN'] + '/auth/identity/connect/token'
            data = {'userName': app.config['CHECKMARX_USERNAME'],
                    'password': app.config['CHECKMARX_PASSWORD'],
                    'grant_type': 'password',
                    'scope': 'sast_rest_api',
                    'client_id': 'resource_owner_client',
                    'client_secret': app.config['CHECKMARX_SECRET']
                    }
            token = requests.post(url, data).json().get('access_token')

            # Get report
            url = app.config['CHECKMARX_ORIGIN'] + '/reports/sastScan/' + report_id
            headers = {'Authorization': 'Bearer ' + token}
            r = requests.get(url, headers=headers, allow_redirects=True)
            file_obj = BytesIO(r.content)
            return send_file(
                file_obj,
                attachment_filename='report.pdf',
                mimetype="Content-Type: application/pdf; charset={r.encoding}"
            )
        except Exception as e:
            return {"message": "error", "data": e.__str__()}, 400
