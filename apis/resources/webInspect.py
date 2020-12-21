import json
from datetime import datetime

from flask import make_response
from flask_jwt_extended import jwt_required
from flask_restful import Resource, reqparse

import config
import model
import util
from model import db
# -------- API methods --------
from resources import apiError, role
from resources.apiError import DevOpsError
from resources.logger import logger


def __api_request(method, path, headers=None, params=None, data=None):
    if headers is None:
        headers = {}
    if params is None:
        params = {}
    if 'Content-Type' not in headers:
        headers['Content-Type'] = 'application/json'

    url = "{0}{1}".format(config.get('WEBINSPECT_BASE_URL'), path)
    print(url)
    output = util.api_request(method, url, headers, params, data)

    logger.info('WebInspect api {0} {1}, params={2}, body={5}, response={3} {4}'.format(
        method, url, params.__str__(), output.status_code, output.text, data))
    if int(output.status_code / 100) != 2:
        raise apiError.DevOpsError(
            output.status_code,
            'Got non-2xx response from WebInspect.',
            apiError.error_3rd_party_api('WebInspect', output))
    return output


def __api_get(path, params=None, headers=None):
    return __api_request('GET', path, params=params, headers=headers)


def __api_post(path, params=None, headers=None, data=None, ):
    return __api_request('POST', path, headers=headers, data=data, params=params)


# -------------- Regular methods --------------
def wi_create_scan(args):
    new = model.WebInspect(
        scan_id=args['scan_id'],
        project_name=args['project_name'],
        branch=args['branch'],
        commit_id=args['commit_id'],
        run_at=datetime.now(),
        finished=False
    )
    db.session.add(new)
    db.session.commit()


def wi_list_scans(project_name):
    ret = []
    rows = model.WebInspect.query.filter_by(project_name=project_name).all()
    for row in rows:
        ret.append(json.loads(str(row)))
    return ret


def wi_get_scan_status(scan_id):
    status = __api_get('/scanner/scans/{0}?action=GetCurrentStatus'.format(
        scan_id)).json().get('ScanStatus')
    if status == 'Complete':
        scan = model.WebInspect.query.filter_by(scan_id=scan_id).one()
        if not scan.finished:
            # This line will fill the data in db
            wi_get_scan_statistics(scan_id)
    return status


def wi_get_scan_statistics(scan_id):
    row = model.WebInspect.query.filter_by(scan_id=scan_id).one()
    if row.stats is not None:
        return json.loads(row)
    ret = {0: 0, 1: 0, 2: 0, 3: 0, 4: 0}
    results = __api_get('/scanner/scans/{0}.issue'.format(scan_id)).json()
    for r in results:
        for issue in r['issues']:
            ret[issue['severity']] += 1
    row = model.WebInspect.query.filter_by(scan_id=scan_id).one()
    row.stats = json.dumps(ret)
    row.finished = True
    db.session.commit()
    return ret


def wi_download_report(scan_id):
    xml = __api_get('/scanner/scans/{0}.xml?detailType=Full'.format(
        scan_id)).content
    response = make_response(xml)
    response.headers.set('Content-Type', 'application/xml')
    response.headers.set('charset', 'utf-8')
    response.headers.set(
        'Content-Disposition', 'attachment', filename='report-{0}.xml'.format(scan_id))
    return response


# --------------------- Resources ---------------------
class WebInspectScan(Resource):
    @jwt_required
    def post(self):
        parser = reqparse.RequestParser()
        parser.add_argument('scan_id', type=str)
        parser.add_argument('project_name', type=str)
        parser.add_argument('branch', type=str)
        parser.add_argument('commit_id', type=str)
        args = parser.parse_args()
        role.require_in_project(project_name=args['project_name'])
        return util.success(wi_create_scan(args))

    @jwt_required
    def get(self, project_name):
        role.require_in_project(project_name=project_name)
        return util.success(wi_list_scans(project_name))


class WebInspectScanStatus(Resource):
    @jwt_required
    def get(self, scan_id):
        return util.success({'status': wi_get_scan_status(scan_id)})


class WebInspectScanStatistics(Resource):
    @jwt_required
    def get(self, scan_id):
        return util.success({'severity_count': wi_get_scan_statistics(scan_id)})


class WebInspectReport(Resource):
    @jwt_required
    def get(self, scan_id):
        return wi_download_report(scan_id)
