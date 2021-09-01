import json
from datetime import datetime, timedelta

from flask import make_response
from flask_jwt_extended import jwt_required
from flask_restful import Resource, reqparse

import model
import nexus
import util
from model import db
# -------- API methods --------
from resources import apiError, role, gitlab, kubernetesClient
from resources.logger import logger

wie = None
wi_base_url = ''
sec = kubernetesClient.read_namespace_secret('default', 'webinspect')
if sec is not None:
    wi_base_url = sec.get('wi-base-url', '')


def wie_instance():
    global wie
    if wie is None:
        wie = WIE()
    return wie


def wi_api_request(method, path, headers=None, params=None, data=None):
    if headers is None:
        headers = {}
    if params is None:
        params = {}
    if 'Content-Type' not in headers:
        headers['Content-Type'] = 'application/json'

    if wi_base_url == '':
        raise apiError.DevOpsError(
            500,
            'WebInspect is not set up.',
            apiError.resource_not_found())
    url = f"{wi_base_url}{path}"
    output = util.api_request(method, url, headers, params, data)

    logger.debug(f"WebInspect api {method} {url}, header={str(headers)}, params={str(params)}, body={data},"
                 f" response={output.status_code} {output.text}")
    if int(output.status_code / 100) != 2:
        raise apiError.DevOpsError(
            output.status_code,
            'Got non-2xx response from WebInspect.',
            apiError.error_3rd_party_api('WebInspect', output))
    return output


def wi_api_get(path, params=None, headers=None):
    return wi_api_request('GET', path, params=params, headers=headers)


def wi_api_post(path, params=None, headers=None, data=None):
    return wi_api_request('POST', path, headers=headers, data=data, params=params)


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
    project_id = nexus.nx_get_project(name=project_name).id
    rows = model.WebInspect.query.filter_by(project_name=project_name).all()
    for row in rows:
        d = json.loads(str(row))
        d['issue_link'] = gitlab.commit_id_to_url(project_id, d['commit_id'])
        ret.append(d)
    return ret


def wi_get_scan_by_commit(project_id, commit_id):
    project_name = nexus.nx_get_project(id=project_id).name
    row = model.WebInspect.query.filter(
        model.WebInspect.project_name == project_name,
        model.WebInspect.commit_id.like(f'{commit_id}%')
    ).first()
    if row is None:
        return {}
    d = json.loads(str(row))
    d['issue_link'] = gitlab.commit_id_to_url(project_id, d['commit_id'])
    return d


def is_wie():
    wi_type = kubernetesClient.read_namespace_secret('default', 'webinspect').get('wi-type', None)
    return wi_type == 'WIE'


def wix_get_scan_status(scan_id):
    if is_wie():
        return wie_instance().get_scan_status(scan_id)
    else:
        return wi_get_scan_status(scan_id)


def wi_get_scan_status(scan_id):
    status = wi_api_get('/scanner/scans/{0}?action=GetCurrentStatus'.format(
        scan_id)).json().get('ScanStatus')
    if status == 'Complete':
        scan = model.WebInspect.query.filter_by(scan_id=scan_id).one()
        if not scan.finished:
            # This line will fill the data in db
            wi_get_scan_statistics(scan_id)
    elif status == 'NotRunning' or status == 'Interrupted' or status == 'Failed':
        wi_set_scan_failed(scan_id, status)
    return status


def wix_get_scan_statistics(scan_id):
    if is_wie():
        return wie_instance().get_scan_statistics(scan_id)
    else:
        return wi_get_scan_statistics(scan_id)


def wi_get_scan_statistics(scan_id):
    row = model.WebInspect.query.filter_by(scan_id=scan_id).one()
    if row.stats is not None:
        return json.loads(row.stats)
    ret = {0: 0, 1: 0, 2: 0, 3: 0, 4: 0, 'status': 'Complete'}
    results = wi_api_get('/scanner/scans/{0}.issue'.format(scan_id)).json()
    for r in results:
        for issue in r['issues']:
            ret[issue['severity']] += 1
    row = model.WebInspect.query.filter_by(scan_id=scan_id).one()
    row.stats = json.dumps(ret)
    row.finished = True
    db.session.commit()
    return ret


def wi_set_scan_failed(scan_id, status):
    row = model.WebInspect.query.filter_by(scan_id=scan_id).one()
    row.stats = json.dumps({'status': status})
    row.finished = True
    db.session.commit()


def wix_download_report(scan_id):
    if is_wie():
        return wie_instance().download_report(scan_id)
    else:
        return wi_download_report(scan_id)


def wix_get_report(scan_id):
    if is_wie():
        return wie_instance().get_report(scan_id)
    else:
        return wi_get_report(scan_id)


def wi_download_report(scan_id):
    xml = wi_api_get('/scanner/scans/{0}.xml?detailType=Full'.format(
        scan_id)).content
    response = make_response(xml)
    response.headers.set('Content-Type', 'application/xml')
    response.headers.set('charset', 'utf-8')
    response.headers.set(
        'Content-Disposition', 'attachment', filename='report-{0}.xml'.format(scan_id))
    return response


def wi_get_report(scan_id):
    return wi_api_get('/scanner/scans/{0}.xml?detailType=Full'.format(
        scan_id)).content


class WIE:
    def __init__(self):
        self.token = None
        self.token_made = None
        self.login()

    def login(self):
        secret = kubernetesClient.read_namespace_secret('default', 'webinspect')
        res = wi_api_post('/v1/auth', data={
            'username': secret.get('wi-username', None),
            'password': secret.get('wi-password', None)
        })
        self.token = res.json().get('data').split(' ')[1]
        self.token_made = datetime.now()

    def cookie_header(self):
        if (datetime.now() - self.token_made) > timedelta(hours=12):
            self.login()
        return {'Cookie': f'WIESession={self.token}'}

    def get_scan_status(self, scan_id):
        return wi_api_get(f'/v2/scans/{scan_id}', headers=self.cookie_header()
                          ).json().get('data').get('scanStateText', 'Error')

    def get_scan_statistics(self, scan_id):
        row = model.WebInspect.query.filter_by(scan_id=scan_id).one()
        if row.stats is not None:
            return json.loads(row.stats)
        data = wi_api_get(f'/v2/scans/{scan_id}', headers=self.cookie_header()
                          ).json().get('data')
        ret = data.get('scanStatistics')
        ret['status'] = data.get('scanStateText', 'Error')
        row = model.WebInspect.query.filter_by(scan_id=scan_id).one()
        row.stats = json.dumps(ret)
        row.finished = True
        db.session.commit()
        return ret

    def download_report(self, scan_id):
        xml = wi_api_get(f'/v2/scans/{scan_id}/export?type=xml', headers=self.cookie_header()).content
        response = make_response(xml)
        response.headers.set('Content-Type', 'application/xml')
        response.headers.set('charset', 'utf-8')
        response.headers.set(
            'Content-Disposition', 'attachment', filename='report-{0}.xml'.format(scan_id))
        return response

    def get_report(self, scan_id):
        return wi_api_get(f'/v2/scans/{scan_id}/export?type=xml', headers=self.cookie_header()).content


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
        return util.success({'status': wix_get_scan_status(scan_id)})


class WebInspectScanStatistics(Resource):
    @jwt_required
    def get(self, scan_id):
        return util.success({'severity_count': wix_get_scan_statistics(scan_id)})


class WebInspectReport(Resource):
    @jwt_required
    def get(self, scan_id):
        return wix_download_report(scan_id)
