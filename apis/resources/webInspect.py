from datetime import datetime

from flask_jwt_extended import jwt_required
from flask_restful import Resource, reqparse

import config
import model
import util
from model import db
# -------- API methods --------
from resources import apiError
from resources.logger import logger


def __api_request(self, method, path, headers=None, params=None, data=None):
    if headers is None:
        headers = {}
    if params is None:
        params = {}
    if 'Content-Type' not in headers:
        headers['Content-Type'] = 'application/json'

    url = "http://{0}{1}".format(config.get('WEBINSPECT_BASE_URL'), path)
    params['key'] = self.redmine_key

    output = util.api_request(method, url, headers, params, data)

    logger.info('WebInspect api {0} {1}, params={2}, body={5}, response={3} {4}'.format(
        method, url, params.__str__(), output.status_code, output.text, data))
    if int(output.status_code / 100) != 2:
        raise apiError.DevOpsError(
            output.status_code,
            'Got non-2xx response from WebInspect.',
            apiError.error_3rd_party_api('WebInspect', output))
    return output


def __api_get(self, path, params=None, headers=None):
    return self.__api_request('GET', path, params=params, headers=headers)


def __api_post(self, path, params=None, headers=None, data=None, ):
    return self.__api_request('POST', path, headers=headers, data=data, params=params)


# -------------- Regular methods --------------
def create_scan(args):
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
        return util.success(create_scan(args))
