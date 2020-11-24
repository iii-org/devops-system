from flask_jwt_extended import jwt_required
from flask_restful import Resource
from requests.auth import HTTPBasicAuth

import config
from resources import util, apiError
from resources.logger import logger


def __api_request(method, path, headers=None, params=None, data=None):
    if headers is None:
        headers = {}
    if params is None:
        params = {}
    if 'Content-Type' not in headers:
        headers['Content-Type'] = 'application/json'
    auth = HTTPBasicAuth(config.get('HARBOR_ACCOUNT'), config.get('HARBOR_PASSWORD'))
    url = "{0}{1}".format(config.get('HARBOR_BASE_URL'), path)

    output = util.api_request(method, url, headers=headers,
                              params=params, data=data, auth=auth)

    logger.info('Harbor api {0} {1}, params={2}, body={5}, response={3} {4}'.format(
        method, url, params.__str__(), output.status_code, output.text, data))
    if int(output.status_code / 100) != 2:
        raise apiError.DevOpsError(
            output.status_code,
            'Got non-2xx response from Harbor.',
            apiError.error_3rd_party_api('Harbor', output))
    return output


def __api_get(path, params=None, headers=None):
    return __api_request('GET', path, params=params, headers=headers)


def __api_post(path, params=None, headers=None, data=None):
    return __api_request('POST', path, headers=headers, data=data, params=params)


def __api_put(path, params=None, headers=None, data=None):
    return __api_request('PUT', path, headers=headers, data=data, params=params)


def __api_delete(path, params=None, headers=None):
    return __api_request('DELETE', path, params=params, headers=headers)


def hb_create_project():
    pass


class HarborProject(Resource):
    @jwt_required
    def post(self):
        pass
