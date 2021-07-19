import uuid

from flask_jwt_extended import jwt_required
from flask_restful import Resource

import config
import model
import util
from resources import kubernetesClient, role, apiError
from resources.apiError import DevOpsError
from resources.logger import logger

version_center_token = None


def __get_token():
    global version_center_token
    if version_center_token is None:
        _login()
    return version_center_token


def __api_request(method, path, headers=None, params=None, data=None, with_token=True, retry=False):
    if headers is None:
        headers = {}
    if params is None:
        params = {}
    if with_token:
        headers['Authorization'] = f'Bearer {__get_token()}'

    url = f'{config.get("VERSION_CENTER_BASE_URL")}{path}'
    output = util.api_request(method, url, headers, params, data)

    # Token expire
    if output.status_code == 401 and not retry:
        _login()
        return __api_request(method, path, headers, params, data, True, True)

    if int(output.status_code / 100) != 2:
        raise DevOpsError(output.status_code,
                          'Got non-2xx response from Version center.',
                          error=apiError.error_3rd_party_api('Version Center', output))
    return output


def __api_get(path, params=None, headers=None, with_token=True):
    return __api_request('GET', path, params=params, headers=headers, with_token=with_token)


def __api_post(path, params=None, headers=None, data=None, with_token=True):
    return __api_request('POST', path, headers=headers, data=data, params=params, with_token=with_token)


def __api_put(path, params=None, headers=None, data=None, with_token=True):
    return __api_request('PUT', path, headers=headers, data=data, params=params, with_token=with_token)


def __api_delete(path, params=None, headers=None, with_token=True):
    return __api_request('DELETE', path, params=params, headers=headers, with_token=with_token)


def _login():
    global version_center_token
    dp_uuid = model.NexusVersion.query.one().deployment_uuid
    res = __api_post('/login', params={'uuid': dp_uuid, 'name': 'Test deployment'}, with_token=False)
    version_center_token = res.json().get('data', {}).get('access_token', None)


def set_deployment_uuid():
    my_uuid = uuid.uuid1()
    row = model.NexusVersion.query.first()
    row.deployment_uuid = my_uuid
    model.db.session.commit()


def has_devops_update():
    versions = __api_get('/current_version').json().get('data', None)
    if versions is None:
        raise DevOpsError(500, '/current_version returns no data.')
    current_version = model.NexusVersion.query.one().deploy_version
    return {
        'has_update': current_version != versions['version_name'],
        'latest_version': versions
    }


def update_deployment(versions):
    version_name = versions['version_name']
    logger.info(f'Updating deployment to {version_name}...')
    api_image_tag = versions['api_image_tag']
    ui_image_tag = versions['ui_image_tag']
    kubernetesClient.update_deployment_image_tag('default', 'devopsapi', api_image_tag)
    kubernetesClient.update_deployment_image_tag('default', 'devopsui', ui_image_tag)
    # Record update done
    model.NexusVersion.query.one().deploy_version = version_name
    model.db.session.commit()
    __api_post('/report_update', data={'version_name': version_name})


# ------------------ Resources ------------------
class DevOpsVersionCheck(Resource):
    @jwt_required
    def get(self):
        role.require_admin()
        return util.success(has_devops_update())


class DevOpsVersionUpdate(Resource):
    @jwt_required
    def patch(self):
        role.require_admin()
        versions = has_devops_update()['latest_version']
        update_deployment(versions)
        return util.success(versions)
