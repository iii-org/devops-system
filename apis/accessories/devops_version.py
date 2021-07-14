import uuid

import config
import model
import util
from resources.apiError import DevOpsError
from resources.logger import logger

version_center_token = None


def __get_token():
    global version_center_token
    if version_center_token is None:
        _login()
    return version_center_token


def __api_request(method, path, headers=None, params=None, data=None, with_token=True):
    if headers is None:
        headers = {}
    if params is None:
        params = {}
    if with_token:
        headers['Authorization'] = f'Bearer {__get_token()}'

    url = f'{config.get("VERSION_CENTER_BASE_URL")}{path}'
    output = util.api_request(method, url, headers, params, data)

    if int(output.status_code / 100) != 2:
        raise DevOpsError(output.status_code,
                          'Got non-2xx response from Version center.')
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


def check_deployment_version():
    try:
        versions = __api_get('/current_version').json().get('data', None)
        if versions is None:
            raise DevOpsError(500, '/current_version returns no data.')
        print(versions)
    except DevOpsError as e:
        # Leave logs, but let the system run
        logger.exception(str(e))
