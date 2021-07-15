import uuid

import config
import model
import util
from resources import kubernetesClient
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
        current_version = model.NexusVersion.query.one().deploy_version
        if current_version != versions['version_name']:
            update_deployment(versions)
    except DevOpsError as e:
        # Leave logs, but let the system run
        logger.exception(str(e))
        # FIXME
        raise e


def update_deployment(versions):
    version_name = versions['version_name']
    logger.info(f'Updating deployment to {version_name}...')
    api_image_tag = versions['api_image_tag']
    ui_image_tag = versions['ui_image_tag']

    # Update API
    dp_api = kubernetesClient.read_namespace_deployment('default', 'devopsapi')
    image_api = dp_api.spec.template.spec.containers[0].image
    parts = image_api.split(':')
    parts[-1] = api_image_tag
    dp_api.spec.template.spec.containers[0].image = ':'.join(parts)
    kubernetesClient.update_namespace_deployment('default', 'devopsapi', dp_api)

    # Update UI
    dp_ui = kubernetesClient.read_namespace_deployment('default', 'devopsui')
    image_ui = dp_ui.spec.template.spec.containers[0].image
    parts = image_ui.split(':')
    parts[-1] = ui_image_tag
    dp_ui.spec.template.spec.containers[0].image = ':'.join(parts)
    kubernetesClient.update_namespace_deployment('default', 'devopsui', dp_ui)

    # Record update done
    model.NexusVersion.query.one().deploy_version = version_name
    model.db.session.commit()
