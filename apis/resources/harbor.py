from urllib.parse import quote

from flask_jwt_extended import jwt_required, get_jwt_identity
from flask_restful import Resource, reqparse
from requests.auth import HTTPBasicAuth

import config
import nexus
import util
import re
import json
import model
from resources import apiError, role
from resources.apiError import DevOpsError
from resources.logger import logger

HAR_PASS_REG = '((?=.*\d)(?=.*[a-z])(?=.*[A-Z])).{8,20}$'
DEFAULT_PASSWORD = 'IIIdevops_12345'


def check_passsword(password):
    return bool(re.match(HAR_PASS_REG, password))


# API bridge methods
def __api_request(method, path, headers=None, params=None, data=None):
    if headers is None:
        headers = {}
    if params is None:
        params = {}
    if 'Content-Type' not in headers:
        headers['Content-Type'] = 'application/json'
    auth = HTTPBasicAuth(config.get('HARBOR_ACCOUNT'), config.get('HARBOR_PASSWORD'))
    url = "{0}{1}".format(config.get('HARBOR_INTERNAL_BASE_URL'), path)

    output = util.api_request(method, url, headers=headers,
                              params=params, data=data, auth=auth)

    logger.info('Harbor api {0} {1}, params={2}, body={5}, response={3} {4}'.format(
        method, url, params.__str__(), output.status_code, output.text, data))
    if int(output.status_code / 100) != 2:
        raise DevOpsError(
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


def __encode(repository_name):
    return quote(quote(repository_name, safe=""))


# Regular methods
def hb_get_id_by_name(project_name):
    projects = __api_get('/projects', params={'name': project_name}).json()
    if len(projects) == 0:
        raise DevOpsError(404, 'Harbor does not have such project.',
                          error=apiError.project_not_found(project_name))
    return projects[0]['project_id']


def hb_create_project(project_name):
    data = {
        'project_name': project_name,
        'cve_whitelist': {
            'items': [{'cve_id': 'string'}]
        },
        'storage_limit': 10737418240,
        'metadata': {
            'enable_content_trust': 'string',
            'auto_scan': 'true',
            'severity': 'string',
            'reuse_sys_cve_whitelist': 'string',
            'public': 'false',
            'prevent_vul': 'string'
        },
        'public': False
    }
    try:
        __api_post('/projects', data=data)
    except DevOpsError as e:
        if e.unpack_response()['errors'][0]['code'] == 'CONFLICT':
            raise DevOpsError(422, 'Harbor already has a project using this name.',
                              error=apiError.identifier_has_been_taken(project_name))
        else:
            raise e
    return hb_get_id_by_name(project_name)


def hb_delete_project(harbor_param):
    try:
        repositoriest = hb_list_repositories(harbor_param[1])
        if len(repositoriest) != 0:
            for repository in repositoriest:
                split_list = repository["name"].split("/")
                project_name = split_list[0]
                repository_name = '/'.join(split_list[1:])
                hb_delete_repository(project_name, repository_name)
        __api_delete('/projects/{0}'.format(harbor_param[0]))
    except DevOpsError as e:
        if e.status_code in [404, 403]:
            # 404: Deleting a not existing project , let it go
            # 403: list not existing repositories, let it go
            pass
        else:
            raise e


def hb_create_user(args, is_admin=False):
    login = args['login']
    pass_quality = check_passsword(args['password'])
    harbor_password = args['password']
    if pass_quality is False:
        harbor_password = DEFAULT_PASSWORD
    data = {
        "username": login,
        "password": harbor_password,
        "realname": args['name'],
        "email": args['email']
    }
    if is_admin:
        data['sysadmin_flag'] = True
    __api_post('/users', data=data)
    res = __api_get('/users/search', params={'username': login}).json()
    return res[0]['user_id']


def hb_delete_user(user_id):
    __api_delete('/users/{0}'.format(user_id))


def hb_update_user_password(user_id, new_pwd, old_pwd):
    pass_quality = check_passsword(new_pwd)
    if pass_quality is False:
        new_pwd = DEFAULT_PASSWORD
    data = {
        "new_password": new_pwd,
        "old_password": old_pwd
    }
    try:
        __api_put(f'/users/{user_id}/password', data=data)
    except DevOpsError as e:
        if e.status_code == 400 and \
                e.error_value['details']['response']['errors'][0][
                    'message'] == 'the new password can not be same with the old one':
            pass
        else:
            raise e


def hb_update_user_email(user_id, user_name, new_email):
    data = {
        'email': new_email,
        'realname': user_name
    }
    try:
        __api_put(f'/users/{user_id}', data=data)
    except DevOpsError as e:
        if e.status_code == 400 and \
                e.error_value['details']['response']['errors'][0][
                    'message'] == 'the new password can not be same with the old one':
            pass
        else:
            raise e


def hb_add_member(project_id, user_id):
    data = {
        "role_id": 1,
        "member_user": {
            "user_id": user_id
        }
    }
    __api_post('/projects/{0}/members'.format(project_id), data=data)


def hb_remove_member(project_id, user_id):
    members = __api_get('/projects/{0}/members'.format(project_id)).json()
    member_id = None
    for member in members:
        if member['entity_id'] == user_id:
            member_id = member['id']
            break
    if member_id is None:
        raise DevOpsError(404, 'User is not in the project.',
                          error=apiError.user_not_found(user_id))
    __api_delete('/projects/{0}/members/{1}'.format(project_id, member_id))


def hb_list_repositories(project_name):
    repositories = __api_get('/projects/{0}/repositories'.format(project_name)).json()
    ret = []
    for repo in repositories:
        repo['harbor_link'] = hb_build_external_link('/harbor/projects/{0}/repositories/{1}'.format(
            repo['project_id'],
            repo['name'].replace((project_name + "/"), "")))
        ret.append(repo)
    return ret


def hb_list_artifacts(project_name, repository_name):
    artifacts = __api_get(f'/projects/{project_name}/repositories'
                          f'/{__encode(repository_name)}/artifacts',
                          params={'with_scan_overview': True}).json()
    ret = []
    for art in artifacts:
        scan = next(iter(art['scan_overview'].values()))
        if (scan is None) or ('summary' not in scan) or ('total' not in scan['summary']):
            vul = ''
        else:
            vul = '{0} ({1})'.format(scan['severity'], scan['summary']['total'])
        if 'tags' in art and art['tags'] is not None:
            for tag in art['tags']:
                ret.append({
                    'artifact_id': art['id'],
                    'tag_id': tag['id'],
                    'name': tag['name'],
                    'size': art['size'],
                    'vulnerabilities': vul,
                    'digest': art['digest'],
                    'labels': art['labels'],
                    'push_time': art['push_time']
                })
        else:
            ret.append({
                'artifact_id': art['id'],
                'tag_id': '',
                'name': '',
                'size': art['size'],
                'vulnerabilities': vul,
                'digest': art['digest'],
                'labels': art['labels'],
                'push_time': art['push_time']
            })
    return ret


def hb_check_tags(project_name, repository_name, tag_name):
    return {}


def hb_get_repository_info(project_name, repository_name):
    return __api_get(f'/projects/{project_name}/repositories/{__encode(repository_name)}').json()


def hb_update_repository(project_name, repository_name, args):
    return __api_put(f'/projects/{project_name}/repositories/{__encode(repository_name)}',
                     data={'description': args['description']})


def hb_delete_repository(project_name, repository_name):
    return __api_delete(f'/projects/{project_name}/repositories/{__encode(repository_name)}')


def hb_delete_artifact(project_name, repository_name, reference):
    return __api_delete(f'/projects/{project_name}/repositories/{__encode(repository_name)}'
                        f'/artifacts/{reference}')


def hb_list_tags(project_name, repository_name, reference):
    return __api_get(f'/projects/{project_name}/repositories/{__encode(repository_name)}'
                     f'/artifacts/{reference}/tags').json()


def hb_create_artifact_tag(project_name, repository_name, reference, tag_name):
    return __api_post(f'/projects/{project_name}/repositories/{__encode(repository_name)}'
                      f'/artifacts/{reference}/tags', data={'name': tag_name})


def hb_delete_artifact_tag(project_name, repository_name, reference, tag_name):
    __api_delete(f'/projects/{project_name}/repositories/{__encode(repository_name)}'
                 f'/artifacts/{reference}/tags/{tag_name}')
    if len(hb_list_tags(project_name, repository_name, reference)) == 0:
        hb_delete_artifact(project_name, repository_name, reference)


def hb_get_project_summary(project_id):
    return __api_get('/projects/{0}/summary'.format(project_id)).json()


def hb_build_external_link(path):
    return f"{config.get('HARBOR_EXTERNAL_BASE_URL')}{path}"


def get_storage_usage(project_id):
    habor_info = hb_get_project_summary(project_id)
    usage_info = {}
    usage_info['title'] = 'Harbor'
    usage_info['used'] = {}
    usage_info['used']['value'] = habor_info['quota']['used']['storage']
    usage_info['used']['unit'] = ''
    usage_info['quota'] = {}
    usage_info['quota']['value'] = habor_info['quota']['hard']['storage']
    usage_info['quota']['unit'] = ''
    return usage_info


def hb_get_registries(registry_id=None, args=None):
    if registry_id:
        response = __api_get('/registries/{0}'.format(registry_id))
    if args:
        response = __api_get('/registries?q={0}'.format(args))
    registry = json.loads(response.content.decode('utf8'))
    return registry


def hb_create_registries(args):
    user_id = get_jwt_identity()['user_id']
    if args['type'] == 'aws-ecr':
        args['insecure'] = False
        args['url'] = 'https://api.ecr.{location}.amazonaws.com'.format(location=args['location'])
    elif args['type'] == 'azure-acr':
        args['insecure'] = False
        args['url'] = 'https://{login_server}'.format(login_server=args['login_server'])
    __api_post('/registries/ping', data=args)
    args['credential'] = {
        'access_key': args['access_key'],
        'access_secret': args['access_secret'],
        'type': 'basic'
    }
    __api_post('/registries', data=args)
    registries_id = hb_get_registries(args='name={0}'.format(args['name']))[0].get('id')
    new_registries = model.Registries(
        registries_id=registries_id,
        name=args['name'],
        user_id=user_id,
        description=args['description'],
        access_key=args['access_key'],
        access_secret=args['access_secret'],
        url=args['url'],
        type=args['type']
    )
    model.db.session.add(new_registries)
    model.db.session.commit()


def hb_create_replication_policy(args):
    dest_registry = hb_get_registries(registry_id=args['registry_id'])
    data = {
        "name": args['name'],
        "description": args['description'],
        "dest_registry": dest_registry,
        "trigger": {
            "type": "manual",
            "trigger_settings": {"cron": ""}
            },
        "enabled": True,
        "deletion": False,
        "override": True,
        "filters": [
            {
                "type": "name",
                "value": args['image_name']
            },
            {
                "type": "resource",
                "value": "image"
            }
        ]
    }
    __api_post('/replication/policies', data=data)


def hb_execute_replication_policy(args):
    data = {"policy_id": args['policy_id']}
    __api_post('/replication/executions', data=data)


def hb_ping_registries(args):
    data = {"id": args['registries_id']}
    __api_post('/registries/ping', data=data)


# ----------------- Resources -----------------
def extract_names():
    parser = reqparse.RequestParser()
    parser.add_argument('repository_fullname', type=str)
    args = parser.parse_args()
    name = args['repository_fullname']
    names = name.split('/')
    return names[0], '/'.join(names[1:])


class HarborRepository(Resource):
    @jwt_required
    def get(self, nexus_project_id):
        role.require_in_project(nexus_project_id)
        project_name = nexus.nx_get_project(id=nexus_project_id).name
        return util.success(hb_list_repositories(project_name))

    @jwt_required
    def put(self):
        project_name, repository_name = extract_names()
        role.require_in_project(project_name=project_name)
        parser = reqparse.RequestParser()
        parser.add_argument('description', type=str)
        args = parser.parse_args()
        hb_update_repository(project_name, repository_name, args)
        return util.success()

    @jwt_required
    def delete(self):
        project_name, repository_name = extract_names()
        role.require_in_project(project_name=project_name)
        hb_delete_repository(project_name, repository_name)
        return util.success()


class HarborArtifact(Resource):
    @jwt_required
    def get(self):
        project_name, repository_name = extract_names()
        return util.success(hb_list_artifacts(project_name, repository_name))

    @jwt_required
    def delete(self):
        project_name, repository_name = extract_names()
        role.require_in_project(project_name=project_name)
        parser = reqparse.RequestParser()
        parser.add_argument('digest', type=str)
        parser.add_argument('tag_name', type=str)
        args = parser.parse_args()
        hb_delete_artifact_tag(project_name, repository_name, args['digest'], args['tag_name'])
        return util.success()


class HarborProject(Resource):
    @jwt_required
    def get(self, nexus_project_id):
        role.require_in_project(nexus_project_id)
        project_id = nexus.nx_get_project_plugin_relation(nexus_project_id=nexus_project_id).harbor_project_id
        return util.success(hb_get_project_summary(project_id))


class HarborRelease():
    @jwt_required
    def get_list_artifacts(self, project_name, repository_name):
        return hb_list_artifacts(project_name, repository_name)

    def check_harbor_release(self, artifacts, tag_name):
        output = {'check': False, "info": "", "target": {}, "errors": {}}
        if len(artifacts) > 0:
            output['check'] = True
            output['target'] = artifacts[0]
        for art in artifacts:
            if art['name'] == tag_name:
                output['check'] = False
                output['info'] = '{0} is exists in harbor'.format(tag_name)
                output['errors'] = art
        return output

    def create(self, project_name, repository_name, reference, tag_name):
        return hb_create_artifact_tag(project_name, repository_name, reference, tag_name)

    def delete_harbor_tag(self, project_name, repository_name, hb_info):
        return hb_delete_artifact_tag(project_name, repository_name, hb_info['digest'], hb_info['name'])


hb_release = HarborRelease()


class HarborRegistries(Resource):
    @jwt_required
    def post(self):
        parser = reqparse.RequestParser()
        parser.add_argument('name', type=str, required=True)
        parser.add_argument('type', type=str, required=True)
        parser.add_argument('access_key', type=str, required=True)
        parser.add_argument('access_secret', type=str, required=True)
        parser.add_argument('location', type=str, required=False)
        parser.add_argument('login_server', type=str, required=False)
        parser.add_argument('description', type=str)
        args = parser.parse_args()
        hb_create_registries(args)
        return util.success()


class HarborRegistriesPing(Resource):
    @jwt_required
    def post(self):
        parser = reqparse.RequestParser()
        parser.add_argument('registries_id', type=str, required=True)
        args = parser.parse_args()
        hb_create_replication_policy(args)
        return util.success()


class HarborReplicationPolicy(Resource):
    @jwt_required
    def post(self):
        parser = reqparse.RequestParser()
        parser.add_argument('name', type=str)
        parser.add_argument('image_name', type=str)
        parser.add_argument('registry_id', type=int)
        parser.add_argument('description', type=str)
        args = parser.parse_args()
        hb_create_replication_policy(args)
        return util.success()


class HarborReplicationExecution(Resource):
    @jwt_required
    def post(self):
        parser = reqparse.RequestParser()
        parser.add_argument('policy_id', type=int)
        args = parser.parse_args()
        hb_execute_replication_policy(args)
        return util.success()
