import re

from flask_jwt_extended import jwt_required
from flask_restful import Resource, reqparse
from requests.auth import HTTPBasicAuth

import config
import model
from resources import apiError, role
import util
from resources.apiError import DevOpsError
from resources.logger import logger


# API bridge methods

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
                              error=apiError.identifier_has_been_token(project_name))
        else:
            raise e
    return hb_get_id_by_name(project_name)


def hb_delete_project(project_id):
    try:
        __api_delete('/projects/{0}'.format(project_id))
    except DevOpsError as e:
        if e.status_code == 404:
            # Deleting a not existing project, let it go
            pass
        else:
            raise e


def hb_create_user():
    pass


def hb_delete_user():
    pass


def hb_add_member():
    pass


def hb_remove_member():
    pass


def hb_list_repositories(project_name):
    return __api_get('/projects/{0}/repositories'.format(project_name)).json()


def hb_list_artifacts(project_name, repository_name):
    artifacts = __api_get('/projects/{0}/repositories/{1}/artifacts'.format(
        project_name, repository_name), params={'with_scan_overview': True}).json()
    ret = []
    for art in artifacts:
        scan = next(iter(art['scan_overview'].values()))
        if scan is None:
            vul = ''
        else:
            vul = '{0} ({1})'.format(scan['severity'], scan['summary']['total'])
        for tag in art['tags']:
            ret.append({
                'artifact_id': art['id'],
                'tag_id': tag['id'],
                'name': tag['name'],
                'size': art['size'],
                'vulnerabilities': vul,
                'digest': art['digest'][7:15],
                'labels': art['labels'],
                'push_time': art['push_time']
            })
    return ret


def hb_update_repository(project_name, repository_name, args):
    return __api_put('/projects/{0}/repositories/{1}'.format(
        project_name, repository_name),
        data={'description': args['description']})


def hb_delete_repository(project_name, repository_name):
    return __api_delete('/projects/{0}/repositories/{1}'.format(
        project_name, repository_name))


def hb_delete_artifact_tag(project_name, repository_name, reference, tag_name):
    return __api_delete('/projects/{0}/repositories/{1}/artifacts/{2}/tags/{3}'.format(
        project_name, repository_name, reference, tag_name))


# ----------------- Resources -----------------
class HarborProject(Resource):
    @jwt_required
    def post(self):
        role.require_pm()
        parser = reqparse.RequestParser()
        parser.add_argument('name', type=str)
        args = parser.parse_args()

        pattern = "^[a-z0-9][a-z0-9-]{0,253}[a-z0-9]$"
        result = re.fullmatch(pattern, args['name'])
        if result is None:
            return util.respond(400, 'Error while creating project',
                                error=apiError.invalid_project_name(args['name']))
        pid = hb_create_project(args['name'])
        return util.success({'harbor_project_id': pid})

    @jwt_required
    def delete(self, harbor_project_id):
        role.require_pm()
        hb_delete_project(harbor_project_id)
        return util.success()


class HarborRepository(Resource):
    @staticmethod
    def preprocess():
        parser = reqparse.RequestParser()
        parser.add_argument('name', type=str)
        args = parser.parse_args()

        names = args['name'].split('/')
        project_name = names[0]
        repository_name = names[1]
        try:
            pjt = model.Project.query.filter_by(name=project_name).one()
        except DevOpsError:
            return util.respond(404, 'Project not found.',
                                error=apiError.project_not_found(project_name))
        project_id = pjt.id
        role.require_in_project(project_id)
        return project_name, repository_name

    @jwt_required
    def get(self, project_id):
        role.require_in_project(project_id)
        try:
            pjt = model.Project.query.filter_by(id=project_id).one()
        except DevOpsError:
            return util.respond(404, 'Project not found.',
                                error=apiError.project_not_found(project_id))
        project_name = pjt.name
        return util.success(hb_list_repositories(project_name))

    @jwt_required
    def put(self):
        parser = reqparse.RequestParser()
        parser.add_argument('description', type=str)
        args = parser.parse_args()
        project_name, repository_name = self.preprocess()
        hb_update_repository(project_name, repository_name, args)
        return util.success()

    @jwt_required
    def delete(self):
        project_name, repository_name = self.preprocess()
        hb_delete_repository(project_name, repository_name)
        return util.success()


class HarborArtifact(Resource):
    @jwt_required
    def get(self, project_name, repository_name):
        return util.success(hb_list_artifacts(project_name, repository_name))

    @jwt_required
    def delete(self):
        parser = reqparse.RequestParser()
        parser.add_argument('digest', type=str)
        parser.add_argument('tag_name', type=str)
        args = parser.parse_args()
        project_name, repository_name = self.preprocess()
        hb_delete_artifact_tag(project_name, repository_name, args['digest'], args['tag_name'])
        return util.success()
