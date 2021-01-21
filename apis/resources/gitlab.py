import json

import requests
from flask_jwt_extended import jwt_required
from flask_restful import Resource, reqparse
from sqlalchemy.orm.exc import NoResultFound

import config
import model
import nexus
import util as util
from resources import apiError, kubernetesClient, role
from resources.apiError import DevOpsError
from resources.logger import logger


def get_nexus_project_id(repo_id):
    row = model.ProjectPluginRelation.query.filter_by(git_repository_id=repo_id).first()
    if row:
        return row.project_id
    else:
        return -1


def get_repo_url(project_id):
    row = model.Project.query.filter_by(id=project_id).one()
    return row.http_url


def commit_id_to_url(project_id, commit_id):
    return f'{get_repo_url(project_id)[0:-4]}/-/commit/{commit_id}'


class GitLab(object):
    private_token = None

    def __init__(self):
        if config.get("GITLAB_API_VERSION") == "v3":
            # get gitlab admin token
            url = f'{config.get("GITLAB_BASE_URL")}/api/v3/session'
            param = {
                "login": config.get("GITLAB_ADMIN_ACCOUNT"),
                "password": config.get("GITLAB_ADMIN_PASSWORD")
            }
            output = requests.post(url,
                                   data=json.dumps(param),
                                   headers={'Content-Type': 'application/json'},
                                   verify=False)
            self.private_token = output.json()['private_token']
        else:
            self.private_token = config.get("GITLAB_PRIVATE_TOKEN")

    @staticmethod
    def gl_get_nexus_project_id(repository_id):
        project_id = get_nexus_project_id(repository_id)
        if project_id > 0:
            return util.success(project_id)
        else:
            raise DevOpsError(404, "Error when getting project id.",
                              error=apiError.repository_id_not_found(repository_id))

    @staticmethod
    def gl_get_project_id_from_url(repository_url):
        row = model.Project.query.filter_by(http_url=repository_url).one()
        project_id = row.id
        repository_id = get_repository_id(project_id)
        return {
            'project_id': project_id,
            'repository_id': repository_id
        }

    def __api_request(self, method, path, headers=None, params=None, data=None):
        if headers is None:
            headers = {}
        if params is None:
            params = {}
        if 'Content-Type' not in headers:
            headers['Content-Type'] = 'application/json'

        url = f'{config.get("GITLAB_BASE_URL")}/api/' \
              f'{config.get("GITLAB_API_VERSION")}{path}' \
              f'?private_token={self.private_token}'

        output = util.api_request(method, url, headers, params, data)

        logger.info('gitlab api {0} {1}, params={2}, body={5}, response={3} {4}'.format(
            method, url, params.__str__(), output.status_code, output.text, data))
        if int(output.status_code / 100) != 2:
            raise apiError.DevOpsError(
                output.status_code,
                'Got non-2xx response from Gitlab.',
                apiError.gitlab_error(output))
        return output

    def __api_get(self, path, params=None, headers=None):
        return self.__api_request('GET', path, params=params, headers=headers)

    def __api_post(self, path, params=None, headers=None, data=None):
        return self.__api_request('POST', path, headers=headers, data=data, params=params)

    def __api_put(self, path, params=None, headers=None, data=None):
        return self.__api_request('PUT', path, headers=headers, data=data, params=params)

    def __api_delete(self, path, params=None, headers=None):
        return self.__api_request('DELETE', path, params=params, headers=headers)

    def gl_create_project(self, args):
        return self.__api_post('/projects', params={
            'name': args["name"],
            'description': args["description"]
        }).json()

    def gl_get_project(self, repo_id):
        return self.__api_get('/projects/{0}'.format(repo_id)).json()

    def gl_update_project(self, repo_id, description):
        params = {'description': description}
        return self.__api_put('/projects/{0}'.format(repo_id), params=params)

    def gl_delete_project(self, repo_id):
        return self.__api_delete('/projects/{0}'.format(repo_id))

    def gl_create_user(self, args, user_source_password, is_admin=False):
        data = {
            "name": args['name'],
            "email": args['email'],
            "username": args['login'],
            "password": user_source_password,
            "skip_confirmation": True
        }
        if is_admin:
            data['admin'] = True
        return self.__api_post('/users', data=data).json()

    def gl_update_password(self, repository_user_id, new_pwd):
        return self.__api_put('/users/{0}'.format(repository_user_id),
                              params={"password": new_pwd})

    def gl_get_user_list(self, args):
        return self.__api_get('/users', params=args)

    def gl_project_add_member(self, project_id, user_id):
        params = {
            "user_id": user_id,
            "access_level": 40,
        }
        return self.__api_post('/projects/{0}/members'.format(project_id),
                               params=params)

    def gl_project_delete_member(self, project_id, user_id):
        return self.__api_delete('/projects/{0}/members/{1}'.format(
            project_id, user_id))

    def gl_delete_user(self, gitlab_user_id):
        return self.__api_delete('/users/{0}'.format(gitlab_user_id))

    def gl_count_branches(self, repo_id):
        output = self.__api_get('/projects/{0}/repository/branches'.format(repo_id))
        return len(output.json())

    def gl_get_tags(self, repo_id):
        return self.__api_get('/projects/{0}/repository/tags'.format(repo_id)).json()

    def gl_create_rancher_pipeline_yaml(self, repo_id, args, method):
        path = '/projects/{0}/repository/files/{1}'.format(repo_id, args["file_path"])
        params = {}
        for key in ['branch', 'start_branch', 'encoding', 'author_email',
                    'author_name', 'content', 'commit_message']:
            params[key] = args[key]
        return self.__api_request(method, path, params=params)

    def gl_get_project_file_for_pipeline(self, project_id, args):
        return self.__api_get('/projects/{0}/repository/files/{1}'.format(
            project_id, args["file_path"]
        ), params={'ref': args["branch"]})

    def gl_get_branches(self, repo_id):
        output = self.__api_get('/projects/{0}/repository/branches'.format(repo_id))
        if output.status_code != 200:
            raise DevOpsError(output.status_code, "Error while getting git branches",
                              error=apiError.gitlab_error(output))
        # get gitlab project path
        project_detail = self.gl_get_project(repo_id)
        # get kubernetes service nodePort url
        k8s_service_list = kubernetesClient.list_service_all_namespaces()
        k8s_node_list = kubernetesClient.list_work_node()
        work_node_ip = k8s_node_list[0]['ip']

        branch_list = []
        for branch_info in output.json():
            env_url_list = []
            for k8s_service in k8s_service_list:
                if k8s_service['type'] == 'NodePort' and \
                        "{0}-{1}".format(project_detail['path'], branch_info["name"]) \
                        in k8s_service['name']:
                    port_list = []
                    for port in k8s_service['ports']:
                        port_list.append(
                            {"port": port['port'], "url": "http://{0}:{1}".format(work_node_ip, port['nodePort'])})
                    env_url_list.append({k8s_service['name']: port_list})
            branch = {
                "name": branch_info["name"],
                "last_commit_message": branch_info["commit"]["message"],
                "last_commit_time":
                    branch_info["commit"]["committed_date"],
                "short_id": branch_info["commit"]["short_id"][0:7],
                'commit_url': commit_id_to_url(
                    get_nexus_project_id(repo_id),
                    branch_info['commit']['short_id']),
                "env_url": env_url_list
            }
            branch_list.append(branch)
        return branch_list

    def gl_create_branch(self, repo_id, args):
        output = self.__api_post('/projects/{0}/repository/branches'.format(repo_id),
                                 params={'branch': args['branch'], 'ref': args['ref']})
        return output.json()

    def gl_get_branch(self, repo_id, branch):
        output = self.__api_get('/projects/{0}/repository/branches/{1}'.format(
            repo_id, branch))
        return output.json()

    def gl_delete_branch(self, project_id, branch):
        output = self.__api_delete('/projects/{0}/repository/branches/{1}'.format(
            project_id, branch))
        return output

    def gl_get_repository_tree(self, repo_id, branch):
        output = self.__api_get('/projects/{0}/repository/tree'.format(repo_id),
                                params={'ref': branch})
        return {"file_list": output.json()}

    def __edit_file_exec(self, method, repo_id, args):
        path = '/projects/{0}/repository/files/{1}'.format(repo_id, args['file_path'])
        params = {}
        keys = ['branch', 'start_branch', 'encoding', 'author_email', 'author_name',
                'content', 'commit_message']
        for k in keys:
            params[k] = args[k]

        if method.upper() == 'POST':
            output = self.__api_post(path, params=params)
        elif method.upper() == 'PUT':
            output = self.__api_put(path, params=params)
        else:
            raise DevOpsError(500, 'Only accept POST and PUT.',
                              error=apiError.invalid_code_path('Only PUT and POST is allowed, but'
                                                               '{0} provided.'.format(method)))

        if output.status_code == 201:
            return util.success({
                "file_path": output.json()["file_path"],
                "branch_name": output.json()["branch"]})
        else:
            raise DevOpsError(output.status_code, "Error when adding gitlab file.",
                              error=apiError.gitlab_error(output))

    def gl_add_file(self, repo_id, args):
        return self.__edit_file_exec('POST', repo_id, args)

    def gl_update_file(self, repo_id, args):
        return self.__edit_file_exec('PUT', repo_id, args)

    def gl_get_file(self, repo_id, branch, file_path):
        output = self.__api_get('/projects/{0}/repository/files/{1}'.format(
            repo_id, file_path
        ), params={'ref': branch})
        return util.success({
            "file_name": output.json()["file_name"],
            "file_path": output.json()["file_path"],
            "size": output.json()["size"],
            "encoding": output.json()["encoding"],
            "content": output.json()["content"],
            "content_sha256": output.json()["content_sha256"],
            "ref": output.json()["ref"],
            "last_commit_id": output.json()["last_commit_id"]
        })

    def gl_delete_file(self, repo_id, branch, file_path, args):
        return self.__api_delete('/projects/{0}/repository/files/{1}'.format(
            repo_id, file_path), params={
            'branch': branch,
            'commit_message': args['commit_message']
        })

    def gl_create_tag(self, repo_id, args):
        path = '/projects/{0}/repository/tags'.format(repo_id)
        params = {}
        keys = ['tag_name', 'ref', 'message', 'release_description']
        for k in keys:
            params[k] = args[k]
        return self.__api_post(path, params=params).json()

    def gl_delete_tag(self, repo_id, tag_name):
        return self.__api_delete('/projects/{0}/repository/tags/{1}'.format(
            repo_id, tag_name))

    def gl_get_commits(self, project_id, branch):
        return self.__api_get('/projects/{0}/repository/commits'.format(project_id),
                              params={'ref_name': branch, 'per_page': 100}).json()

    # 用project_id查詢project的網路圖
    def gl_get_network(self, repo_id):
        branch_commit_list = []

        # 整理各branches的commit_list
        branches = self.gl_get_branches(repo_id)
        for branch in branches:
            branch_commits = self.gl_get_commits(repo_id, branch["name"])
            for branch_commit in branch_commits:
                obj = {
                    "id": branch_commit["id"],
                    "title": branch_commit["title"],
                    "message": branch_commit["message"],
                    "author_name": branch_commit["author_name"],
                    "committed_date": branch_commit["committed_date"],
                    "parent_ids": branch_commit["parent_ids"],
                    "branch_name": branch["name"],
                    "tags": []
                }
                branch_commit_list.append(obj)

        # 整理tags
        tags = gitlab.gl_get_tags(repo_id)
        for tag in tags:
            for commit in branch_commit_list:
                if commit["id"] == tag["commit"]["id"]:
                    commit["tags"].append(tag["name"])

        data_by_time = sorted(branch_commit_list,
                              reverse=False,
                              key=lambda c_list: c_list["committed_date"])

        return util.success(data_by_time)


# May throws NoResultFound
def get_repository_id(project_id):
    return model.ProjectPluginRelation.query.filter_by(
        project_id=project_id).one().git_repository_id


# --------------------- Resources ---------------------
gitlab = GitLab()


class GitProjectBranches(Resource):
    @jwt_required
    def get(self, repository_id):
        return util.success({'branch_list': gitlab.gl_get_branches(repository_id)})

    @jwt_required
    def post(self, repository_id):
        parser = reqparse.RequestParser()
        parser.add_argument('branch', type=str, required=True)
        parser.add_argument('ref', type=str, required=True)
        args = parser.parse_args()
        return util.success(gitlab.gl_create_branch(repository_id, args))


class GitProjectBranch(Resource):
    @jwt_required
    def get(self, repository_id, branch_name):
        project_id = get_nexus_project_id(repository_id)
        role.require_in_project(project_id)
        return util.success(gitlab.gl_get_branch(repository_id, branch_name))

    @jwt_required
    def delete(self, repository_id, branch_name):
        project_id = get_nexus_project_id(repository_id)
        role.require_in_project(project_id)
        gitlab.gl_delete_branch(repository_id, branch_name)
        return util.success()


class GitProjectRepositories(Resource):
    @jwt_required
    def get(self, repository_id, branch_name):
        project_id = get_nexus_project_id(repository_id)
        role.require_in_project(project_id)
        return util.success(
            gitlab.gl_get_repository_tree(repository_id, branch_name))


class GitProjectFile(Resource):
    @jwt_required
    def post(self, repository_id):
        project_id = get_nexus_project_id(repository_id)
        role.require_in_project(project_id)
        parser = reqparse.RequestParser()
        parser.add_argument('branch', type=str, required=True)
        parser.add_argument('file_path', type=str, required=True)
        parser.add_argument('start_branch', type=str)
        parser.add_argument('author_email', type=str)
        parser.add_argument('author_name', type=str)
        parser.add_argument('encoding', type=str)
        parser.add_argument('content', type=str, required=True)
        parser.add_argument('commit_message', type=str, required=True)
        args = parser.parse_args()
        return gitlab.gl_add_file(repository_id, args)

    @jwt_required
    def put(self, repository_id):
        project_id = get_nexus_project_id(repository_id)
        role.require_in_project(project_id)
        parser = reqparse.RequestParser()
        parser.add_argument('branch', type=str, required=True)
        parser.add_argument('file_path', type=str, required=True)
        parser.add_argument('start_branch', type=str)
        parser.add_argument('author_email', type=str)
        parser.add_argument('author_name', type=str)
        parser.add_argument('encoding', type=str)
        parser.add_argument('content', type=str, required=True)
        parser.add_argument('commit_message', type=str, required=True)
        args = parser.parse_args()
        return gitlab.gl_update_file(repository_id, args)

    @jwt_required
    def get(self, repository_id, branch_name, file_path):
        project_id = get_nexus_project_id(repository_id)
        role.require_in_project(project_id)
        return gitlab.gl_get_file(repository_id, branch_name, file_path)

    @jwt_required
    def delete(self, repository_id, branch_name, file_path):
        project_id = get_nexus_project_id(repository_id)
        role.require_in_project(project_id)
        parser = reqparse.RequestParser()
        parser.add_argument('commit_message', type=str, required=True)
        args = parser.parse_args()
        gitlab.gl_delete_file(repository_id, branch_name, file_path, args)
        return util.success()


class GitProjectTag(Resource):
    @jwt_required
    def get(self, repository_id):
        project_id = get_nexus_project_id(repository_id)
        role.require_in_project(project_id)
        res = gitlab.gl_get_tags(repository_id)
        return util.success({'tag_list': res})

    @jwt_required
    def post(self, repository_id):
        project_id = get_nexus_project_id(repository_id)
        role.require_in_project(project_id)
        parser = reqparse.RequestParser()
        parser.add_argument('tag_name', type=str, required=True)
        parser.add_argument('ref', type=str, required=True)
        parser.add_argument('message', type=str)
        parser.add_argument('release_description', type=str)
        args = parser.parse_args()
        return util.success(gitlab.gl_create_tag(repository_id, args))

    @jwt_required
    def delete(self, repository_id, tag_name):
        project_id = get_nexus_project_id(repository_id)
        role.require_in_project(project_id)
        gitlab.gl_delete_tag(repository_id, tag_name)
        return util.success()


# class GitProjectMergeBranch(Resource):
#     @jwt_required
#     def post(self, repository_id):
#         project_id = repo_id_to_project_id(repository_id)
#         role.require_in_project(project_id)
#         parser = reqparse.RequestParser()
#         parser.add_argument('schemas', type=dict, required=True)
#         args = parser.parse_args()["schemas"]
#         return gitlab.gl_merge(repository_id, args)
#
#
class GitProjectBranchCommits(Resource):
    @jwt_required
    def get(self, repository_id):
        project_id = get_nexus_project_id(repository_id)
        role.require_in_project(project_id)
        parser = reqparse.RequestParser()
        parser.add_argument('branch', type=str, required=True)
        args = parser.parse_args()
        return util.success(gitlab.gl_get_commits(repository_id, args['branch']))


class GitProjectNetwork(Resource):
    @jwt_required
    def get(self, repository_id):
        return gitlab.gl_get_network(repository_id)


class GitProjectId(Resource):
    @jwt_required
    def get(self, repository_id):
        return GitLab.gl_get_nexus_project_id(repository_id)


class GitProjectIdFromURL(Resource):
    @jwt_required
    def get(self):
        parser = reqparse.RequestParser()
        parser.add_argument('repository_url', type=str, required=True)
        args = parser.parse_args()
        try:
            return util.success(GitLab.gl_get_project_id_from_url(args['repository_url']))
        except NoResultFound:
            return util.respond(404, 'No such repository found in database.',
                                error=apiError.repository_id_not_found(args['repository_url']))


class GitProjectURLFromId(Resource):
    @jwt_required
    def get(self):
        parser = reqparse.RequestParser()
        parser.add_argument('project_id', type=int)
        parser.add_argument('repository_id', type=int)
        args = parser.parse_args()
        project_id = args['project_id']
        if project_id is None:
            repo_id = args['repository_id']
            if repo_id is None:
                return util.respond(400, 'You must provide project_id or repository_id.',
                                    error=apiError.argument_error('project_id|repository_id'))
            project_id = get_nexus_project_id(repo_id)
        return util.success({'http_url': get_repo_url(project_id)})
