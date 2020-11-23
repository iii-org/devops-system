import json

import requests
from flask_jwt_extended import jwt_required
from flask_restful import Resource, reqparse

import config
import model
import resources.util as util
from model import db
from resources import apiError, kubernetesClient, role
from resources.logger import logger


def repo_id_to_project_id(repo_id):
    row = model.ProjectPluginRelation.query.filter_by(git_repository_id=repo_id).first()
    if row:
        return row.project_id
    else:
        return -1


class GitLab(object):
    private_token = None

    def __init__(self):
        if config.get("GITLAB_API_VERSION") == "v3":
            # get gitlab admin token
            url = "http://{0}/api/v3/session".format(config.get("GITLAB_IP_PORT"))
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
    def gl_get_project_id(repository_id):
        project_id = repo_id_to_project_id(repository_id)
        if project_id > 0:
            return util.success(project_id)
        else:
            return util.respond(404, "Error when getting project id.",
                                error=apiError.repository_id_not_found(repository_id))

    def __api_request(self, method, path, headers=None, params=None, data=None):
        if headers is None:
            headers = {}
        if params is None:
            params = {}
        if 'Content-Type' not in headers:
            headers['Content-Type'] = 'application/json'

        url = "http://{0}/api/{1}{2}?private_token={3}".format(
            config.get("GITLAB_IP_PORT"),
            config.get("GITLAB_API_VERSION"),
            path,
            self.private_token)

        output = util.api_request(method, url, headers, params, data)

        logger.info('gitlab api {0} {1}, params={2}, body={5}, response={3} {4}'.format(
            method, url, params.__str__(), output.status_code, output.text, data))

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
        })

    def gl_get_project(self, repo_id):
        return self.__api_get('/projects/{0}'.format(repo_id))

    def gl_update_project(self, repo_id, description):
        params = {'description': description}
        return self.__api_put('/projects/{0}'.format(repo_id), params=params)

    def gl_delete_project(self, repo_id):
        return self.__api_delete('/projects/{0}'.format(repo_id))

    def gl_create_user(self, args, user_source_password):
        data = {
            "name": args['name'],
            "email": args['email'],
            "username": args['login'],
            "password": user_source_password,
            "skip_confirmation": True
        }
        output = self.__api_post('/users', data=data)
        return output

    def gl_update_password(self, repository_user_id, new_pwd):
        output = self.__api_put('/users/{0}'.format(repository_user_id),
                                params={"password": new_pwd})
        if output.status_code == 200:
            return None
        else:
            return output

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
        if output.status_code != 200:
            return -1, util.respond_request_style(
                output.status_code, "Error while getting git branches",
                error=apiError.gitlab_error(output))
        return len(output.json()), None

    def gl_get_tags(self, repo_id):
        return self.__api_get('/projects/{0}/repository/tags'.format(repo_id))

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
            return util.respond(output.status_code, "Error while getting git branches",
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
                        "{0}-{1}".format(project_detail.json()['path'], branch_info["name"]) \
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
                "short_id": branch_info["commit"]["short_id"],
                "env_url": env_url_list
            }
            branch_list.append(branch)
        return util.success({"branch_list": branch_list})

    def gl_create_branch(self, repo_id, args):
        output = self.__api_post('/projects/{0}/repository/branches'.format(repo_id),
                                 params={'branch': args['branch'], 'ref': args['ref']})
        if output.status_code == 201:
            return util.success(output.json())
        else:
            return util.respond(output.status_code, "Error while creating branch.",
                                error=apiError.gitlab_error(output))

    def gl_get_branch(self, repo_id, branch):
        output = self.__api_get('/projects/{0}/repository/branches/{1}'.format(
            repo_id, branch))
        if output.status_code == 200:
            return util.success(output.json())
        else:
            return util.respond(output.status_code, "Error when getting gitlab branch.",
                                error=apiError.gitlab_error(output))

    def gl_delete_branch(self, project_id, branch):
        output = self.__api_delete('/projects/{0}/repository/branches/{1}'.format(
            project_id, branch))
        if output.status_code == 204:
            return util.success()
        else:
            return util.respond(output.status_code, "Error when deleting gitlab branch.",
                                error=apiError.gitlab_error(output))

    def gl_get_repository_tree(self, repo_id, branch):
        output = self.__api_get('/projects/{0}/repository/tree'.format(repo_id),
                                params={'ref': branch})
        if output.status_code == 200:
            return util.success({"file_list": output.json()})
        else:
            return util.respond(output.status_code, "Error when deleting gitlab branch.",
                                error=apiError.gitlab_error(output))

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
            return util.respond(500, 'Only accept POST and PUT.',
                                error=apiError.unknown_method(method))

        if output.status_code == 201:
            return util.success({
                "file_path": output.json()["file_path"],
                "branch_name": output.json()["branch"]})
        else:
            return util.respond(output.status_code, "Error when adding gitlab file.",
                                error=apiError.gitlab_error(output))

    def gl_add_file(self, repo_id, args):
        return self.__edit_file_exec('POST', repo_id, args)

    def gl_update_file(self, repo_id, args):
        return self.__edit_file_exec('PUT', repo_id, args)

    def gl_get_file(self, repo_id, branch, file_path):
        output = self.__api_get('/projects/{0}/repository/files/{1}'.format(
            repo_id, file_path
        ), params={'ref': branch})
        if output.status_code == 200:
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
        else:
            return util.respond(output.status_code, "Error when getting gitlab file.",
                                error=apiError.gitlab_error(output))

    def gl_delete_file(self, repo_id, branch, file_path, args):
        output = self.__api_delete('/projects/{0}/repository/files/{1}'.format(
            repo_id, file_path), params={
            'branch': branch,
            'commit_message': args['commit_message']
        })
        if output.status_code == 204:
            return util.success()
        else:
            return util.respond(output.status_code, "Error when deleting gitlab file.",
                                error=apiError.gitlab_error(output))

    def gl_create_tag(self, repo_id, args):
        path = '/projects/{0}/repository/tags'.format(repo_id)
        params = {}
        keys = ['tag_name', 'ref', 'message', 'release_description']
        for k in keys:
            params[k] = args[k]
        output = self.__api_post(path, params=params)
        if output.status_code == 201:
            return util.success(output.json())
        else:
            return util.respond(output.status_code, "Error when deleting gitlab file.",
                                error=apiError.gitlab_error(output))

    def gl_delete_tag(self, repo_id, tag_name):
        output = self.__api_delete('/projects/{0}/repository/tags/{1}'.format(
            repo_id, tag_name))
        if output.status_code == 204:
            return util.success()
        else:
            return util.respond(output.status_code, "Error when deleting gitlab tag.",
                                error=apiError.gitlab_error(output))

    # def gl_merge(self, repo_id, args):
    #     # 新增merge request
    #     path = '/projects/{0}/merge_requests'.format(repo_id)
    #     params = {}
    #     keys = ['source_branch', 'target_branch', 'title']
    #     for k in keys:
    #         params[k] = args[k]
    #     output = self.__api_post(path, params=params)
    #     if output.status_code != 201:
    #         return util.respond(output.status_code, "Error when merging.",
    #                             error=apiError.gitlab_error(output))
    #     merge_request_iid = output.json()["iid"]
    #     output = self.__api_put('/projects/{0}/merge_requests/{1}/merge'.format(
    #         repo_id, merge_request_iid))
    #     if output.status_code == 200:
    #         return util.success()
    #     else:
    #         # 刪除merge request
    #         output_del = self.__api_delete('/projects/{0}/merge_requests/{1}'.format(
    #             repo_id, merge_request_iid))
    #         if output_del.status_code == 204:
    #             return util.respond(400, "merge failed and already delete your merge request.",
    #                                 error=apiError.gitlab_error(output))
    #         else:
    #             return util.respond(output.status_code, "Error when deleting pull request.",
    #                                 error=apiError.gitlab_error(output_del))

    def gl_get_commits(self, project_id, branch):
        output = self.__api_get('/projects/{0}/repository/commits'.format(project_id),
                                params={'ref_name': branch, 'per_page': 100})
        if output.status_code == 200:
            return util.success(output.json())
        else:
            return util.respond(output.status_code, "Error when getting commits.",
                                error=apiError.gitlab_error(output))

    # 用project_id查詢project的網路圖
    def gl_get_network(self, repo_id):
        branch_commit_list = []

        # 整理各branches的commit_list
        branches = self.gl_get_branches(repo_id)
        if int(branches[1] / 100) != 2:
            return branches
        for branch in branches[0]["data"]["branch_list"]:
            branch_commits = self.gl_get_commits(repo_id, branch["name"])
            if int(branch_commits[1] / 100) != 2:
                return branch_commits
            for branch_commit in branch_commits[0]["data"]:
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
        output_tags = gitlab.gl_get_tags(repo_id)
        if int(output_tags.status_code / 100) != 2:
            return output_tags, output_tags.status_code
        tags = output_tags.json()
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
        return gitlab.gl_get_branches(repository_id)

    @jwt_required
    def post(self, repository_id):
        parser = reqparse.RequestParser()
        parser.add_argument('branch', type=str, required=True)
        parser.add_argument('ref', type=str, required=True)
        args = parser.parse_args()
        return gitlab.gl_create_branch(repository_id, args)


class GitProjectBranch(Resource):
    @jwt_required
    def get(self, repository_id, branch_name):
        project_id = repo_id_to_project_id(repository_id)
        role.require_in_project(project_id)
        return gitlab.gl_get_branch(repository_id, branch_name)

    @jwt_required
    def delete(self, repository_id, branch_name):
        project_id = repo_id_to_project_id(repository_id)
        role.require_in_project(project_id)
        return gitlab.gl_delete_branch(repository_id, branch_name)


class GitProjectRepositories(Resource):
    @jwt_required
    def get(self, repository_id, branch_name):
        project_id = repo_id_to_project_id(repository_id)
        role.require_in_project(project_id)
        return gitlab.gl_get_repository_tree(repository_id, branch_name)


class GitProjectFile(Resource):
    @jwt_required
    def post(self, repository_id):
        project_id = repo_id_to_project_id(repository_id)
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
        project_id = repo_id_to_project_id(repository_id)
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
        project_id = repo_id_to_project_id(repository_id)
        role.require_in_project(project_id)
        return gitlab.gl_get_file(repository_id, branch_name, file_path)

    @jwt_required
    def delete(self, repository_id, branch_name, file_path):
        project_id = repo_id_to_project_id(repository_id)
        role.require_in_project(project_id)
        parser = reqparse.RequestParser()
        parser.add_argument('commit_message', type=str, required=True)
        args = parser.parse_args()
        return gitlab.gl_delete_file(repository_id, branch_name, file_path, args)


class GitProjectTag(Resource):
    @jwt_required
    def get(self, repository_id):
        project_id = repo_id_to_project_id(repository_id)
        role.require_in_project(project_id)
        res = gitlab.gl_get_tags(repository_id)
        if res.status_code == 200:
            return util.success({'tag_list': res.json()})
        else:
            return util.respond(res.status_code, "Error while getting repo tags.",
                                error=apiError.gitlab_error(res))

    @jwt_required
    def post(self, repository_id):
        project_id = repo_id_to_project_id(repository_id)
        role.require_in_project(project_id)
        parser = reqparse.RequestParser()
        parser.add_argument('tag_name', type=str, required=True)
        parser.add_argument('ref', type=str, required=True)
        parser.add_argument('message', type=str)
        parser.add_argument('release_description', type=str)
        args = parser.parse_args()
        return gitlab.gl_create_tag(repository_id, args)

    @jwt_required
    def delete(self, repository_id, tag_name):
        project_id = repo_id_to_project_id(repository_id)
        role.require_in_project(project_id)
        return gitlab.gl_delete_tag(repository_id, tag_name)


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
        project_id = repo_id_to_project_id(repository_id)
        role.require_in_project(project_id)
        parser = reqparse.RequestParser()
        parser.add_argument('branch', type=str, required=True)
        args = parser.parse_args()
        return gitlab.gl_get_commits(repository_id, args['branch'])


class GitProjectNetwork(Resource):
    @jwt_required
    def get(self, repository_id):
        return gitlab.gl_get_network(repository_id)


class GitProjectId(Resource):
    @jwt_required
    def get(self, repository_id):
        return GitLab.gl_get_project_id(repository_id)
