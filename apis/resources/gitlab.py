import json
import pytz
from datetime import datetime, timedelta, time
from dateutil import tz
from gitlab import Gitlab
import requests
from flask_jwt_extended import jwt_required, get_jwt_identity
from flask_restful import Resource, reqparse
from sqlalchemy.orm.exc import NoResultFound

import config
import model
from model import db, GitCommitNumberEachDays
import util as util
from resources import apiError, kubernetesClient, role
from resources.apiError import DevOpsError
from resources.logger import logger
from .rancher import rancher


def get_nexus_project_id(repo_id):
    row = model.ProjectPluginRelation.query.filter_by(
        git_repository_id=repo_id).first()
    if row:
        return row.project_id
    else:
        return -1


def get_repo_url(project_id):
    row = model.Project.query.filter_by(id=project_id).one()
    return row.http_url


def commit_id_to_url(project_id, commit_id):
    return f'{get_repo_url(project_id)[0:-4]}/-/commit/{commit_id}'


# May throws NoResultFound
def get_repository_id(project_id):
    return model.ProjectPluginRelation.query.filter_by(
        project_id=project_id).one().git_repository_id


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
            output = requests.post(
                url,
                data=json.dumps(param),
                headers={'Content-Type': 'application/json'},
                verify=False)
            self.private_token = output.json()['private_token']
        else:
            self.private_token = config.get("GITLAB_PRIVATE_TOKEN")
        self.gl = Gitlab(config.get("GITLAB_BASE_URL"),
                         private_token=self.private_token)

    @staticmethod
    def gl_get_nexus_project_id(repository_id):
        project_id = get_nexus_project_id(repository_id)
        if project_id > 0:
            return util.success(project_id)
        else:
            raise DevOpsError(
                404,
                "Error when getting project id.",
                error=apiError.repository_id_not_found(repository_id))

    @staticmethod
    def gl_get_project_id_from_url(repository_url):
        row = model.Project.query.filter_by(http_url=repository_url).one()
        project_id = row.id
        repository_id = get_repository_id(project_id)
        return {'project_id': project_id, 'repository_id': repository_id}

    def __api_request(self,
                      method,
                      path,
                      headers=None,
                      params=None,
                      data=None):
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

        logger.info(
            f'gitlab api {method} {url}, params={params.__str__()}, body={data}, response={output.status_code} {output.text}'
        )
        if int(output.status_code / 100) != 2:
            raise apiError.DevOpsError(output.status_code,
                                       'Got non-2xx response from Gitlab.',
                                       apiError.gitlab_error(output))
        return output

    def __api_get(self, path, params=None, headers=None):
        return self.__api_request('GET', path, params=params, headers=headers)

    def __api_post(self, path, params=None, headers=None, data=None):
        return self.__api_request('POST',
                                  path,
                                  headers=headers,
                                  data=data,
                                  params=params)

    def __api_put(self, path, params=None, headers=None, data=None):
        return self.__api_request('PUT',
                                  path,
                                  headers=headers,
                                  data=data,
                                  params=params)

    def __api_delete(self, path, params=None, headers=None):
        return self.__api_request('DELETE',
                                  path,
                                  params=params,
                                  headers=headers)

    def __gl_timezone_to_utc(self, gl_datetime_str):
        return datetime.strftime(
            datetime.strptime(gl_datetime_str,
                              '%Y-%m-%dT%H:%M:%S.%f%z').astimezone(pytz.utc),
            '%Y-%m-%dT%H:%M:%S%z')

    def gl_create_project(self, args):
        return self.__api_post('/projects',
                               params={
                                   'name': args["name"],
                                   'description': args["description"]
                               }).json()

    def gl_get_project(self, repo_id):
        return self.__api_get(f'/projects/{repo_id}', {
            'statistics': 'true'
        }).json()

    def gl_update_project(self, repo_id, description):
        params = {'description': description}
        return self.__api_put(f'/projects/{repo_id}', params=params)

    def gl_delete_project(self, repo_id):
        return self.__api_delete(f'/projects/{repo_id}')

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
        return self.__api_put(f'/users/{repository_user_id}',
                              params={
                                  "password": new_pwd,
                                  "skip_reconfirmation": True
                              })

    def gl_update_email(self, repository_user_id, new_email):
        return self.__api_put(f'/users/{repository_user_id}',
                              params={
                                  "email": new_email,
                                  "skip_reconfirmation": True
                              })

    def gl_get_user_list(self, args):
        return self.__api_get('/users', params=args)

    def gl_project_add_member(self, project_id, user_id):
        params = {
            "user_id": user_id,
            "access_level": 40,
        }
        return self.__api_post(f'/projects/{project_id}/members',
                               params=params)

    def gl_project_delete_member(self, project_id, user_id):
        return self.__api_delete(f'/projects/{project_id}/members/{user_id}')

    def gl_delete_user(self, gitlab_user_id):
        return self.__api_delete(f'/users/{gitlab_user_id}')

    def gl_get_user_email(self, gitlab_user_id):
        return self.__api_get(f'/users/{gitlab_user_id}/emails')

    def gl_delete_user_email(self, gitlab_user_id, gitlab_email_id):
        return self.__api_delete(f'/users/{gitlab_user_id}/emails/{gitlab_email_id}')

    def gl_count_branches(self, repo_id):
        output = self.__api_get(f'/projects/{repo_id}/repository/branches')
        return len(output.json())

    def gl_get_tags(self, repo_id, params={}):
        return self.__api_get(f'/projects/{repo_id}/repository/tags',
                              params).json()

    def gl_create_rancher_pipeline_yaml(self, repo_id, args, method):
        path = f'/projects/{repo_id}/repository/files/{args["file_path"]}'
        params = {}
        for key in [
                'branch', 'start_branch', 'encoding', 'author_email',
                'author_name', 'content', 'commit_message'
        ]:
            params[key] = args[key]
        return self.__api_request(method, path, params=params)

    def gl_get_project_file_for_pipeline(self, project_id, args):
        return self.__api_get(
            f'/projects/{project_id}/repository/files/{args["file_path"]}',
            params={'ref': args["branch"]})

    def gl_get_branches(self, repo_id):
        output = self.__api_get(f'/projects/{repo_id}/repository/branches')
        if output.status_code != 200:
            raise DevOpsError(output.status_code,
                              "Error while getting git branches",
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
                        f'{project_detail["path"]}-{branch_info["name"]}' \
                        in k8s_service['name']:
                    port_list = []
                    for port in k8s_service['ports']:
                        port_list.append({
                            "port":
                            port['port'],
                            "url":
                            f"http://{work_node_ip}:{port['nodePort']}"
                        })
                    env_url_list.append({k8s_service['name']: port_list})
            branch = {
                "name":
                branch_info["name"],
                "last_commit_message":
                branch_info["commit"]["message"],
                "last_commit_time":
                branch_info["commit"]["committed_date"],
                "short_id":
                branch_info["commit"]["short_id"][0:7],
                'commit_url':
                commit_id_to_url(get_nexus_project_id(repo_id),
                                 branch_info['commit']['short_id']),
                "env_url":
                env_url_list
            }
            branch_list.append(branch)
        return branch_list

    def gl_create_branch(self, repo_id, args):
        output = self.__api_post(f'/projects/{repo_id}/repository/branches',
                                 params={
                                     'branch': args['branch'],
                                     'ref': args['ref']
                                 })
        return output.json()

    def gl_get_branch(self, repo_id, branch):
        output = self.__api_get(
            f'/projects/{repo_id}/repository/branches/{branch}')
        return output.json()

    def gl_delete_branch(self, project_id, branch):
        output = self.__api_delete(
            f'/projects/{project_id}/repository/branches/{branch}')
        return output

    def gl_get_repository_tree(self, repo_id, branch):
        output = self.__api_get(f'/projects/{repo_id}/repository/tree',
                                params={'ref': branch})
        return {"file_list": output.json()}

    def gl_get_storage_usage(self, repo_id):
        project_detail = self.gl_get_project(repo_id)
        usage_info = {}
        usage_info['title'] = 'GitLab'
        usage_info['used'] = {}
        usage_info['quota'] = {}
        usage_info['used']['value'] = project_detail['statistics'][
            'storage_size']
        usage_info['used']['unit'] = ""
        usage_info['quota']['value'] = "1073741824"
        usage_info['quota']['unit'] = ""
        return usage_info

    def __edit_file_exec(self, method, repo_id, args):
        path = f'/projects/{repo_id}/repository/files/{args["file_path"]}'
        params = {}
        keys = [
            'branch', 'start_branch', 'encoding', 'author_email',
            'author_name', 'content', 'commit_message'
        ]
        for k in keys:
            params[k] = args[k]

        if method.upper() == 'POST':
            output = self.__api_post(path, params=params)
        elif method.upper() == 'PUT':
            output = self.__api_put(path, params=params)
        else:
            raise DevOpsError(500,
                              'Only accept POST and PUT.',
                              error=apiError.invalid_code_path(
                                  'Only PUT and POST is allowed, but'
                                  f'{method} provided.'))

        if output.status_code == 201:
            return util.success({
                "file_path": output.json()["file_path"],
                "branch_name": output.json()["branch"]
            })
        else:
            raise DevOpsError(output.status_code,
                              "Error when adding gitlab file.",
                              error=apiError.gitlab_error(output))

    def gl_add_file(self, repo_id, args):
        return self.__edit_file_exec('POST', repo_id, args)

    def gl_update_file(self, repo_id, args):
        return self.__edit_file_exec('PUT', repo_id, args)

    def gl_get_file(self, repo_id, branch, file_path):
        output = self.__api_get(
            f'/projects/{repo_id}/repository/files/{file_path}',
            params={'ref': branch})
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

    def gl_delete_file(self, repo_id, file_path, args, branch=None):
        if branch is None:
            pj = self.gl.projects.get(repo_id)
            branch = pj.default_branch
        return self.__api_delete(
            f'/projects/{repo_id}/repository/files/{file_path}',
            params={
                'branch': branch,
                'commit_message': args['commit_message']
            })

    def gl_create_tag(self, repo_id, args):
        path = f'/projects/{repo_id}/repository/tags'
        params = {}
        keys = ['tag_name', 'ref', 'message', 'release_description']
        for k in keys:
            params[k] = args[k]
        return self.__api_post(path, params=params).json()

    def gl_delete_tag(self, repo_id, tag_name):
        return self.__api_delete(
            f'/projects/{repo_id}/repository/tags/{tag_name}')

    def gl_get_commits(self, project_id, branch):
        return self.__api_get(f'/projects/{project_id}/repository/commits',
                              params={
                                  'ref_name': branch,
                                  'per_page': 100
                              }).json()

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

    def gl_create_access_token(self, user_id):
        data = {
            'name': 'IIIDevops Helm source code analysis',
            'scopes': ['read_api']
        }
        return self.__api_post(f'/users/{user_id}/impersonation_tokens',
                               data=data).json()['token']

    # Get Gitlab list releases
    def gl_list_releases(self, repo_id):
        return self.__api_get(f'/projects/{repo_id}/releases').json()

    # Get Gitlab list releases
    def gl_get_release(self, repo_id, tag_name):
        return self.__api_get(
            f'/projects/{repo_id}/releases/{tag_name}').json()

    def gl_get_release(self, repo_id, tag_name):
        return self.__api_get(
            f'/projects/{repo_id}/releases/{tag_name}').json()

    def gl_create_release(self, repo_id, data):
        path = f'/projects/{repo_id}/releases'
        return self.__api_post(path, params=data).json()

    def gl_update_release(self, repo_id, tag_name, data):
        path = f'/projects/{repo_id}/releases/{tag_name}'
        return self.__api_put(path, params=data).json()

    def gl_delete_release(self, repo_id, tag_name):
        path = f'/projects/{repo_id}/releases/{tag_name}'
        return self.__api_delete(path).json()

    def gl_get_the_last_hours_commits(self,
                                      the_last_hours=None,
                                      show_commit_rows=None,
                                      git_repository_id=None,
                                      user_id=None):
        if role.is_admin() is False:
            user_id = get_jwt_identity()["user_id"]
        if user_id is not None:
            rows = db.session.query(model.ProjectUserRole, model.ProjectPluginRelation).join(\
                model.ProjectPluginRelation, \
                model.ProjectPluginRelation.project_id == model.ProjectUserRole.project_id).\
                filter(model.ProjectUserRole.user_id == user_id,
                        model.ProjectUserRole.project_id == model.ProjectPluginRelation.project_id).all()
        out_list = []
        if show_commit_rows is not None:
            last_days_ago = None
            for x in range(12, 169, 12):
                days_ago = (datetime.utcnow() - timedelta(days=x)).isoformat()
                pjs = []
                if user_id is not None:
                    for row in rows:
                        pjs.append(
                            self.gl.projects.get(
                                row.ProjectPluginRelation.git_repository_id))
                elif git_repository_id is not None:
                    pjs.append(self.gl.projects.get(git_repository_id))
                else:
                    pjs = self.gl.projects.list(order_by="last_activity_at")
                for pj in pjs:
                    if (pj.empty_repo is False) and (
                        ("iiidevops-templates" not in pj.path_with_namespace)
                            and
                        ("local-templates" not in pj.path_with_namespace)):
                        for commit in pj.commits.list(since=days_ago,
                                                      until=last_days_ago):
                            out_list.append({
                                "pj_name":
                                pj.name,
                                "author_name":
                                commit.author_name,
                                "author_email":
                                commit.author_email,
                                "commit_time":
                                self.__gl_timezone_to_utc(
                                    commit.committed_date),
                                "commit_id":
                                commit.short_id,
                                "commit_title":
                                commit.title,
                                "commit_message":
                                commit.message
                            })
                            if len(out_list) > show_commit_rows - 1:
                                sorted(
                                    (out["commit_time"] for out in out_list),
                                    reverse=True)
                                return out_list[:show_commit_rows]
                last_days_ago = days_ago
            sorted((out["commit_time"] for out in out_list), reverse=True)
            return out_list[:show_commit_rows]
        else:
            if the_last_hours == None:
                the_last_hours = 24
            days_ago = (datetime.utcnow() -
                        timedelta(hours=the_last_hours)).isoformat()
            pjs = []
            if user_id is not None:
                for row in rows:
                    pjs.append(
                        self.gl.projects.get(
                            row.ProjectPluginRelation.git_repository_id))
            elif git_repository_id is not None:
                pjs.append(self.gl.projects.get(git_repository_id))
            else:
                pjs = self.gl.projects.list(order_by="last_activity_at")
            for pj in pjs:
                if (pj.empty_repo is False) and (
                    ("iiidevops-templates" not in pj.path_with_namespace) and
                    ("local-templates" not in pj.path_with_namespace)):
                    for commit in pj.commits.list(since=days_ago):
                        out_list.append({
                            "pj_name":
                            pj.name,
                            "author_name":
                            commit.author_name,
                            "author_email":
                            commit.author_email,
                            "commit_time":
                            self.__gl_timezone_to_utc(commit.committed_date),
                            "commit_id":
                            commit.short_id,
                            "commit_title":
                            commit.title,
                            "commit_message":
                            commit.message
                        })
        sorted((out["commit_time"] for out in out_list), reverse=True)
        return out_list

    def gl_count_each_pj_commits_by_days(self, days=30):
        for pj in self.gl.projects.list(all=True):
            if ("iiidevops-templates" not in pj.path_with_namespace) and (
                    "local-templates" not in pj.path_with_namespace):
                for i in range(1, days + 1):
                    pj_create_date = datetime.strptime(
                        pj.created_at, '%Y-%m-%dT%H:%M:%S.%f%z').astimezone(
                            tz.tzlocal()).date()
                    day_start = datetime.combine(
                        (datetime.now() - timedelta(days=i)), time(00, 00))
                    day_end = datetime.combine(
                        (datetime.now() - timedelta(days=i)), time(23, 59))
                    if day_start.date() >= pj_create_date:
                        count = GitCommitNumberEachDays.query.filter(
                            GitCommitNumberEachDays.repo_id == pj.id,
                            GitCommitNumberEachDays.date ==
                            day_start.date()).count()
                        if count == 0:
                            if (pj.empty_repo is True):
                                commit_number = 0
                            else:
                                commit_number = len(
                                    pj.commits.list(all=True,
                                                    query_parameters={
                                                        'since': day_start,
                                                        'until': day_end
                                                    }))
                            one_row_data = GitCommitNumberEachDays(
                                repo_id=pj.id,
                                repo_name=pj.name,
                                date=day_start.date(),
                                commit_number=commit_number,
                                created_at=str(datetime.now()))
                            db.session.add(one_row_data)
                            db.session.commit()

    def ql_get_collection(self, repository_id, path):
        try:
            pj = self.gl.projects.get(repository_id)
            return pj.repository_tree(ref=pj.default_branch, path=path)
        except apiError.TemplateError as e:
            raise apiError.TemplateError(
                404,
                "Error when getting project repository_tree.",
                error=apiError.gitlab_error(e))
    
    def gl_get_file(self, repository_id, path):
        pj = self.gl.projects.get(repository_id)
        f_byte = pj.files.raw(file_path=path, ref=pj.default_branch).decode()
        return f_byte


# --------------------- Resources ---------------------
gitlab = GitLab()


class GitRelease():
    @jwt_required
    def check_gitlab_release(self, repository_id, tag_name):
        output = {'check': True, "info": "", "errors": {}}
        tag = gitlab.gl_get_tags(str(repository_id), {'search': tag_name})
        if len(tag) > 0:
            output['check'] = False
            output['info'] = '{0} is exists in gitlab'.format(tag_name)
            output['errors'] = tag[0]
        return output


gl_release = GitRelease()


class GitProjectBranches(Resource):
    @jwt_required
    def get(self, repository_id):
        return util.success(
            {'branch_list': gitlab.gl_get_branches(repository_id)})

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
        gitlab.gl_delete_file(repository_id, file_path, args, branch_name)
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


class GitProjectBranchCommits(Resource):
    @jwt_required
    def get(self, repository_id):
        project_id = get_nexus_project_id(repository_id)
        role.require_in_project(project_id)
        parser = reqparse.RequestParser()
        parser.add_argument('branch', type=str, required=True)
        args = parser.parse_args()
        return util.success(
            gitlab.gl_get_commits(repository_id, args['branch']))


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
            return util.success(
                GitLab.gl_get_project_id_from_url(args['repository_url']))
        except NoResultFound:
            return util.respond(404,
                                'No such repository found in database.',
                                error=apiError.repository_id_not_found(
                                    args['repository_url']))


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
                return util.respond(
                    400,
                    'You must provide project_id or repository_id.',
                    error=apiError.argument_error('project_id|repository_id'))
            project_id = get_nexus_project_id(repo_id)
        return util.success({'http_url': get_repo_url(project_id)})


class GitTheLastHoursCommits(Resource):
    @jwt_required
    def get(self):
        parser = reqparse.RequestParser()
        parser.add_argument('the_last_hours', type=int)
        parser.add_argument('show_commit_rows', type=int)
        parser.add_argument('git_repository_id', type=int)
        parser.add_argument('user_id', type=int)
        args = parser.parse_args()
        return util.success(
            gitlab.gl_get_the_last_hours_commits(args["the_last_hours"],
                                                 args["show_commit_rows"],
                                                 args["git_repository_id"],
                                                 args["user_id"]))


class GitCountEachPjCommitsByDays(Resource):
    def get(self):
        return util.success(gitlab.gl_count_each_pj_commits_by_days())