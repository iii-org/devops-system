import json
import logging

import requests

import config
import resources.util as util
from resources import apiError

from resources.logger import logger


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

    def count_branches(self, repo_id):
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

    # Not used now, skipping refactor
    # def gl_get_branches(self, repo_id):
    #     output = self.__api_get('/projects/{0}/repository/branches'.format(repo_id))
    #     if output.status_code != 200:
    #         return util.respond_request_style(output.status_code, "Error while getting git branches",
    #                                           error=apiError.gitlab_error(output))
    #     # get gitlab project path
    #     projtct_detail = self.get_one_git_project(logger, app, repo_id)
    #     logger.info("Get git path: {0}".format(projtct_detail.json()['path']))
    #     # get kubernetes service nodePort url
    #     k8s_service_list = kubernetesClient.list_service_all_namespaces()
    #     k8s_node_list = kubernetesClient.list_work_node()
    #     work_node_ip = k8s_node_list[0]['ip']
    #     logger.info("k8s_node ip: {0}".format(work_node_ip))
    #
    #     branch_list = []
    #     for branch_info in output.json():
    #         env_url_list = []
    #         for k8s_service in k8s_service_list:
    #             if k8s_service['type'] == 'NodePort' and \
    #                     "{0}-{1}".format(projtct_detail.json()['path'], branch_info["name"]) \
    #                     in k8s_service['name']:
    #                 port_list = []
    #                 for port in k8s_service['ports']:
    #                     port_list.append(
    #                         {"port": port['port'], "url": "http://{0}:{1}".format(work_node_ip, port['nodePort'])})
    #                 env_url_list.append({k8s_service['name']: port_list})
    #         branch = {
    #             "name": branch_info["name"],
    #             "last_commit_message": branch_info["commit"]["message"],
    #             "last_commit_time":
    #                 branch_info["commit"]["committed_date"],
    #             "short_id": branch_info["commit"]["short_id"],
    #             "env_url": env_url_list
    #         }
    #         branch_list.append(branch)
    #     return {
    #                "message": "success",
    #                "data": {
    #                    "branch_list": branch_list
    #                }
    #            }, 200
