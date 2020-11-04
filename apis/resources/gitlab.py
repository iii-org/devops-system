import config
import json
import logging

import requests

from resources.util import util

logger = logging.getLogger(config.get('LOGGER_NAME'))


class GitLab(object):
    private_token = None
    headers = {'Content-Type': 'application/json'}

    def __init__(self, app):
        self.app = app
        if config.get("GITLAB_API_VERSION") == "v3":
            # get gitlab admin token
            url = "http://{0}/api/v3/session".format(config.get("GITLAB_IP_PORT"))
            param = {
                "login": config.get("GITLAB_ADMIN_ACCOUNT"),
                "password": config.get("GITLAB_ADMIN_PASSWORD")
            }
            output = requests.post(url,
                                   data=json.dumps(param),
                                   headers=self.headers,
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
        output = self.__api_post('/projects', params={
            'name': args["name"],
            'description': args["description"]
        })
        return output

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

    def update_password(self, repository_user_id, new_pwd):
        url = "http://{0}/api/{1}/users/{2}?private_token={3}".format(
            config.get("GITLAB_IP_PORT"),
            config.get("GITLAB_API_VERSION"),
            repository_user_id,
            self.private_token)
        param = {"password": new_pwd}
        output = requests.put(url, data=json.dumps(param), headers=self.headers, verify=False)
        if output.status_code == 200:
            return None
        else:
            return output

    def get_user_list(self, args):
        url = "http://{0}/api/{1}/users"\
            .format(config.get("GITLAB_IP_PORT"), config.get("GITLAB_API_VERSION"), \
                    )
        args['private_token'] = self.private_token
        logger.info("gitlab create user url: {0}".format(url))
        output = requests.get(url,
                              params=args,
                              headers=self.headers,
                              verify=False)
        #logger.info("gitlab get user list output: status_code: {0}, message: {1}".
        # format(output.status_code, output.json()))
        return output

    def project_add_member(self, logger, app, project_id, user_id):
        gitlab = GitLab(app)
        url = "http://{0}/api/{1}/projects/{2}/members?private_token={3}"\
            .format(config.get("GITLAB_IP_PORT"), config.get("GITLAB_API_VERSION"), \
                    project_id, gitlab.private_token)
        parame = {
            "user_id": user_id,
            "access_level": 40,
        }
        output = requests.post(url,
                               data=json.dumps(parame),
                               headers=self.headers,
                               verify=False)
        logger.info(
            "gitlab project add member api output: status_code: {0}, message: {1}"
            .format(output.status_code, output.text))
        return output, output.status_code

    def project_delete_member(self, logger, app, project_id, user_id):
        gitlab = GitLab(app)
        url = "http://{0}/api/{1}/projects/{2}/members/{3}?private_token={4}"\
            .format(config.get("GITLAB_IP_PORT"), config.get("GITLAB_API_VERSION"), \
                    project_id, user_id, gitlab.private_token)
        output = requests.delete(url, headers=self.headers, verify=False)
        logger.info(
            "gitlab project delete member api output: status_code: {0}, message: {1}"
            .format(output.status_code, output.text))
        return output, output.status_code