import config
import json
import logging

import requests

from resources.util import Util

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

        output = Util.api_request(method, url, headers, params, data)

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

    def gl_update_password(self, repository_user_id, new_pwd):
        output = self.__api_put('/users/{0}'.format(repository_user_id),
                                params={"password": new_pwd})
        if output.status_code == 200:
            return None
        else:
            return output

    def gl_get_user_list(self, args):
        output = self.__api_get('/users', params=args)
        return output

    def gl_project_add_member(self, project_id, user_id):
        params = {
            "user_id": user_id,
            "access_level": 40,
        }
        output = self.__api_post('/projects/{0}/members'.format(project_id),
                                 params=params)
        return output

    def gl_project_delete_member(self, project_id, user_id):
        output = self.__api_delete('/projects/{0}/members/{1}'.format(
            project_id, user_id))
        return output
