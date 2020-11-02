import config
import json
import logging
import time
from io import BytesIO

import requests
import werkzeug
from flask import send_file
from flask_restful import reqparse

from .error import Error
from .util import util

logger = logging.getLogger(config.get('LOGGER_NAME'))


class Redmine:

    redmine_key = None
    headers = {'Content-Type': 'application/json'}

    def __init__(self, app):
        self.app = app
        self.headers = {'Content-Type': 'application/json'}
        self.key_generated = 0.0
        # get redmine_key
        url = "http://{0}:{1}@{2}/users/current.json".format(config.get('REDMINE_ADMIN_ACCOUNT'), \
                                                             config.get('REDMINE_ADMIN_PASSWORD'), config.get('REDMINE_IP_PORT'))
        output = requests.get(url, headers=self.headers, verify=False)
        self.redmine_key = output.json()['user']['api_key']
        logger.info("redmine_key: {0}".format(self.redmine_key))

    def api_request(self, method, path, headers=None, params=None, data=None):
        self.key_check()
        if headers is None:
            headers = {}
        if params is None:
            params = {}
        if 'Content-Type' not in headers:
            headers['Content-Type'] = 'application/json'

        url = "http://{0}{1}.json".format(config.get('REDMINE_IP_PORT'), path)
        params['key'] = self.redmine_key

        if method.upper() == 'GET':
            output = requests.get(url, headers=headers, params=params, verify=False)
        elif method.upper() == 'POST':
            params['key'] = self.redmine_key
            if type(data) is dict:
                if 'Content-Type' not in headers:
                    headers['Content-Type'] = 'application/json'
                output = requests.post(url, data=json.dumps(data), params=params,
                                       headers=headers, verify=False)
            else:
                output = requests.post(url, data=data, params=params,
                                       headers=headers, verify=False)
        elif method.upper() == 'PUT':
            output = requests.put(url, data=json.dumps(data), params=params,
                                  headers=headers, verify=False)
        elif method.upper() == 'DELETE':
            output = requests.delete(url, headers=headers, params=params, verify=False)
        else:
            return util.respond(
                500, 'Error while request {0} {1}'.format(method, url),
                error=Error.detail(Error.UNKNOWN_METHOD, {'method': method}))

        logger.info('redmine api {0} {1}, params={2}, body={5}, response={3} {4}'.format(
            method, url, params.__str__(), output.status_code, output.text, data))

        return output

    def api_get(self, path, params=None, headers=None):
        return self.api_request('GET', path, params=params, headers=headers)

    def api_post(self, path, params=None, headers=None, data=None):
        return self.api_request('POST', path, headers=headers, data=data, params=params)

    def api_put(self, path, params=None, headers=None, data=None):
        return self.api_request('PUT', path, headers=headers, data=data, params=params)

    def api_delete(self, path, params=None, headers=None):
        return self.api_request('DELETE', path, params=params, headers=headers)

    def key_check(self):
        # Check if key expires first, seems to expire in 2 hours in default?
        if time.time() - self.key_generated >= 7200:
            self.rm_refresh_key()

    def rm_refresh_key(self):
        # get redmine_key
        url = "http://{0}:{1}@{2}/users/current.json".format(config.get('REDMINE_ADMIN_ACCOUNT'),
                                                             config.get('REDMINE_ADMIN_PASSWORD'),
                                                             config.get('REDMINE_IP_PORT'))
        output = requests.get(url, headers=Redmine.headers, verify=False)
        self.redmine_key = output.json()['user']['api_key']
        self.key_generated = time.time()
        logger.info("redmine_key: {0}".format(self.redmine_key))
        return self.redmine_key

    def rm_get_issues_by_user(self, user_id):
        params = {'assigned_to_id': user_id, 'limit': 100}
        output = self.api_get('/issues', params=params)
        logger.info("get issues by output: {0}".format(output.json()))
        return output.json()

    def rm_get_issues_by_project(self, plan_project_id):
        params = {'project_id': plan_project_id, 'limit': 1000}
        output = self.api_get('/issues', params=params)
        return output.json()

    def rm_get_issues_by_project_and_user(self, user_id, plan_project_id):
        params = {
            'assigned_to_id': user_id,
            'project_id': plan_project_id,
            'limit': 100
        }
        output = self.api_get('/issues', params=params)
        return output.json()

    def rm_get_issue(self, issue_id):
        params = {'include': 'journals,attachment'}
        output = self.api_get('/issues/{0}'.format(issue_id), params=params)
        logger.info("get issues output: {0}".format(output))
        return output

    def rm_get_statistics(self, params):
        output = self.api_get('/issues', params=params)
        return output.json(), output.status_code

    def rm_create_issue(self, args):
        data = {"issue": args}
        output = self.api_post('/issues', data=data)
        return output, output.status_code

    def rm_update_issue(self, issue_id, args):
        output = self.api_put('/issues/{0}'.format(issue_id), data={"issue": args})
        return output, output.status_code

    def rm_delete_issue(self, issue_id):
        params = {'include': 'journals,attachment'}
        output = self.api_delete('/issues/{0}'.format(issue_id), params=params)
        return output, output.status_code

    def rm_get_issue_status(self):
        return self.api_get('/issue_statuses').json()

    def rm_get_priority(self):
        return self.api_get('/enumerations/issue_priorities').json()

    def rm_get_trackers(self):
        return self.api_get('/trackers').json()

    def rm_create_user(self, args, user_source_password):
        params = {
            "user": {
                "login": args["login"],
                "firstname": '#',
                "lastname": args["name"],
                "mail": args["email"],
                "password": user_source_password
            }
        }
        output = self.api_post('/users', data=params)
        return output

    def rm_update_password(self, plan_user_id, new_pwd):
        param = {"user": {"password": new_pwd}}
        output = self.api_put('/users/{0}'.format(plan_user_id), data=param)
        if output.status_code == 204:
            return None
        else:
            return output

    def rm_get_user_list(self, args):
        output = self.api_get('/users', params=args)
        return output.json()

    def redmine_delete_user(self, redmine_user_id):
        redmine_url = "http://{0}/users/{1}.json?key={2}".format(
            config.get("REDMINE_IP_PORT"), redmine_user_id,
            config.get("REDMINE_API_KEY"))
        logger.info("delete redmine user url: {0}".format(redmine_url))
        redmine_output = requests.delete(redmine_url,
                                            headers=self.headers,
                                            verify=False)
        logger.info(
            "delete redmine user output: {0}".format(redmine_output))

    def redmine_get_wiki_list(self, project_id):
        url = "http://{0}/projects/{1}/wiki/index.json?key={2}".format(
            config.get('REDMINE_IP_PORT'), project_id, self.redmine_key)
        logger.info("url: {0}".format(url))
        output = requests.get(url, headers=Redmine.headers, verify=False)
        logger.info("get wiki list output and status: {0} and {1}".format(
            output, output.status_code))
        return output, output.status_code

    def redmine_get_wiki(self, logger, app, project_id, wiki_name):
        url = "http://{0}/projects/{1}/wiki/{2}.json?key={3}".format(
            config.get('REDMINE_IP_PORT'), project_id, wiki_name,
            self.redmine_key)
        logger.info("url: {0}".format(url))
        output = requests.get(url, headers=Redmine.headers, verify=False)
        logger.info("get wiki list output and status: {0} and {1}".format(
            output, output.status_code))
        return output, output.status_code

    def redmine_put_wiki(self, logger, app, project_id, wiki_name, args):
        url = "http://{0}/projects/{1}/wiki/{2}.json?key={3}".format(
            config.get('REDMINE_IP_PORT'), project_id, wiki_name,
            self.redmine_key)
        logger.info("url: {0}".format(url))
        param = {"wiki_page": {"text": args['wiki_text']}}
        output = requests.put(url,
                              data=json.dumps(param),
                              headers=Redmine.headers,
                              verify=False)
        logger.info("get wiki list output and status: {0} and {1}".format(
            output, output.status_code))
        return output, output.status_code

    def redmine_delete_wiki(self, logger, app, project_id, wiki_name):
        url = "http://{0}/projects/{1}/wiki/{2}.json?key={3}".format(
            config.get('REDMINE_IP_PORT'), project_id, wiki_name,
            self.redmine_key)
        logger.info("url: {0}".format(url))
        output = requests.delete(url, headers=Redmine.headers, verify=False)
        logger.info("get wiki list output and status: {0} and {1}".format(
            output, output.status_code))
        return output, output.status_code

    # Get Redmine Version List
    def redmine_get_version_list(self, logger, app, project_id):
        url = "http://{0}/projects/{1}/versions.json?key={2}".format(
            config.get('REDMINE_IP_PORT'), project_id, self.redmine_key)
        logger.info("url: {0}".format(url))
        output = requests.get(url, headers=Redmine.headers, verify=False)
        logger.info("get version list output and status: {0} and {1}".format(
            output, output.status_code))
        return output, output.status_code

    # Create Redmine Version
    def redmine_post_version(self, logger, app, project_id, args):
        url = "http://{0}/projects/{1}/versions.json?key={2}".format(
            config.get('REDMINE_IP_PORT'), project_id, self.redmine_key)
        logger.info("url: {0}".format(url))
        output = requests.post(url,
                               data=json.dumps(args),
                               headers=Redmine.headers,
                               verify=False)
        logger.info("get wiki list output and status: {0} and {1}".format(
            output, output.status_code))
        return output, output.status_code

    def redmine_get_version(self, logger, app, version_id):
        url = "http://{0}/versions/{1}.json?key={2}".format(
            config.get('REDMINE_IP_PORT'), version_id, self.redmine_key)
        logger.info("url: {0}".format(url))
        output = requests.get(url, headers=Redmine.headers, verify=False)
        logger.info("get version output and status: {0} and {1}".format(
            output, output.status_code))
        return output, output.status_code

    def redmine_put_version(self, logger, app, version_id, args):
        url = "http://{0}/versions/{1}.json?key={2}".format(
            config.get('REDMINE_IP_PORT'), version_id, self.redmine_key)
        logger.info("url: {0}".format(url))
        output = requests.put(url,
                              data=json.dumps(args),
                              headers=Redmine.headers,
                              verify=False)
        logger.info("put redmine  output and status: {0} and {1}".format(
            output, output.status_code))
        return output, output.status_code

    def redmine_delete_version(self, logger, app, version_id):
        url = "http://{0}/versions/{1}.json?key={2}".format(
            config.get('REDMINE_IP_PORT'), version_id, self.redmine_key)
        logger.info("url: {0}".format(url))
        output = requests.delete(url, headers=Redmine.headers, verify=False)
        logger.info("Delete version output and status: {0} and {1}".format(
            output, output.status_code))
        return output, output.status_code

    def redmine_create_memberships(self, logger, app, project_id, user_id,
                                   role_id):
        url = "http://{0}/projects/{1}/memberships.json?key={2}".format(
            config.get('REDMINE_IP_PORT'), project_id, self.redmine_key)
        param = {"membership": {"user_id": user_id, "role_ids": [role_id]}}
        logger.info("redmine create membership url: {0}".format(url))
        # logger.info("post user param: {0}".format(param))
        output = requests.post(url,
                               data=json.dumps(param),
                               headers=self.headers,
                               verify=False)
        #logger.info("redmine create membership message: {0}".format(output.text))
        logger.info("post status code: {0}".format(output.status_code))
        return output, output.status_code

    def redmine_delete_memberships(self, logger, app, membership_id):
        url = "http://{0}/memberships/{1}.json?key={2}".format(
            config.get('REDMINE_IP_PORT'), membership_id, self.redmine_key)
        output = requests.delete(url, headers=self.headers, verify=False)
        logger.info("delete status code: {0}".format(output.status_code))
        logger.info("redmine_delete_memberships message: {0}".format(
            output.text))
        return output, output.status_code

    def redmine_get_memberships_list(self, logger, app, project_id):
        url = "http://{0}/projects/{1}/memberships.json?key={2}".format(
            config.get('REDMINE_IP_PORT'), project_id, self.redmine_key)
        logger.info("redmine get membership list url: {0}".format(url))
        output = requests.get(url, headers=self.headers, verify=False)
        logger.info("post status code: {0}".format(output.status_code))
        return output, output.status_code

    def redmine_upload(self, args):
        if 'upload_file' in args:
            file = args['upload_file']
            if file is None:
                return None
        else:
            return None
        headers = {'Content-Type': 'application/octet-stream'}
        res = self.api_post('/uploads', data=file, headers=headers)
        if res.status_code != 201:
            return util.respond(res.status_code, "Error while uploading to redmine", res.text)
        token = res.json().get('upload').get('token')
        filename = file.filename
        del args['upload_file']
        if 'upload_filename' in args:
            filename = args['upload_filename']
            del args['upload_filename']
        ret = {
            'token': token,
            'filename': filename
        }
        if 'upload_description' in args:
            ret['description'] = args['upload_description']
            del args['upload_description']
        return ret

    def redmine_upload_to_project(self, plan_project_id, args):
        if plan_project_id < 0:
            return util.respond(400, 'Project does not exist.')
        parse = reqparse.RequestParser()
        parse.add_argument('file', type=werkzeug.datastructures.FileStorage, location='files')
        f_args = parse.parse_args()
        file = f_args['file']
        if file is None:
            return util.respond(400, 'No file is sent.')
        headers = {'Content-Type': 'application/octet-stream'}
        res = self.api_post('/uploads', data=file, headers=headers)
        if res.status_code != 201:
            return util.respond(res.status_code, "Error while uploading to redmine", res.text)
        token = res.json().get('upload').get('token')
        filename = args['filename']
        if filename is None:
            filename = file.filename
        params = {
            'token': token,
            'filename': filename
        }
        if args['description'] is not None:
            params['description'] = args['description']
        if args['version_id'] is not None:
            params['version_id'] = args['version_id']
        data = {'file': params}
        res = self.api_post('/projects/%d/files' % plan_project_id, data=data)
        if res.status_code == 204:
            return None, 201
        else:
            return util.respond(res.status_code, "Error while adding the file to redmine", res.text)

    def redmine_list_file(self, plan_project_id):
        res = self.api_get('/projects/%d/files' % plan_project_id)
        return {"message": "success", "data": res.json()}, 200

    def redmine_download_attachment(self, args):
        a_id = args['id']
        filename = args['filename']
        try:
            url = "http://{0}/attachments/download/{1}/{2}?key={3}".format(
                config.get('REDMINE_IP_PORT'),
                a_id,
                filename,
                self.redmine_key)
            r = requests.get(url, headers=self.headers, verify=False)
            file_obj = BytesIO(r.content)
            return send_file(
                file_obj,
                attachment_filename=filename
            )
        except Exception as e:
            return {"message": "error", "data": e.__str__()}, 400

    def redmine_create_project(self, args):
        xml_body = """<?xml version="1.0" encoding="UTF-8"?>
                    <project>
                    <name>{0}</name>
                    <identifier>{1}</identifier>
                    <description>{2}</description>
                    <is_public>false</is_public>
                    </project>""".format(
            args["display"],
            args["identifier"],
            args["description"])
        logger.info("create redmine project body: {0}".format(xml_body))
        headers = {'Content-Type': 'application/xml'}
        redmine_output = self.api_post('/projects',
                                       headers=headers,
                                       data=xml_body.encode('utf-8'))
        logger.info("create redmine project output: {0} / {1}".format(
            redmine_output, redmine_output.json()))

        return redmine_output

    def redmine_delete_project(self, plan_project_id):
        logger.info("delete redmine project plan_id: {0}".format(plan_project_id))
        redmine_output = self.api_delete('/projects/{0}'.format(plan_project_id))
        logger.info("delete redmine project output: {0}".format(redmine_output))
        return redmine_output

