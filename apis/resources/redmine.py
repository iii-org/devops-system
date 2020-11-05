from io import BytesIO

import json
import logging, config, time
import requests
import werkzeug
from .util import util
from flask import send_file
from flask_restful import reqparse

# from model import db, Project_relationship
# from .util import util

logger = logging.getLogger('devops.api')


class Redmine(object):

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

    def api_post(self, path, data=None, params=None):
        self.key_check()
        if data is None:
            data = {}
        if params is None:
            params = {}
        params['key'] = self.redmine_key
        url = "http://{0}{1}.json".format(config.get('REDMINE_IP_PORT'), path)
        headers = self.headers.copy()
        if type(data) is dict:
            output = requests.post(url, data=json.dumps(data), params=params,
                                   headers=headers, verify=False)
        else:
            headers['Content-Type'] = 'application/octet-stream'
            output = requests.post(url, data=data, params=params,
                                   headers=headers, verify=False)
        return output

    def api_get(self, path):
        self.key_check()
        url = "http://{0}{1}.json?key={2}".format(
            config.get('REDMINE_IP_PORT'), path, self.redmine_key)
        output = requests.get(url, headers=self.headers, verify=False)
        return output

    def key_check(self):
        # Check if key expires first, seems to expire in 2 hours in default
        if time.time() - self.key_generated >= 7200:
            self.get_redmine_key()

    def get_redmine_key(self, logger=logger, app=None):
        # get redmine_key
        url = "http://{0}:{1}@{2}/users/current.json".format(config.get('REDMINE_ADMIN_ACCOUNT'), \
                                                             config.get('REDMINE_ADMIN_PASSWORD'), config.get('REDMINE_IP_PORT'))
        output = requests.get(url, headers=Redmine.headers, verify=False)
        self.redmine_key = output.json()['user']['api_key']
        self.key_generated = time.time()
        logger.info("redmine_key: {0}".format(self.redmine_key))
        return self.redmine_key

    def redmine_get_issues_by_user(self, logger, app, user_id):

        url = "http://{0}/issues.json?key={1}&assigned_to_id={2}&limit=100&status_id=*".format(\
            config.get('REDMINE_IP_PORT'), self.redmine_key, user_id)
        output = requests.get(url, headers=self.headers, verify=False)
        logger.info("get issues by output: {0}".format(output.json()))
        return output.json()

    def redmine_get_issues_by_project(self, plan_project_id, args):
        args['key'] = self.redmine_key
        args['project_id'] = plan_project_id
        args['limit'] = 1000
        args['status_id'] = '*'
        url = "http://{0}/issues.json".format(config.get('REDMINE_IP_PORT'))
        output = requests.get(url,
                              params=args,
                              headers=self.headers,
                              verify=False)
        logger.info("get issues by project output: {0}".format(output.json()))
        return output.json()

    def redmine_get_issues_by_project_and_user(self, logger, app, user_id,
                                               project_id, redmine_key):
        url = "http://{0}/issues.json?key={1}&assigned_to_id={2}&project_id={3}&status_id=*".format(\
            config.get('REDMINE_IP_PORT'), redmine_key, user_id, project_id)
        output = requests.get(url, headers=self.headers, verify=False)
        logger.info("get issues by project&user output: {0}".format(
            output.json()))
        return output.json()

    def redmine_get_issue(self, logger, app, issue_id):
        url = "http://{0}/issues/{1}.json?key={2}&include=journals,attachments".format(
            config.get('REDMINE_IP_PORT'), issue_id, self.redmine_key)
        output = requests.get(url, headers=self.headers, verify=False)
        logger.info("get issues output: {0}".format(output))
        return output

    def redmine_get_statistics(self, logger, app, args):
        args['key'] = self.redmine_key
        args['status_id'] = '*'
        url = "http://{0}/issues.json".format(config.get('REDMINE_IP_PORT'))
        logger.info("args: {0}".format(args))
        output = requests.get(url,
                              headers=self.headers,
                              verify=False,
                              params=args)
        logger.info("get issues output: {0}".format(output.json()))
        return output.json(), output.status_code

    def redmine_create_issue(self, args):
        url = "http://{0}/issues.json?key={1}".format(
            config.get('REDMINE_IP_PORT'), self.redmine_key)
        param = {"issue": args}
        logger.info("create issues param: {0}".format(param))
        output = requests.post(url,
                               data=json.dumps(param),
                               headers=self.headers,
                               verify=False)
        logger.info("create issues output: {0}, status_code: {1}".format(
            output.json(), output.status_code))
        return output, output.status_code

    def redmine_update_issue(self, logger, app, issue_id, args):
        url = "http://{0}/issues/{1}.json?key={2}".format(
            config.get('REDMINE_IP_PORT'), issue_id, self.redmine_key)
        param = {"issue": args}
        logger.info("update issues param: {0}".format(param))
        output = requests.put(url,
                              data=json.dumps(param),
                              headers=self.headers,
                              verify=False)
        logger.info("update issues output: {0}, status_code: {1}".format(
            output.text, output.status_code))
        return output, output.status_code

    def redmine_delete_issue(self, issue_id):
        url = "http://{0}/issues/{1}.json?key={2}&include=journals".format(
            config.get('REDMINE_IP_PORT'), issue_id, self.redmine_key)
        output = requests.delete(url, headers=self.headers, verify=False)
        logger.info("redmine delete user output: {0}".format(output))
        return output

    def redmine_get_issue_status(self, logger, app):
        url="http://{0}/issue_statuses.json?key={1}".format(\
            config.get('REDMINE_IP_PORT'), self.redmine_key,)
        output = requests.get(url, headers=self.headers, verify=False)
        logger.info("get issues stauts list output: {0}".format(output.json()))
        return output.json()

    def redmine_get_priority(self, logger, app):
        url="http://{0}/enumerations/issue_priorities.json?key={1}".format(\
            config.get('REDMINE_IP_PORT'), self.redmine_key)
        output = requests.get(url, headers=self.headers, verify=False)
        logger.info("get issues stauts list output: {0}".format(output.json()))
        return output.json()

    def redmine_get_trackers(self, logger, app):
        url="http://{0}/trackers.json?key={1}".format(\
            config.get('REDMINE_IP_PORT'), self.redmine_key)
        output = requests.get(url, headers=self.headers, verify=False)
        logger.info("get issues stauts list output: {0}".format(output.json()))
        return output.json()

    def redmine_post_user(self, logger, app, args, user_source_password):
        url = "http://{0}/users.json?key={1}".format(
            config.get('REDMINE_IP_PORT'), self.redmine_key)
        param = {
            "user": {
                "login": args["login"],
                "firstname": '#',
                "lastname": args["name"],
                "mail": args["email"],
                "password": user_source_password
            }
        }
        logger.info("post user param: {0}".format(param))
        output = requests.post(url,
                               data=json.dumps(param),
                               headers=self.headers,
                               verify=False)
        logger.info(
            "redmine create user api output: status_code: {0}, message: {1}".
            format(output.status_code, output.json()))
        return output

    def redmine_update_password(self, plan_user_id, new_pwd):
        url = "http://{0}/users/{1}.json?key={2}".format(
            config.get('REDMINE_IP_PORT'), plan_user_id, self.redmine_key)
        param = {"user": {"password": new_pwd}}
        output = requests.put(url,
                              data=json.dumps(param),
                              headers=self.headers,
                              verify=False)
        if output.status_code == 204:
            return None
        else:
            return output

    def redmine_get_user_list(self, args):
        args['key'] = self.redmine_key
        url = "http://{0}/users.json".format(
            config.get('REDMINE_IP_PORT'))
        logger.info("args: {0}".format(args))
        output = requests.get(url,
                              headers=self.headers,
                              verify=False,
                              params=args)
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

    def redmine_get_wiki_list(self, logger, app, project_id):
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
        res = self.api_post('/uploads', file)
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
        res = self.api_post('/uploads', file)
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
        res = self.api_post('/projects/%d/files' % plan_project_id, data)
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

