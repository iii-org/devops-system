import time
from io import BytesIO

import requests
import werkzeug
from flask import send_file
from flask_jwt_extended import jwt_required
from flask_restful import reqparse, Resource

import config
import resources.apiError as apiError
import util as util
from resources.apiError import DevOpsError
from resources.logger import logger


class Redmine:
    def __init__(self):
        self.key_generated = 0.0
        self.last_operator_id = None
        self.redmine_key = None

    def __api_request(self, method, path, headers=None, params=None, data=None,
                      operator_id=None, resp_format='.json'):
        self.__key_check()
        if headers is None:
            headers = {}
        if params is None:
            params = {}
        if 'Content-Type' not in headers:
            headers['Content-Type'] = 'application/json'

        url = f"{config.get('REDMINE_INTERNAL_BASE_URL')}{path}{resp_format}"
        if operator_id is not None:
            if operator_id != self.last_operator_id:
                self.last_operator_id = operator_id
                self.__refresh_key(operator_id)
        else:
            if self.last_operator_id is not None:
                self.last_operator_id = None
                self.__refresh_key()
        params['key'] = self.redmine_key

        output = util.api_request(method, url, headers, params, data)

        if resp_format != '':
            logger.info('redmine api {0} {1}, params={2}, body={5}, response={3} {4}'.format(
                method, url, params.__str__(), output.status_code, output.text, data))
        if int(output.status_code / 100) != 2:
            raise apiError.DevOpsError(
                output.status_code,
                'Got non-2xx response from Redmine.',
                apiError.redmine_error(output))
        return output

    def __api_get(self, path, params=None, headers=None,
                  resp_format='.json'):
        return self.__api_request('GET', path, params=params, headers=headers, resp_format=resp_format)

    def __api_post(self, path, params=None, headers=None, data=None,
                   operator_id=None, resp_format='.json'):
        return self.__api_request('POST', path, headers=headers, data=data, params=params,
                                  operator_id=operator_id, resp_format=resp_format)

    def __api_put(self, path, params=None, headers=None, data=None,
                  operator_id=None, resp_format='.json'):
        return self.__api_request('PUT', path, headers=headers, data=data, params=params,
                                  operator_id=operator_id, resp_format=resp_format)

    def __api_delete(self, path, params=None, headers=None,
                     operator_id=None, resp_format='.json'):
        return self.__api_request('DELETE', path, params=params, headers=headers,
                                  operator_id=operator_id, resp_format=resp_format)

    def __key_check(self):
        # Check if key expires first, seems to expire in 2 hours in default?
        if self.redmine_key is None or time.time() - self.key_generated >= 7200:
            self.__refresh_key()

    def __refresh_key(self, operator_id=None):
        protocol = 'http'
        host = config.get('REDMINE_INTERNAL_BASE_URL')[len(protocol + '://'):]
        if operator_id is None:
            # get redmine_key
            url = f"{protocol}://{config.get('REDMINE_ADMIN_ACCOUNT')}" \
                  f":{config.get('REDMINE_ADMIN_PASSWORD')}" \
                  f"@{host}/users/current.json"
            self.key_generated = time.time()
        else:
            url = f"{protocol}://{config.get('REDMINE_ADMIN_ACCOUNT')}" \
                  f":{config.get('REDMINE_ADMIN_PASSWORD')}" \
                  f"@{host}/users/{operator_id}.json"
        output = requests.get(url, headers={'Content-Type': 'application/json'}, verify=False)
        self.redmine_key = output.json()['user']['api_key']

    # --------------- Normal methods ---------------

    def paging(self, key, params=None):
        if params is None:
            params = {}
        offset = 0
        ret = []
        path = '/{0}'.format(key)
        params['limit'] = 100
        while True:
            res = self.__api_get(path=path, params=params).json().get(key)
            ret.extend(res)
            if len(res) == 100:
                offset += 100
                params['offset'] = offset
            else:
                break
        return ret

    def rm_list_projects(self):
        return self.paging('projects')

    def rm_get_project(self, plan_project_id):
        return self.__api_get('/projects/{0}'.format(plan_project_id)).json()

    def rm_update_project(self, plan_project_id, args):
        xml_body = """<?xml version="1.0" encoding="UTF-8"?>
                <project>
                <name>{0}</name>
                <description>{1}</description>
                </project>""".format(
            args["display"],
            args["description"])
        headers = {'Content-Type': 'application/xml'}
        return self.__api_put('/projects/{0}'.format(plan_project_id),
                              headers=headers,
                              data=xml_body.encode('utf-8'))

    def rm_delete_project(self, plan_project_id):
        return self.__api_delete('/projects/{0}'.format(plan_project_id))

    def rm_list_issues(self):
        params = {'status_id': '*'}
        return self.paging('issues', params)

    def rm_get_issues_by_user(self, user_id):
        params = {'assigned_to_id': user_id, 'status_id': '*'}
        return self.paging('issues', params)

    def rm_get_issues_by_project(self, plan_project_id, args=None):
        if args is not None and 'fixed_version_id' in args:
            params = {'project_id': plan_project_id, 'status_id': '*',
                      'fixed_version_id': args['fixed_version_id']}
        else:
            params = {'project_id': plan_project_id, 'status_id': '*'}
        return self.paging('issues', params)

    def rm_get_issues_by_project_and_user(self, user_id, plan_project_id):
        params = {
            'assigned_to_id': user_id,
            'project_id': plan_project_id,
            'status_id': '*'
        }
        return self.paging('issues', params)

    def rm_get_issue(self, issue_id):
        params = {'include': 'journals,attachments'}
        output = self.__api_get('/issues/{0}'.format(issue_id), params=params)
        return output

    def rm_get_statistics(self, params):
        if 'status_id' not in params:
            params['status_id'] = '*'
        return self.__api_get('/issues', params=params).json()

    def rm_create_issue(self, args, operator_id):
        return self.__api_post('/issues', data={"issue": args},
                               operator_id=operator_id).json()

    def rm_update_issue(self, issue_id, args, operator_id):
        return self.__api_put('/issues/{0}'.format(issue_id),
                              data={"issue": args}, operator_id=operator_id)

    def rm_delete_issue(self, issue_id):
        params = {'include': 'journals,attachment'}
        return self.__api_delete('/issues/{0}'.format(issue_id), params=params)

    def rm_get_issue_status(self):
        return self.__api_get('/issue_statuses').json()

    def rm_get_priority(self):
        return self.__api_get('/enumerations/issue_priorities').json()

    def rm_get_trackers(self):
        return self.__api_get('/trackers').json()

    def rm_create_user(self, args, user_source_password, is_admin=False):
        params = {
            "user": {
                "login": args["login"],
                "firstname": '#',
                "lastname": args["name"],
                "mail": args["email"],
                "password": user_source_password
            }
        }
        if is_admin:
            params['user']['admin'] = True
        return self.__api_post('/users', data=params).json()

    def rm_update_password(self, plan_user_id, new_pwd):
        param = {"user": {"password": new_pwd}}
        return self.__api_put('/users/{0}'.format(plan_user_id), data=param)

    def rm_get_user_list(self, args):
        return self.__api_get('/users', params=args).json()

    def rm_delete_user(self, redmine_user_id):
        return self.__api_delete('/users/{0}'.format(redmine_user_id))

    def rm_get_wiki_list(self, project_id):
        return self.__api_get('/projects/{0}/wiki/index'.format(project_id)).json()

    def rm_get_wiki(self, project_id, wiki_name):
        return self.__api_get('/projects/{0}/wiki/{1}'.format(
            project_id, wiki_name)).json()

    def rm_put_wiki(self, project_id, wiki_name, args, operator_id):
        param = {"wiki_page": {"text": args['wiki_text']}}
        return self.__api_put('/projects/{0}/wiki/{1}'.format(project_id, wiki_name),
                              data=param, operator_id=operator_id)

    def rm_delete_wiki(self, project_id, wiki_name):
        return self.__api_delete('/projects/{0}/wiki/{1}'.format(
            project_id, wiki_name))

    # Get Redmine Version List
    def rm_get_version_list(self, project_id):
        return self.__api_get('/projects/{0}/versions'.format(project_id)).json()

    # Create Redmine Version
    def rm_post_version(self, project_id, args):
        return self.__api_post('/projects/{0}/versions'.format(
            project_id), data=args).json()

    def rm_get_version(self, version_id):
        return self.__api_get('/versions/{0}'.format(version_id)).json()

    def rm_put_version(self, version_id, args):
        return self.__api_put('/versions/{0}'.format(version_id), data=args)

    def rm_delete_version(self, version_id):
        return self.__api_delete('/versions/{0}'.format(version_id))

    def rm_create_memberships(self, project_id, user_id, role_id):
        param = {"membership": {"user_id": user_id, "role_ids": [role_id]}}
        return self.__api_post('/projects/{0}/memberships'.format(project_id),
                               data=param)

    def rm_delete_memberships(self, membership_id):
        return self.__api_delete('/memberships/{0}'.format(membership_id))

    def rm_get_memberships_list(self, project_id):
        return self.__api_get('/projects/{0}/memberships'.format(project_id)).json()

    def rm_upload(self, args):
        if 'upload_file' in args:
            file = args['upload_file']
            if file is None:
                return None
        else:
            return None
        headers = {'Content-Type': 'application/octet-stream'}
        res = self.__api_post('/uploads', data=file, headers=headers)
        if res.status_code != 201:
            raise DevOpsError(res.status_code, "Error while uploading to redmine",
                              error=apiError.redmine_error(res.text))
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

    def rm_upload_to_project(self, plan_project_id, args):
        parse = reqparse.RequestParser()
        parse.add_argument('file', type=werkzeug.datastructures.FileStorage, location='files')
        f_args = parse.parse_args()
        file = f_args['file']
        if file is None:
            raise DevOpsError(400, 'No file is sent.',
                              error=apiError.argument_error('file'))
        headers = {'Content-Type': 'application/octet-stream'}
        res = self.__api_post('/uploads', data=file, headers=headers)
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
        res = self.__api_post('/projects/%d/files' % plan_project_id, data=data)
        if res.status_code == 204:
            return util.respond(201, None)
        else:
            raise DevOpsError(res.status_code, "Error while adding the file to redmine",
                              error=apiError.redmine_error(res.text))

    def rm_list_file(self, plan_project_id):
        return self.__api_get('/projects/%d/files' % plan_project_id).json()

    def rm_download_attachment(self, args):
        a_id = args['id']
        filename = args['filename']
        try:
            r = self.__api_get('/attachments/download/{0}/{1}'.format(
                a_id, filename
            ), resp_format='')
            file_obj = BytesIO(r.content)
            return send_file(
                file_obj,
                attachment_filename=filename
            )
        except Exception as e:
            raise DevOpsError(500, 'Error when downloading an attachment.',
                              error=apiError.uncaught_exception(e))

    def rm_delete_attachment(self, attachment_id):
        output = self.__api_delete('/attachments/{0}'.format(attachment_id))
        status_code = output.status_code
        if status_code == 204:
            return util.success()
        elif status_code == 404:
            return util.respond(200, 'File is already deleted.')
        else:
            raise DevOpsError(status_code, "Error while deleting attachments.",
                              error=apiError.redmine_error(output))

    def rm_create_project(self, args):
        xml_body = """<?xml version="1.0" encoding="UTF-8"?>
                    <project>
                    <name>{0}</name>
                    <identifier>{1}</identifier>
                    <description>{2}</description>
                    <is_public>false</is_public>
                    </project>""".format(
            args["display"],
            args["name"],
            args["description"])
        headers = {'Content-Type': 'application/xml'}
        return self.__api_post('/projects',
                               headers=headers,
                               data=xml_body.encode('utf-8')).json()

    @staticmethod
    def rm_build_external_link(path):
        return f"{config.get('REDMINE_EXTERNAL_BASE_URL')}{path}"


# --------------------- Resources ---------------------
redmine = Redmine()


class RedmineFile(Resource):
    @jwt_required
    def get(self):
        parser = reqparse.RequestParser()
        parser.add_argument('id', type=int)
        parser.add_argument('filename', type=str)
        args = parser.parse_args()
        return redmine.rm_download_attachment(args)

    @jwt_required
    def delete(self, file_id):
        return redmine.rm_delete_attachment(file_id)
