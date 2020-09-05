from flask import Flask
from flask import Response
from flask import jsonify
from flask import request as flask_req
from flask_restful import Resource, Api, reqparse
from flask_jwt_extended import jwt_required, get_jwt_identity

import logging
from logging import handlers
import json
import datetime
from model import db

from jsonwebtoken import jsonwebtoken
from urllib.parse import urlparse

import resources.util as util
import resources.auth as auth
import resources.issue as issue
import resources.redmine as redmine
import resources.project as project
import resources.pipeline as pipeline
import resources.requirement as requirement
import resources.parameter as parameter
import resources.testCase as testCase
import resources.testItem as testItem
import resources.testValue as testValue
import resources.wiki as wiki
import resources.version as version
import resources.testData as testData
import resources.flow as flow
import resources.testResult as testResult

app = Flask(__name__)
app.config.from_object('config')
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = datetime.timedelta(days=1)
api = Api(app)

handler = handlers.TimedRotatingFileHandler(
    'devops-api.log', when='D' \
    , interval=1, backupCount=14)
handler.setFormatter(logging.Formatter(
    '%(asctime)s %(filename)s [line:%(lineno)d] %(levelname)s %(message)s' \
    , '%Y %b %d, %a %H:%M:%S'))
logger = logging.getLogger('devops.api')
logger.setLevel(logging.DEBUG)
logger.addHandler(handler)

ut = util.util()
au = auth.auth(logger, app)
redmine = redmine.Redmine(logger, app)
iss = issue.Issue()
pjt = project.Project(logger, app)
pipe = pipeline.Pipeline()
wk = wiki.Wiki()
vn = version.Version()

rqmt = requirement.Requirement()
flow = flow.Flow()
param = parameter.Parameter()
tc = testCase.TestCase()
ti = testItem.TestItem()
tv = testValue.TestValue()
td = testData.TestData()
tr = testResult.TestResult()


class Index(Resource):
    def get(self):
        iss.create_data_into_project_relationship(logger)
        return {"message": "DevOps api is working"}


class TotalProjectList(Resource):
    @jwt_required
    def get(self):
        role_id = get_jwt_identity()["role_id"]
        print("role_id={0}".format(role_id))

        if role_id in (3, 5):
            user_id = get_jwt_identity()["user_id"]
            print("user_id={0}".format(user_id))
            try:
                output = pjt.get_pm_project_list(logger, app, user_id)
                return output
            except Exception as error:
                return {"message": str(error)}, 400
        else:
            return {"message": "您無權限訪問！"}, 401


class CreateProject(Resource):
    @jwt_required
    def post(self):
        role_id = get_jwt_identity()["role_id"]
        print("role_id={0}".format(role_id))

        if role_id == (3, 5):
            user_id = get_jwt_identity()["user_id"]
            print("user_id={0}".format(user_id))
            parser = reqparse.RequestParser()
            parser.add_argument('name', type=str, required=True)
            parser.add_argument('description', type=str)
            parser.add_argument('disabled', type=bool, required=True)
            args = parser.parse_args()
            logger.info("post body: {0}".format(args))
            try:
                output = pjt.pm_create_project(logger, app, user_id, args)
                return output
            except Exception as error:
                return {"message": str(error)}, 400
        else:
            return {"message": "您無權限訪問！"}, 401


class Project(Resource):
    @jwt_required
    def get(self, project_id):
        role_id = get_jwt_identity()["role_id"]
        print("role_id={0}".format(role_id))

        if role_id in (3, 5):
            try:
                output = pjt.pm_get_project(logger, app, project_id)
                return output
            except Exception as error:
                return {"message": str(error)}, 400
        else:
            return {"message": "您無權限訪問！"}, 401

    @jwt_required
    def put(self, project_id):
        role_id = get_jwt_identity()["role_id"]
        print("role_id={0}".format(role_id))

        if role_id in (3, 5):
            # user_id = get_jwt_identity()["user_id"]
            # print("user_id={0}".format(user_id))
            parser = reqparse.RequestParser()
            parser.add_argument('name', type=str)
            parser.add_argument('user_id', type=int)
            parser.add_argument('description', type=str)
            parser.add_argument('disabled', type=bool)
            # parser.add_argument('homepage', type=str)
            args = parser.parse_args()
            logger.info("put body: {0}".format(args))
            try:
                output = pjt.pm_update_project(logger, app, project_id, args)
                return output
            except Exception as error:
                return {"message": str(error)}, 400
        else:
            return {"message": "您無權限訪問！"}, 401

    @jwt_required
    def delete(self, project_id):
        role_id = get_jwt_identity()["role_id"]
        print("role_id={0}".format(role_id))

        if role_id in (3, 5):
            try:
                output = pjt.pm_delete_project(logger, app, project_id)
                return output
            except Exception as error:
                return {"message": str(error)}, 400
        else:
            return {"message": "您無權限訪問！"}, 401


class GitProjects(Resource):
    @jwt_required
    def get(self):
        output = pjt.get_all_git_projects(logger, app)
        return output.json()

    @jwt_required
    def post(self):
        parser = reqparse.RequestParser()
        parser.add_argument('name', type=str)
        parser.add_argument('visibility', type=str)
        args = parser.parse_args()
        logger.info("post body: {0}".format(args))
        output = pjt.create_git_project(logger, app, args)
        return output.json()


class GitOneProject(Resource):
    @jwt_required
    def get(self, project_id):
        output = pjt.get_one_git_project(logger, app, project_id)
        return output.json()

    @jwt_required
    def put(self, project_id):
        parser = reqparse.RequestParser()
        parser.add_argument('name', type=str)
        parser.add_argument('visibility', type=str)
        args = parser.parse_args()
        logger.info("put body: {0}".format(args))
        output = pjt.update_git_project(logger, app, project_id, args)

    @jwt_required
    def delete(self, project_id):
        output = pjt.delete_git_project(logger, app, project_id)
        return output.json()


class GitProjectWebhooks(Resource):
    @jwt_required
    def get(self, project_id):
        output = pjt.get_git_project_webhooks(logger, app, project_id)
        return output.json()

    @jwt_required
    def post(self, project_id):
        parser = reqparse.RequestParser()
        parser.add_argument('url', type=str)
        parser.add_argument('push_events', type=bool)
        parser.add_argument('push_events_branch_filter', type=str)
        parser.add_argument('enable_ssl_verification', type=bool)
        parser.add_argument('token', type=str)
        args = parser.parse_args()
        logger.info("post body: {0}".format(args))
        output = pjt.create_git_project_webhook(logger, app, project_id, args)
        return output.json()

    @jwt_required
    def put(self, project_id):
        parser = reqparse.RequestParser()
        parser.add_argument('hook_id', type=int)
        parser.add_argument('url', type=str)
        parser.add_argument('push_events', type=bool)
        parser.add_argument('push_events_branch_filter', type=str)
        parser.add_argument('enable_ssl_verification', type=bool)
        parser.add_argument('token', type=str)
        args = parser.parse_args()
        logger.info("put body: {0}".format(args))
        output = pjt.update_git_project_webhook(logger, app, project_id, args)
        return output.json()

    @jwt_required
    def delete(self, project_id):
        parser = reqparse.RequestParser()
        parser.add_argument('hook_id', type=int)
        args = parser.parse_args()
        logger.info("del body: {0}".format(args))
        output = pjt.delete_git_project_webhook(logger, app, project_id, args)


class ProjectList(Resource):
    @jwt_required
    def get(self, user_id):
        if int(user_id) == get_jwt_identity()['user_id'] or get_jwt_identity(
        )['role_id'] in (3, 5):
            output_array = pjt.get_project_list(logger, app, user_id)
            return jsonify({'message': 'success', 'data': output_array})
        else:
            return {'message': 'Access token is missing or invalid'}, 401


class UserLogin(Resource):
    def post(self):
        parser = reqparse.RequestParser()
        parser.add_argument('username', type=str, required=True)
        parser.add_argument('password', type=str, required=True)
        args = parser.parse_args()
        output = au.user_login(logger, args)
        return output


class UserForgetPassword(Resource):
    def post(self):
        parser = reqparse.RequestParser()
        parser.add_argument('mail', type=str, required=True)
        parser.add_argument('user_account', type=str, required=True)
        args = parser.parse_args()
        try:
            status = au.user_forgetpassword(logger, args)
            return jsonify({"message": "success"})
        except Exception as err:
            return jsonify({"message": err}), 400


class UserInfo(Resource):
    @jwt_required
    def get(self, user_id):
        logger.debug("int(user_id): {0}".format(int(user_id)))
        logger.debug("get_jwt_identity()['user_id']: {0}".format(
            get_jwt_identity()['user_id']))
        if int(user_id) == get_jwt_identity()['user_id'] or get_jwt_identity(
        )['role_id'] not in (1, 3, 5):
            user_info = au.user_info(logger, user_id)
            return user_info
        else:
            return {
                'message': 'you dont have authorize to update user informaion'
            }, 401

    @jwt_required
    def put(self, user_id):
        if int(user_id) == get_jwt_identity()['user_id'] or get_jwt_identity(
        )['role_id'] == 5:
            parser = reqparse.RequestParser()
            parser.add_argument('name', type=str)
            parser.add_argument('password', type=str)
            parser.add_argument('phone', type=int)
            parser.add_argument('email', type=str)
            parser.add_argument('project_id', action='append')
            parser.add_argument('status', type=str)
            args = parser.parse_args()
            try:
                output = au.update_user_info(logger, user_id, args)
                return output
            except Exception as error:
                return jsonify({"message": str(error)}), 400
        else:
            return {
                'message': 'you dont have authorize to update user informaion'
            }, 401

    @jwt_required
    def delete(self, user_id):
        '''delete user'''
        if get_jwt_identity()["role_id"] == 5:
            try:
                output = au.delete_user(logger, app, user_id)
                return output
            except Exception as error:
                return {"message": str(error)}, 400
        else:
            return {"message": "your role art not administrator"}, 401


class UserStatus(Resource):
    @jwt_required
    def put(self, user_id):
        '''Change user status'''
        if get_jwt_identity()["role_id"] == 5:
            parser = reqparse.RequestParser()
            parser.add_argument('status', type=str, required=True)
            args = parser.parse_args()
            output = au.put_user_status(logger, user_id, args)
            return output
        else:
            return {"message": "your role art not administrator"}, 401


class User(Resource):
    @jwt_required
    def post(self):
        '''create user'''
        if get_jwt_identity()["role_id"] == 5:
            parser = reqparse.RequestParser()
            parser.add_argument('name', type=str)
            parser.add_argument('email', type=str, required=True)
            parser.add_argument('phone', type=int, required=True)
            parser.add_argument('login', type=str, required=True)
            parser.add_argument('password', type=str, required=True)
            parser.add_argument('project_id', action='append')
            parser.add_argument('role_id', type=int, required=True)
            parser.add_argument('status', type=str)
            args = parser.parse_args()
            output = au.create_user(logger, args, app)
            return output
        else:
            return {"message": "your role art not administrator"}, 401


class UserList(Resource):
    @jwt_required
    def get(self):
        if get_jwt_identity()["role_id"] in (3, 5):
            output = au.get_user_list(logger)
            return output
        else:
            return {"message": "your role art not administrator"}, 401


class ProjectUserList(Resource):
    @jwt_required
    def get(self, project_id):
        if get_jwt_identity()["role_id"] in (3, 5):
            parser = reqparse.RequestParser()
            parser.add_argument('exclude', type=int)
            args = parser.parse_args()
            output = au.get_userlist_by_project(logger, project_id, args)
            return output
        else:
            return {"message": "your role art not administrator"}, 401


class ProjectWikiList(Resource):
    @jwt_required
    def get(self, project_id):
        stauts = pjt.verify_project_user(logger, project_id,
                                         get_jwt_identity()['user_id'])
        if stauts or get_jwt_identity()['role_id'] == 5:
            output = wk.get_wiki_list_by_project(logger, app, project_id)
            return output
        else:
            return {
                "message": "your are not in this project or not administrator"
            }, 401


class ProjectWiki(Resource):
    @jwt_required
    def get(self, project_id, wiki_name):
        stauts = pjt.verify_project_user(logger, project_id,
                                         get_jwt_identity()['user_id'])
        if stauts or get_jwt_identity()['role_id'] == 5:
            output, status_code = wk.get_wiki_by_project(
                logger, app, project_id, wiki_name)
            return output, status_code
        else:
            return {
                "message": "your are not in this project or not administrator"
            }, 401

    @jwt_required
    def put(self, project_id, wiki_name):
        stauts = pjt.verify_project_user(logger, project_id,
                                         get_jwt_identity()['user_id'])
        if stauts or get_jwt_identity()['role_id'] == 5:
            parser = reqparse.RequestParser()
            parser.add_argument('wiki_text', type=str, required=True)
            args = parser.parse_args()
            output, status_code = wk.put_wiki_by_project(
                logger, app, project_id, wiki_name, args)
            return output, status_code
        else:
            return {
                "message": "your are not in this project or not administrator"
            }, 401

    @jwt_required
    def delete(self, project_id, wiki_name):
        stauts = pjt.verify_project_user(logger, project_id,
                                         get_jwt_identity()['user_id'])
        if stauts or get_jwt_identity()['role_id'] == 5:
            output, status_code = wk.delete_wiki_by_project(
                logger, app, project_id, wiki_name)
            return output, status_code
        else:
            return {
                "message": "your are not in this project or not administrator"
            }, 401

# Get Project Version List
class ProjectVersionList(Resource):
    @jwt_required
    def get(self, project_id):
        stauts = pjt.verify_project_user(logger, project_id,
                                         get_jwt_identity()['user_id'])
        if stauts or get_jwt_identity()['role_id'] == 5:
            output = vn.get_version_list_by_project(logger, app, project_id)
            return output
        else:
            return {
                "message": "your are not in this project or not administrator"
            }, 401


# Create  Project Version 
class ProjectVersion(Resource):
    @jwt_required
    def post(self, project_id):
        stauts = pjt.verify_project_user(logger, project_id,
                                         get_jwt_identity()['user_id'])
        if stauts or get_jwt_identity()['role_id'] == 5:
            root_parser = reqparse.RequestParser()
            root_parser.add_argument('version', type=dict, required=True)
            root_args = root_parser.parse_args()
            output, status_code = vn.post_version_by_project(
                logger, app, project_id, root_args)
            return output
        else:
            return {
                "message": "your are not in this project or not administrator"
            }, 401



# Get Project Version Information
class ProjectVersionInfo(Resource):
    @jwt_required
    def get(self, project_id, version_id):
        stauts = pjt.verify_project_user(logger, project_id,
                                         get_jwt_identity()['user_id'])
        if stauts or get_jwt_identity()['role_id'] == 5:
            output, status_code = vn.get_version_by_version_id(
                logger, app, project_id, version_id)
            return output, status_code
        else:
            return {
                "message": "your are not in this project or not administrator"
            }, 401

    @jwt_required
    def put(self, project_id, version_id):
        stauts = pjt.verify_project_user(logger, project_id,
                                         get_jwt_identity()['user_id'])
        if stauts or get_jwt_identity()['role_id'] == 5:
            root_parser = reqparse.RequestParser()
            root_parser.add_argument('version', type=dict, required=True)
            root_args = root_parser.parse_args()
            print(root_args)
            output, status_code = vn.put_version_by_version_id(
                logger, app, project_id, version_id, root_args)
            return output, status_code
        else:
            return {
                "message": "your are not in this project or not administrator"
            }, 401

    @jwt_required
    def delete(self, project_id, version_id):
        stauts = pjt.verify_project_user(logger, project_id,
                                         get_jwt_identity()['user_id'])
        if stauts or get_jwt_identity()['role_id'] == 5:
            output, status_code = vn.delete_version_by_version_id(
                logger, app, project_id, version_id )
            return output, status_code
        else:
            return {
                "message": "your are not in this project or not administrator"
            }, 401


class RoleList(Resource):
    @jwt_required
    def get(self):
        print("role_id is {0}".format(get_jwt_identity()["role_id"]))
        if get_jwt_identity()["role_id"] in (1, 3, 5):
            try:
                output = au.get_role_list(logger, app)
                return output
            except Exception as error:
                return {"message": str(error)}, 400
        else:
            return {"message": "your role art not administrator"}, 401


class GitProjectBranches(Resource):
    @jwt_required
    def get(self, repository_id):
        role_id = get_jwt_identity()["role_id"]
        print("role_id={0}".format(role_id))

        if role_id in (1, 3):
            project_id = repository_id
            try:
                output = pjt.get_git_project_branches(logger, app, project_id)
                return output
            except Exception as error:
                return {"message": str(error)}, 400
        else:
            return {"message": "您無權限訪問！"}, 401

    @jwt_required
    def post(self, repository_id):
        role_id = get_jwt_identity()["role_id"]
        print("role_id={0}".format(role_id))

        if role_id in (1, 5):
            project_id = repository_id
            parser = reqparse.RequestParser()
            parser.add_argument('branch', type=str, required=True)
            parser.add_argument('ref', type=str, required=True)
            args = parser.parse_args()
            logger.info("post body: {0}".format(args))
            output = pjt.create_git_project_branch(logger, app, project_id, args)
            return output
        else:
            return {"message": "您無權限訪問！"}, 401

class GitProjectBranch(Resource):
    @jwt_required
    def get(self, repository_id, branch_name):
        role_id = get_jwt_identity()["role_id"]
        print("role_id={0}".format(role_id))

        if role_id in (1, 5):
            project_id = repository_id
            branch = branch_name
            output = pjt.get_git_project_branch(logger, app, project_id, branch)
            return output
        else:
            return {"message": "您無權限訪問！"}, 401

    @jwt_required
    def delete(self, repository_id, branch_name):
        role_id = get_jwt_identity()["role_id"]
        print("role_id={0}".format(role_id))

        if role_id in (1, 5):
            project_id = repository_id
            branch = branch_name
            output = pjt.delete_git_project_branch(logger, app, project_id, branch)
            return output
        else:
            return {"message": "您無權限訪問！"}, 401


class GitProjectRepositories(Resource):
    @jwt_required
    def get(self, repository_id, branch_name):
        role_id = get_jwt_identity()["role_id"]
        print("role_id={0}".format(role_id))

        if role_id in (1, 5):
            project_id = repository_id
            branch = branch_name
            output = pjt.get_git_project_repositories(logger, app, project_id,
                                                      branch)
            return output
        else:
            return {"message": "您無權限訪問！"}, 401


class GitProjectFiles(Resource):
    @jwt_required
    def post(self, repository_id):
        role_id = get_jwt_identity()["role_id"]
        print("role_id={0}".format(role_id))

        if role_id in (1, 5):
            project_id = repository_id
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
            logger.info("post body: {0}".format(args))
            output = pjt.create_git_project_file(logger, app, project_id, args)

            return output

        else:
            return {"message": "您無權限訪問！"}, 401

    @jwt_required
    def put(self, repository_id):
        role_id = get_jwt_identity()["role_id"]
        print("role_id={0}".format(role_id))

        if role_id in (1, 5):
            project_id = repository_id
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
            logger.info("put body: {0}".format(args))
            output = pjt.update_git_project_file(logger, app, project_id, args)

            return output

        else:
            return {"message": "您無權限訪問！"}, 401


class GitProjectFile(Resource):
    @jwt_required
    def get(self, repository_id, branch_name, file_path):
        role_id = get_jwt_identity()["role_id"]
        print("role_id={0}".format(role_id))

        if role_id in (1, 5):
            project_id = repository_id
            branch = branch_name
            output = pjt.get_git_project_file(logger, app, project_id, branch,
                                              file_path)
            return output

        else:
            return {"message": "您無權限訪問！"}, 401

    @jwt_required
    def delete(self, repository_id, branch_name, file_path):
        role_id = get_jwt_identity()["role_id"]
        print("role_id={0}".format(role_id))

        if role_id in (1, 5):
            project_id = repository_id
            branch = branch_name
            parser = reqparse.RequestParser()
            parser.add_argument('commit_message', type=str, required=True)
            args = parser.parse_args()
            logger.info("delete body: {0}".format(args))
            output = pjt.delete_git_project_file(logger, app, project_id,
                                                 branch, file_path, args)
            return output

        else:
            return {"message": "您無權限訪問！"}, 401


class GitProjectTags(Resource):
    @jwt_required
    def get(self, repository_id):
        role_id = get_jwt_identity()["role_id"]
        print("role_id={0}".format(role_id))

        if role_id in (1, 5):
            project_id = repository_id
            output = pjt.get_git_project_tags(logger, app, project_id)
            return output
        else:
            return {"message": "您無權限訪問！"}, 401

    @jwt_required
    def post(self, repository_id):
        role_id = get_jwt_identity()["role_id"]
        print("role_id={0}".format(role_id))

        if role_id in (1, 5):
            project_id = repository_id
            parser = reqparse.RequestParser()
            parser.add_argument('tag_name', type=str, required=True)
            parser.add_argument('ref', type=str, required=True)
            parser.add_argument('message', type=str)
            parser.add_argument('release_description', type=str)
            args = parser.parse_args()
            logger.info("post body: {0}".format(args))
            output = pjt.create_git_project_tags(logger, app, project_id, args)
            return output
        else:
            return {"message": "您無權限訪問！"}, 401


class GitProjectTag(Resource):
    @jwt_required
    def delete(self, repository_id, tag_name):
        role_id = get_jwt_identity()["role_id"]
        print("role_id={0}".format(role_id))

        if role_id in (1, 5):
            project_id = repository_id
            output = pjt.delete_git_project_tag(logger, app, project_id,
                                                tag_name)
            return output
        else:
            return {"message": "您無權限訪問！"}, 401


class GitProjectDirectory(Resource):
    @jwt_required
    def post(self, repository_id, directory_path):
        project_id = repository_id
        directory_path = directory_path + "%2F%2Egitkeep"
        parser = reqparse.RequestParser()
        parser.add_argument('branch', type=str, required=True)
        parser.add_argument('commit_message', type=str, required=True)
        args = parser.parse_args()
        logger.info("post body: {0}".format(args))
        output = pjt.create_git_project_directory(logger, app, project_id,
                                                  directory_path, args)
        return output.json()

    @jwt_required
    def put(self, repository_id, directory_path):
        project_id = repository_id
        directory_path = directory_path + "%2F%2Egitkeep"
        parser = reqparse.RequestParser()
        parser.add_argument('branch', type=str, required=True)
        parser.add_argument('author_name', type=str)
        parser.add_argument('author_email', type=str)
        parser.add_argument('encoding', type=str)
        parser.add_argument('content', type=str, required=True)
        parser.add_argument('commit_message', type=str, required=True)
        args = parser.parse_args()
        logger.info("put body: {0}".format(args))
        output = pjt.update_git_project_directory(logger, app, project_id,
                                                  directory_path, args)
        return output.json()

    @jwt_required
    def delete(self, repository_id, directory_path):
        project_id = repository_id
        parser = reqparse.RequestParser()
        parser.add_argument('branch', type=str, required=True)
        parser.add_argument('commit_message', type=str, required=True)
        args = parser.parse_args()
        logger.info("delete body: {0}".format(args))
        output = pjt.delete_git_project_directory(logger, app, project_id,
                                                  directory_path, args)
        if str(output) == "<Response [204]>":
            return "Success Delete"
        else:
            return str(output)


class GitProjectMergeBranch(Resource):
    @jwt_required
    def post(self, repository_id):
        project_id = repository_id
        parser = reqparse.RequestParser()
        parser.add_argument('schemas', type=dict, required=True)
        args = parser.parse_args()["schemas"]
        logger.info("post body: {0}".format(args))
        output = pjt.create_git_project_mergebranch(logger, app, project_id,
                                                    args)
        return output.json()


class GitProjectBranchCommmits(Resource):
    @jwt_required
    def get(self, repository_id):
        role_id = get_jwt_identity()["role_id"]
        print("role_id={0}".format(role_id))

        # try:
        #     role_id = db.engine.execute(
        #         "SELECT role_id FROM public.project_user_role \
        #         WHERE user_id = {0} AND project_id = {1}".format(
        #             user_id, project_id)).fetchone()[0]
        # except:
        #     role_id = None

        if role_id <= 5:
            project_id = repository_id
            parser = reqparse.RequestParser()
            parser.add_argument('branch', type=str, required=True)
            args = parser.parse_args()
            logger.info("get body: {0}".format(args))
            output = pjt.get_git_project_branch_commits(
                logger, app, project_id, args)
            return output.json()
        else:
            return "您無權限訪問！"


class GitProjectNetwork(Resource):
    @jwt_required
    def get(self, repository_id):
        project_id = repository_id
        output = pjt.get_git_project_network(logger, app, project_id)
        return output


class GitProjectId(Resource):
    @jwt_required
    def get(self, repository_id):
        return pjt.get_git_project_id(logger, app, repository_id)


class PipelineInfo(Resource):
    @jwt_required
    def get(self, project_id):
        output = pipe.pipeline_info(logger, project_id)
        return jsonify(output)


class PipelineExec(Resource):
    @jwt_required
    def get(self, repository_id):
        output_array = pipe.pipeline_exec_list(logger, app, repository_id)
        return jsonify({'message': 'success', 'data': output_array})


class PipelineExecLogs(Resource):
    @jwt_required
    def get(self):
        parser = reqparse.RequestParser()
        parser.add_argument('repository_id', type=int)
        parser.add_argument('pipelines_exec_run', type=int)
        args = parser.parse_args()
        output_array = pipe.pipeline_exec_logs(logger, app, args)
        return jsonify({'message': 'success', 'data': output_array})


class PipelineSoftware(Resource):
    @jwt_required
    def get(self):
        pipe_out_list = pipe.pipeline_software(logger)
        output_list = []
        for pipe_out in pipe_out_list:
            if 'detail' in pipe_out:
                pipe_out['detail'] = json.loads(pipe_out['detail'].replace(
                    "'", '"'))
            output_list.append(pipe_out)
        return jsonify({'message': 'success', 'data': output_list})


class PipelineGenerateYaml(Resource):
    @jwt_required
    def get(self, repository_id, branch_name):
        output_array = pipe.get_ci_yaml(logger, app, repository_id,
                                        branch_name)
        return jsonify({'message': 'success', 'data': output_array})

    @jwt_required
    def post(self, repository_id, branch_name):
        parser = reqparse.RequestParser()
        parser.add_argument('detail')
        args = parser.parse_args()
        output = pipe.generate_ci_yaml(logger, args, app, repository_id,
                                       branch_name)
        return output


class IssueByProject(Resource):
    @jwt_required
    def get(self, project_id):
        stauts = pjt.verify_project_user(logger, project_id,
                                         get_jwt_identity()['user_id'])
        if stauts or get_jwt_identity()['role_id'] == 5:
            args={}
            output, status_code = iss.get_issue_by_project(logger, app, project_id, args)
            return output, status_code
        else:
            return {'message': 'Dont have authorization to access issue list on project: {0}' \
                .format(project_id)}, 401


class IssuesProgressByProject(Resource):
    @jwt_required
    def get(self, project_id):
        stauts = pjt.verify_project_user(logger, project_id,
                                         get_jwt_identity()['user_id'])
        if stauts or get_jwt_identity()['role_id'] == 5:
            parser = reqparse.RequestParser()
            parser.add_argument('fixed_version_id', type=int)
            args = parser.parse_args()
            logger.debug("show fixed_version_id: {0}".format(args['fixed_version_id']))
            output_array = iss.get_issueProgress_by_project(
                logger, app, project_id, args)
            return output_array
        else:
            return {'message': 'Dont have authorization to access issue list on project: {0}' \
                .format(project_id)}, 401


class IssuesStatisticsByProject(Resource):
    @jwt_required
    def get(self, project_id):
        stauts = pjt.verify_project_user(logger, project_id,
                                         get_jwt_identity()['user_id'])
        if stauts or get_jwt_identity()['role_id'] == 5:
            parser = reqparse.RequestParser()
            parser.add_argument('fixed_version_id', type=int)
            args = parser.parse_args()
            logger.debug("show fixed_version_id: {0}".format(args['fixed_version_id']))
            output = iss.get_issueStatistics_by_project(
                logger, app, project_id, args)
            return output
        else:
            return {'message': 'Dont have authorization to get issue statistics on project: {0}'\
                .format(project_id)}, 401


class IssueCreate(Resource):
    @jwt_required
    def post(self):
        parser = reqparse.RequestParser()
        parser.add_argument('project_id', type=int, required=True)
        parser.add_argument('tracker_id', type=int, required=True)
        parser.add_argument('status_id', type=int, required=True)
        parser.add_argument('priority_id', type=int, required=True)
        parser.add_argument('subject', type=str, required=True)
        parser.add_argument('description', type=str)
        parser.add_argument('assigned_to_id', type=int, required=True)
        parser.add_argument('parent_id', type=int)
        parser.add_argument('fixed_version_id', type=int)
        parser.add_argument('start_date', type=str, required=True)
        parser.add_argument('due_date', type=str, required=True)
        parser.add_argument('done_retio', type=int, required=True)
        parser.add_argument('estimated_hours', type=int, required=True)
        args = parser.parse_args()
        output = iss.create_issue(logger, app, args)
        return output


class Issue(Resource):
    @jwt_required
    def get(self, issue_id):
        output = iss.get_issue_rd(logger, app, issue_id)
        return output

    @jwt_required
    def put(self, issue_id):
        parser = reqparse.RequestParser()
        parser.add_argument('assigned_to_id', type=int)
        parser.add_argument('tracker_id', type=int)
        parser.add_argument('status_id', type=int)
        parser.add_argument('priority_id', type=int)
        parser.add_argument('estimated_hours', type=int)
        parser.add_argument('description', type=str)
        parser.add_argument('parent_id', type=int)
        parser.add_argument('fixed_version_id', type=int)
        parser.add_argument('subject', type=str)
        parser.add_argument('start_date', type=str)
        parser.add_argument('due_date', type=str)
        parser.add_argument('done_ratio', type=int)
        parser.add_argument('notes', type=str)
        args = parser.parse_args()
        output = iss.update_issue_rd(logger, app, issue_id, args)
        return output

    @jwt_required
    def delete(self, issue_id):
        stauts = iss.verify_issue_user(logger, app, issue_id,
                                       get_jwt_identity()['user_id'])
        if stauts and get_jwt_identity()['role_id'] in (3, 5):
            output = iss.delete_issue(logger, app, issue_id)
            return output
        else:
            return {'message': 'Dont have authorization to delete issue for thie user: {0}' \
                .format(get_jwt_identity()['user_account'])}, 401


class IssueStatus(Resource):
    @jwt_required
    def get(self):
        output = iss.get_issue_status(logger, app)
        return jsonify({'message': 'success', 'data': output})


class IssuePrioriry(Resource):
    @jwt_required
    def get(self):
        output = iss.get_issue_priority(logger, app)
        return jsonify({'message': 'success', 'data': output})


class IssueTracker(Resource):
    @jwt_required
    def get(self):
        output = iss.get_issue_trackers(logger, app)
        return jsonify({'message': 'success', 'data': output})


class IssueRDbyUser(Resource):
    @jwt_required
    def get(self, user_id):
        if int(user_id) == get_jwt_identity()['user_id'] or get_jwt_identity()['role_id'] in (3, 5):
            output = iss.get_issue_by_user(logger, app, user_id)
            return jsonify({'message': 'success', 'data': output})
        else:
            return {'message': 'Access token is missing or invalid'}, 401


class IssueStatistics(Resource):
    @jwt_required
    def get(self):
        parser = reqparse.RequestParser()
        parser.add_argument('from_time', type=str, required=True)
        parser.add_argument('to_time', type=str)
        parser.add_argument('status_id', type=int)
        args = parser.parse_args()
        output = iss.get_issue_statistics(logger, app, args,
                                          get_jwt_identity()['user_id'])
        return output


class DashboardIssuePriority(Resource):
    @jwt_required
    def get(self, user_id):
        if int(user_id) == get_jwt_identity()['user_id'] or get_jwt_identity()['role_id'] in (3, 5):
            output = iss.count_prioriry_number_by_issues(logger, app, user_id)
            return jsonify({'message': 'success', 'data': output})
        else:
            return {'message': 'Access token is missing or invalid'}, 401


class DashboardIssueProject(Resource):
    @jwt_required
    def get(self, user_id):
        if int(user_id) == get_jwt_identity()['user_id'] or get_jwt_identity()['role_id'] in (3, 5):
            output = iss.count_project_number_by_issues(logger, app, user_id)
            return jsonify({'message': 'success', 'data': output})
        else:
            return {'message': 'Access token is missing or invalid'}, 401


class DashboardIssueType(Resource):
    @jwt_required
    def get(self, user_id):
        if int(user_id) == get_jwt_identity()['user_id'] or get_jwt_identity()['role_id'] in (3, 5):
            output = iss.count_type_number_by_issues(logger, app, user_id)
            return jsonify({'message': 'success', 'data': output})
        else:
            return {'message': 'Access token is missing or invalid'}, 401


class RequirementByIssue(Resource):

    ## 用issues ID 取得目前所有的需求清單
    @jwt_required
    def get(self, issue_id):
        # temp = get_jwt_identity()
        print(get_jwt_identity())
        output = rqmt.get_requirements_by_issue_id(
            logger, issue_id,
            get_jwt_identity()['user_id'])
        return jsonify({'message': 'success', 'data': output})

    ## 用issues ID 新建立需求清單
    @jwt_required
    def post(self, issue_id):
        parser = reqparse.RequestParser()
        parser.add_argument('project_id', type=int)
        # parser.add_argument('flow_info', type=str)
        args = parser.parse_args()
        output = rqmt.post_requirement_by_issue_id(
            logger, issue_id, args,
            get_jwt_identity()['user_id'])
        return jsonify({'message': 'success', 'data': output})


class Requirement(Resource):

    ## 用requirement_id 取得目前需求流程
    @jwt_required
    def get(self, requirement_id):
        # temp = get_jwt_identity()
        output = rqmt.get_requirement_by_rqmt_id(logger, requirement_id,
                                                 get_jwt_identity()['user_id'])
        return jsonify({'message': 'success', 'data': output})

    ## 用requirement_id 刪除目前需求流程
    @jwt_required
    def delete(self, requirement_id):
        # temp = get_jwt_identity()
        output = {}
        output = rqmt.del_requirement_by_rqmt_id(logger, requirement_id,
                                                 get_jwt_identity()['user_id'])
        return jsonify({'message': 'success'})

    ## 用requirement_id 更新目前需求流程
    @jwt_required
    def put(self, requirement_id):
        output = {}
        parser = reqparse.RequestParser()
        parser.add_argument('flow_info', type=str)
        args = parser.parse_args()
        output = rqmt.modify_requirement_by_rqmt_id(
            logger, requirement_id, args,
            get_jwt_identity()['user_id'])
        return jsonify({'message': 'success'})


class GetFlowType(Resource):
    @jwt_required
    def get(self):
        output = flow.get_flow_support_type()
        return jsonify({'message': 'success', 'data': output})

class FlowByIssue(Resource):

    ## 用issues ID 取得目前所有的需求清單
    @jwt_required
    def get(self, issue_id):
        # requirement_ids = []
        requirement_ids = rqmt.check_requirement_by_issue_id(logger, issue_id)
        print(requirement_ids)
        if not requirement_ids:
            return jsonify({'message': 'success', 'data': {}})    
        output = {}
        for requirement_id in requirement_ids:
            result = flow.get_flow_by_requirement_id(logger, requirement_id, get_jwt_identity()['user_id'])
            output[str(result[0]['requirement_id'] )]= result
        return jsonify({'message': 'success', 'data': output})

    ## 用issues ID 新建立需求清單
    @jwt_required
    def post(self, issue_id):
        output = {}
        parser = reqparse.RequestParser()
        parser.add_argument('project_id', type=int)
        parser.add_argument('type_id', type=int)
        parser.add_argument('name', type=str)
        parser.add_argument('description', type=str)
        args = parser.parse_args()
        check = rqmt.check_requirement_by_issue_id(logger, issue_id)
        if not check:
            requirements = rqmt.post_requirement_by_issue_id(logger, issue_id, args,get_jwt_identity()['user_id'])
            requirement_id  = requirements['requirement_id'][0]
        else:
            requirement_id = check[0]
        
        output = flow.post_flow_by_requirement_id(logger, int(issue_id), requirement_id , args,get_jwt_identity()['user_id'])
        # print(output)
        return jsonify({'message': 'success', 'data': output})

# class FlowByRequirement(Resource):

#     # 用issues ID 取得目前所有的需求清單
#     @jwt_required
#     def get(self, issue_id):
#         output = rqmt.get_requirements_by_issue_id(
#             logger, issue_id,
#             get_jwt_identity()['user_id'])
#         return jsonify({'message': 'success', 'data': output})

#     # 用issues ID 新建立需求清單
#     @jwt_required
#     def post(self, issue_id):
#         parser = reqparse.RequestParser()
#         parser.add_argument('project_id', type=int)
#         parser.add_argument('flow_info', type=str)
#         args = parser.parse_args()
#         output = rqmt.post_requirement_by_issue_id(
#             logger, issue_id, args,
#             get_jwt_identity()['user_id'])
#         return jsonify({'message': 'success', 'data': output})



class Flow(Resource):

    ## 用requirement_id 取得目前需求流程
    @jwt_required
    def get(self, flow_id):
        output = flow.get_flow_by_flow_id(logger, flow_id, get_jwt_identity()['user_id'])
        return jsonify({'message': 'success', 'data': output})

    ## 用requirement_id 刪除目前需求流程
    @jwt_required
    def delete(self, flow_id):
        # temp = get_jwt_identity()
        output = {}
        output = flow.disabled_flow_by_flow_id(logger, flow_id,
                                                 get_jwt_identity()['user_id'])
        return jsonify({'message': 'success','data': output })

    ## 用requirement_id 更新目前需求流程
    @jwt_required
    def put(self, flow_id):
        output = {}
        parser = reqparse.RequestParser()
        parser.add_argument('serial_id', type=int)
        parser.add_argument('type_id', type=int)
        parser.add_argument('name', type=str)
        parser.add_argument('description', type=str)
        args = parser.parse_args()
        output = flow.modify_flow_by_flow_id(logger, flow_id, args, get_jwt_identity()['user_id'])
        return jsonify({'message': 'success','data':output})

class ParameterType(Resource):
    @jwt_required
    def get(self):
        output = {}
        output = param.get_parameter_types()
        return jsonify({'message': 'success', 'data': output})


class ParameterByIssue(Resource):

    ## 用issues ID 取得目前所有的需求清單
    @jwt_required
    def get(self, issue_id):
        output = {}
        output = param.get_parameterss_by_issue_id(
            logger, issue_id,
            get_jwt_identity()['user_id'])
        return jsonify({'message': 'success', 'data': output})

    ## 用issues ID 新建立需求清單
    @jwt_required
    def post(self, issue_id):
        output = {}
        parser = reqparse.RequestParser()
        parser.add_argument('project_id', type=int)
        parser.add_argument('parameter_type_id', type=int)
        parser.add_argument('name', type=str)
        parser.add_argument('description', type=str)
        parser.add_argument('limitation', type=str)
        parser.add_argument('length', type=int)
        args = parser.parse_args()
        output = param.post_parameters_by_issue_id(
            logger, issue_id, args,
            get_jwt_identity()['user_id'])
        return jsonify({'message': 'success', 'data': output})


class Parameter(Resource):

    ## 用requirement_id 取得目前需求流程
    @jwt_required
    def get(self, parameter_id):
        output = {}
        output = param.get_parameters_by_param_id(
            logger, parameter_id,
            get_jwt_identity()['user_id'])
        return jsonify({'message': 'success', 'data': output})

    ## 用requirement_id 刪除目前需求流程
    @jwt_required
    def delete(self, parameter_id):
        output = {}
        output = param.del_parameters_by_param_id(
            logger, parameter_id,
            get_jwt_identity()['user_id'])
        return jsonify({'message': 'success', 'data': output})

    ## 用requirement_id 更新目前需求流程
    @jwt_required
    def put(self, parameter_id):
        output = {}
        parser = reqparse.RequestParser()
        parser.add_argument('parameter_type_id', type=int)
        parser.add_argument('name', type=str)
        parser.add_argument('description', type=str)
        parser.add_argument('limitation', type=str)
        parser.add_argument('length', type=int)
        args = parser.parse_args()
        output = param.modify_parameters_by_param_id(
            logger, parameter_id, args,
            get_jwt_identity()['user_id'])
        return jsonify({'message': 'success'})


class AllTestDataByIssue(Resource):
    @jwt_required
    def get(self, issue_id):

        data = {}
        data['requirement'] = rqmt.get_requirements_by_issue_id(
            logger, issue_id,
            get_jwt_identity()['user_id'])['flow_info']
        data['testCase'] = tc.get_testCase_by_issue_id(
            logger, issue_id,
            get_jwt_identity()['user_id'])
        data['testItem'] = ti.get_testItem_by_issue_id(
            logger, issue_id,
            get_jwt_identity()['user_id'], 'test_case_id')
        data['testValue'] = tv.get_testValue_by_issue_id(
            logger, issue_id,
            get_jwt_identity()['user_id'])
        output = td.get_AllTestData_by_Issue_Id(logger, data,
                                                get_jwt_identity()['user_id'])
        # print(data)
        # output = {}
        # print(output)
        return jsonify({'message': 'success', 'data': output})


class AllTestData(Resource):
    @jwt_required
    def get(self):

        parser = reqparse.RequestParser()
        parser.add_argument('project_id', type=int)
        parser.add_argument('issue_id', type=int)
        parser.add_argument('order_by', type=str)
        user_id = get_jwt_identity()['user_id']
        args = parser.parse_args()
        data = {}
        data['testCase'] = tc.get_testCase_by_Column(logger, args, user_id)
        data['testItem'] = ti.get_testItem_by_Column(logger, args, user_id,
                                                     'test_case_id')
        data['testValue'] = tv.get_testValue_by_Column(logger, args, user_id,
                                                       "test_case_id")
        output = td.analysis_testData(logger, data, user_id)
        return jsonify({'message': 'success', 'data': output})


class TestCaseByIssue(Resource):

    ## 用issues ID 取得目前所有的目前測試案例
    @jwt_required
    def get(self, issue_id):
        # print(issue_id)
        output = {}
        output = tc.get_testCase_by_issue_id(logger, issue_id,
                                             get_jwt_identity()['user_id'])
        return jsonify({'message': 'success', 'data': output})

    ## 用issues ID 新建立測試案例
    @jwt_required
    def post(self, issue_id):
        output = {}
        parser = reqparse.RequestParser()
        parser.add_argument('project_id', type=int)
        parser.add_argument('name', type=str)
        parser.add_argument('data', type=str)
        parser.add_argument('type_id', type=int)
        parser.add_argument('description', type=str)
        args = parser.parse_args()
        output = tc.post_testCase_by_issue_id(logger, issue_id, args,
                                              get_jwt_identity()['user_id'])
        return jsonify({'message': 'success', 'data': output})


class TestCase(Resource):

    ## 用testCase_id 取得目前測試案例
    @jwt_required
    def get(self, testCase_id):
        output = {}
        output = tc.get_testCase_by_tc_id(logger, testCase_id,
                                          get_jwt_identity()['user_id'])
        return jsonify({'message': 'success', 'data': output})

    ## 用testCase_id 刪除目前測試案例
    @jwt_required
    def delete(self, testCase_id):
        output = {}
        output = tc.del_testCase_by_tc_id(logger, testCase_id,
                                          get_jwt_identity()['user_id'])
        return jsonify({'message': 'success', 'data': output})

    ## 用testCase_id 更新目前測試案例
    @jwt_required
    def put(self, testCase_id):
        output = {}
        parser = reqparse.RequestParser()
        parser.add_argument('data')
        parser.add_argument('name', type=str)
        parser.add_argument('type_id', type=int)
        parser.add_argument('description', type=str)
        args = parser.parse_args()
        print(args)
        output = tc.modify_testCase_by_tc_id(logger, testCase_id, args,
                                             get_jwt_identity()['user_id'])
        return jsonify({'message': 'success', 'data': output})


class GetTestCaseAPIMethod(Resource):
    @jwt_required
    def get(self):
        output = {}
        output = tc.get_api_method(logger, get_jwt_identity()['user_id'])
        return jsonify({'message': 'success', 'data': output})


class GetTestCaseType(Resource):
    @jwt_required
    def get(self):
        output = {}
        output = tc.get_testCase_type(logger, get_jwt_identity()['user_id'])
        return jsonify({'message': 'success', 'data': output})


class TestItemByTestCase(Resource):

    ## 用issues ID 取得目前所有的目前測試案例
    @jwt_required
    def get(self, testCase_id):
        # print(issue_id)

        output = {}
        output = ti.get_testItem_by_testCase_id(logger, testCase_id,
                                                get_jwt_identity()['user_id'])
        return jsonify({'message': 'success', 'data': output})

    ## 用issues ID 新建立測試案例
    @jwt_required
    def post(self, testCase_id):
        output = {}
        parser = reqparse.RequestParser()
        parser.add_argument('project_id', type=int)
        parser.add_argument('name', type=str)
        parser.add_argument('issue_id', type=int)
        parser.add_argument('is_passed', type=bool)
        args = parser.parse_args()
        output = ti.post_testItem_by_testCase_id(logger, testCase_id, args,
                                                 get_jwt_identity()['user_id'])
        return jsonify({'message': 'success', 'data': output})


class TestItem(Resource):

    ## testItem_id 取得目前測試項目
    @jwt_required
    def get(self, testItem_id):
        output = {}
        output = ti.get_testItem_by_ti_id(logger, testItem_id,
                                          get_jwt_identity()['user_id'])
        return jsonify({'message': 'success', 'data': output})

    ## testItem_id 刪除目前測試項目
    @jwt_required
    def delete(self, testItem_id):
        output = {}
        output = ti.del_testItem_by_ti_id(logger, testItem_id,
                                          get_jwt_identity()['user_id'])
        return jsonify({'message': 'success', 'data': output})

    ## testItem_id 更新目前測試項目
    @jwt_required
    def put(self, testItem_id):
        output = {}
        parser = reqparse.RequestParser()
        print(parser)
        parser.add_argument('name', type=str)
        parser.add_argument('is_passed', type=bool)
        args = parser.parse_args()
        output = ti.modify_testItem_by_ti_id(logger, testItem_id, args,
                                             get_jwt_identity()['user_id'])
        return jsonify({'message': 'success', 'data': output})


class TestValueByTestItem(Resource):

    ## 用issues ID 取得目前所有的目前測試案例
    @jwt_required
    def get(self, testItem_id):
        output = {}
        output = tv.get_testValue_by_testItem_id(logger, testItem_id,
                                                 get_jwt_identity()['user_id'])
        return jsonify({'message': 'success', 'data': output})

    ## 用issues ID 新建立測試案例
    @jwt_required
    def post(self, testItem_id):
        output = {}
        parser = reqparse.RequestParser()
        parser.add_argument('project_id', type=int)
        parser.add_argument('issue_id', type=int)
        parser.add_argument('testCase_id', type=int)
        parser.add_argument('type_id', type=int)
        parser.add_argument('location_id', type=int)
        parser.add_argument('key', type=str)
        parser.add_argument('value', type=str)
        args = parser.parse_args()
        output = tv.post_testValue_by_testItem_id(
            logger, testItem_id, args,
            get_jwt_identity()['user_id'])
        return jsonify({'message': 'success', 'data': output})

class GetTestValueLocation(Resource):
    @jwt_required
    def get(self):
        output = {}
        output = tv.get_testValue_httpLocation(logger)
        return jsonify({'message': 'success', 'data': output})

class GetTestValueType(Resource):
    @jwt_required
    def get(self):
        output = {}
        output = tv.get_testValue_httpType(logger)
        return jsonify({'message': 'success', 'data': output})

class TestValue(Resource):

    ## testItem_id 取得目前測試項目
    @jwt_required
    def get(self, testValue_id):
        output = {}
        output = tv.get_testValue_by_tv_id(logger, testValue_id,
                                           get_jwt_identity()['user_id'])
        return jsonify({'message': 'success', 'data': output})

    ## testItem_id 刪除目前測試項目
    @jwt_required
    def delete(self, testValue_id):
        output = {}
        output = tv.del_testValue_by_tv_id(logger, testValue_id,
                                           get_jwt_identity()['user_id'])
        return jsonify({'message': 'success', 'data': output})

    ## testItem_id 更新目前測試項目
    @jwt_required
    def put(self, testValue_id):
        output = {}
        parser = reqparse.RequestParser()
        parser.add_argument('key', type=str)
        parser.add_argument('value', type=str)
        parser.add_argument('type_id', type=str)
        parser.add_argument('location_id', type=str)
        args = parser.parse_args()
        output = tv.modify_testValue_by_ti_id(logger, testValue_id, args,
                                              get_jwt_identity()['user_id'])
        return jsonify({'message': 'success', 'data': output})


class TestResult(Resource):
    @jwt_required
    def post(self):
        parser = reqparse.RequestParser()
        parser.add_argument('project_id', type=int, required=True)
        parser.add_argument('total', type=int, required=True)
        parser.add_argument('fail', type=int, required=True)
        args = parser.parse_args()
        output = tr.save(logger, args)
        return output


class ExportToPostman(Resource):
    @jwt_required
    def get(self, project_id):
        jwt_identity = get_jwt_identity()['user_id']
        status = pjt.verify_project_user(logger, project_id, jwt_identity)
        if not status:
            return {'message': 'Don\'t have authorization to access issue list on project: {0}' \
                .format(project_id)}, 401

        output = {
            'info': {
                'name':
                'Project id %s' % project_id,
                'schema':
                'https://schema.getpostman.com/json/collection/v2.1.0/collection.json'
            },
            'item': []
        }
        args = {}
        issues, status_code = iss.get_issue_by_project(logger, app, project_id, args)
        cases = []
        for issue in issues['data']:
            issue_id = issue['id']
            part_cases = tc.get_testCase_by_issue_id(logger, issue_id,
                                                     jwt_identity)
            for case in part_cases.values():
                cases.append(case)

        for case in cases:
            case_id = case['id']
            method = case['data']['method']
            url = urlparse(case['data']['url'])
            items = ti.get_testItem_by_testCase_id(logger, case_id,
                                                   jwt_identity)
            for item in items.values():
                item_id = item['id']
                o_item = {'name': '%s #%s' % (case['name'], item_id)}
                values = []
                part_values = tv.get_testValue_by_testItem_id(
                    logger, item_id, jwt_identity)
                for value in part_values.values():
                    values.append(value)

                o_request = {
                    'method': method,
                    'url': {
                        'protocol': url.scheme,
                        'port': url.port
                    },
                    'header': []
                }
                if bool(url.hostname):
                    o_request['url']['host'] = url.hostname.split('.')
                if len(url.path) > 0:
                    o_request['url']['path'] = url.path[1:].split('/')
                o_request_body = []
                o_execs = []

                for value in values:
                    type_id = value['type_id']
                    location_id = value['location_id']
                    if type_id == 1:
                        if location_id == 1:
                            header = {}
                            if value['key'] == 'token':
                                header['key'] = 'Authorization'
                                header['value'] = 'Bearer %s' % value['value']
                                header['type'] = 'text'
                            else:
                                header['key'] = value['key']
                                header['value'] = value['value']
                            o_request['header'].append(header)
                        elif location_id == 2:
                            o_request_body.append({
                                'key': value['key'],
                                'value': value['value']
                            })
                        else:
                            pass
                    elif type_id == 2:
                        if location_id == 1:
                            pass
                        elif location_id == 2:
                            o_execs.append(
                                'pm.test("value #%d", function () { '
                                'pm.expect(pm.response.json().%s).to.be.eql("%s");});'
                                % (value['id'], value['key'], value['value']))
                    else:
                        pass

                if bool(o_request_body):
                    o_request['body'] = {
                        'mode': 'formdata',
                        'formdata': o_request_body
                    }
                if bool(o_request):
                    o_item['request'] = o_request
                if len(o_execs) > 0:
                    o_item['event'] = [{
                        'listen': 'test',
                        'script': {
                            'type': 'text/javascript',
                            'exec': o_execs
                        }
                    }]
                output['item'].append(o_item)

        return jsonify({'message': 'success', 'data': output})


api.add_resource(Index, '/')

# Project list
api.add_resource(TotalProjectList, '/project/list')

# Project(redmine & gitlab & db)
api.add_resource(CreateProject, '/project')
api.add_resource(Project, '/project/<project_id>')

# Gitlab project
api.add_resource(GitProjects, '/git_projects')
api.add_resource(GitOneProject, '/git_one_project/<project_id>')
api.add_resource(GitProjectWebhooks, '/git_project_webhooks/<project_id>')

api.add_resource(GitProjectBranches, '/repositories/<repository_id>/branches')
api.add_resource(GitProjectBranch,
                 '/repositories/rd/<repository_id>/branch/<branch_name>')
api.add_resource(GitProjectRepositories,
                 '/repositories/rd/<repository_id>/branch/<branch_name>/tree')
api.add_resource(GitProjectFiles,
                 '/repositories/rd/<repository_id>/branch/files')
api.add_resource(
    GitProjectFile,
    '/repositories/rd/<repository_id>/branch/<branch_name>/files/<file_path>')
api.add_resource(GitProjectTags, '/repositories/rd/<repository_id>/tags')
api.add_resource(GitProjectTag,
                 '/repositories/rd/<repository_id>/tags/<tag_name>')
api.add_resource(
    GitProjectDirectory,
    '/repositories/rd/<repository_id>/directory/<directory_path>')
api.add_resource(GitProjectMergeBranch,
                 '/repositories/rd/<repository_id>/merge_branches')
api.add_resource(GitProjectBranchCommmits,
                 '/repositories/<repository_id>/commits')
api.add_resource(GitProjectNetwork, '/repositories/<repository_id>/overview')
api.add_resource(GitProjectId, '/repositories/<repository_id>/id')


# Project
api.add_resource(ProjectList, '/project/rd/<user_id>')
api.add_resource(ProjectUserList, '/project/<int:project_id>/user/list')
api.add_resource(ProjectWikiList, '/project/<int:project_id>/wiki')
api.add_resource(ProjectWiki, '/project/<int:project_id>/wiki/<wiki_name>')
api.add_resource(ProjectVersionList, '/project/<int:project_id>/version/list')
api.add_resource(ProjectVersion, '/project/<int:project_id>/version')
api.add_resource(ProjectVersionInfo, '/project/<int:project_id>/version/<int:version_id>')

# User
api.add_resource(UserLogin, '/user/login')
api.add_resource(UserForgetPassword, '/user/forgetPassword')
api.add_resource(UserInfo, '/user/<int:user_id>')
api.add_resource(UserStatus, '/user/<int:user_id>/status')
api.add_resource(User, '/user')
api.add_resource(UserList, '/user/list')
# Role
api.add_resource(RoleList, '/user/role/list')

# pipeline
api.add_resource(PipelineExec, '/pipelines/rd/<repository_id>/pipelines_exec')
api.add_resource(PipelineExecLogs, '/pipelines/rd/logs')
api.add_resource(PipelineSoftware, '/pipelines/software')
api.add_resource(
    PipelineGenerateYaml,
    '/pipelines/<repository_id>/branch/<branch_name>/generate_ci_yaml')

# issue
api.add_resource(IssueByProject, '/project/<project_id>/issues')
api.add_resource(IssuesProgressByProject,
                 '/project/<project_id>/issues_progress')
api.add_resource(IssuesStatisticsByProject,
                 '/project/<project_id>/issues_statistics')
api.add_resource(IssueCreate, '/issues')
api.add_resource(Issue, '/issues/<issue_id>')
api.add_resource(IssueStatus, '/issues_status')
api.add_resource(IssuePrioriry, '/issues_priority')
api.add_resource(IssueTracker, '/issues_tracker')
api.add_resource(IssueRDbyUser, '/issues_by_user/rd/<user_id>')
api.add_resource(IssueStatistics, '/issues/statistics')

# dashboard
api.add_resource(DashboardIssuePriority,
                 '/dashboard_issues_priority/rd/<user_id>')
api.add_resource(DashboardIssueProject, '/dashboard_issues_project/<user_id>')
api.add_resource(DashboardIssueType, '/dashboard_issues_type/<user_id>')

# testPhase Requirement
api.add_resource(RequirementByIssue, '/requirements_by_issue/<issue_id>')
api.add_resource(Requirement, '/requirements/<requirement_id>')

# testPhase Flow 

api.add_resource(FlowByIssue,'/flows_by_issue/<issue_id>')
# api.add_resource(FlowByRequirement, '/flows_by_requirement/<requirement_id>')
api.add_resource(GetFlowType,'/flows/support_type')
api.add_resource(Flow, '/flows/<flow_id>')


# testPhase Parameters FLow
api.add_resource(ParameterByIssue, '/parameters_by_issue/<issue_id>')
api.add_resource(Parameter, '/parameters/<parameter_id>')
api.add_resource(ParameterType, '/parameter_types')

# TestData
# api.add_resource(AllTestDataByIssue, '/testData_by_issue')
# api.add_resource(AllTestData, '/testData')

# testPhase TestCase Support Case Type
api.add_resource(GetTestCaseType, '/testCases/support_type')

# testPhase TestCase
api.add_resource(TestCaseByIssue, '/testCases_by_issue/<issue_id>')
api.add_resource(TestCase, '/testCases/<testCase_id>')



# testPhase TestCase Support API Method
api.add_resource(GetTestCaseAPIMethod, '/testCases/support_RestfulAPI_Method')

# testPhase TestItem Support API Method
api.add_resource(TestItemByTestCase, '/testItems_by_testCase/<testCase_id>')
api.add_resource(TestItem, '/testItems/<testItem_id>')

# testPhase Testitem Value
api.add_resource(GetTestValueLocation,'/testValues/support_locations')
api.add_resource(GetTestValueType,'/testValues/support_types')
api.add_resource(TestValueByTestItem, '/testValues_by_testItem/<testItem_id>')
api.add_resource(TestValue, '/testValues/<testValue_id>')

# TestResult writing
api.add_resource(TestResult, '/testResults')

# Export tests to postman json format
api.add_resource(ExportToPostman, '/export_to_postman/<project_id>')

if __name__ == "__main__":
    db.init_app(app)
    jsonwebtoken.init_app(app)
    app.run(host='0.0.0.0', port=10009, debug=True)
