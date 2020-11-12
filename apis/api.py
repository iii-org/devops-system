import datetime
import json
import logging
import os
import re
from logging import handlers

import werkzeug
from flask import Flask
from flask import jsonify
from flask_cors import CORS
from flask_jwt_extended import jwt_required, get_jwt_identity
from flask_restful import Resource, Api, reqparse
from werkzeug.routing import IntegerConverter

import config
import resources.apiError as apiError
import resources.flow as flow
import resources.parameter as parameter
import resources.requirement as requirement
import resources.testCase as testCase
import resources.testItem as testItem
import resources.testResult as testResult
import resources.testValue as testValue
import resources.util as util
from jsonwebtoken import jsonwebtoken
from model import db
from resources.checkmarx import CheckMarx
from resources.cicd import Cicd
from resources.gitlab import GitLab
from resources.issue import Issue as IssueResource
from resources.pipeline import Pipeline
from resources.project import Project as ProjectResource
from resources.redmine import Redmine
from resources.user import User as UserResource
from resources.version import Version as VersionResource
from resources.wiki import Wiki as WikiResource

app = Flask(__name__)
for key in ['JWT_SECRET_KEY',
            'SQLALCHEMY_DATABASE_URI',
            'SQLALCHEMY_TRACK_MODIFICATIONS',
            'WTF_CSRF_CHECK_DEFAULT',
            'JSON_AS_ASCII'
            ]:
    app.config[key] = config.get(key)

app.config['JWT_ACCESS_TOKEN_EXPIRES'] = datetime.timedelta(days=1)
api = Api(app)
CORS(app)


class SignedIntConverter(IntegerConverter):
    regex = r'-?\d+'


app.url_map.converters['sint'] = SignedIntConverter

handler = handlers.TimedRotatingFileHandler(
    'devops-api.log', when='D'
    , interval=1, backupCount=14)
handler.setFormatter(logging.Formatter(
    '%(asctime)s %(filename)s [line:%(lineno)d] %(levelname)s %(message)s'
    , '%Y %b %d, %a %H:%M:%S'))
logger = logging.getLogger('devops.api')
logger.setLevel(logging.DEBUG)
logger.addHandler(handler)

redmine = Redmine(app)
wk = WikiResource(redmine)
vn = VersionResource(redmine)
git = GitLab(app)
user = UserResource(redmine, git)
pjt = ProjectResource(app, user, redmine, git)
iss = IssueResource(pjt, redmine, user)
pipe = Pipeline(pjt)
ci = Cicd(pjt, iss)
cm = CheckMarx(app)


class TotalProjectList(Resource):
    @jwt_required
    def get(self):
        role_id = get_jwt_identity()["role_id"]

        if role_id in (3, 5):
            user_id = get_jwt_identity()["user_id"]
            try:
                output = pjt.get_pm_project_list(logger, app, user_id)
                return output
            except Exception as e:
                return {"message": str(e)}, 400
        else:
            return {"message": "your role art not PM/administrator"}, 401


class CreateProject(Resource):
    @jwt_required
    def post(self):
        role_id = get_jwt_identity()["role_id"]

        if role_id in (3, 5):
            user_id = get_jwt_identity()["user_id"]
            parser = reqparse.RequestParser()
            parser.add_argument('name', type=str, required=True)
            parser.add_argument('display', type=str)
            parser.add_argument('description', type=str)
            parser.add_argument('disabled', type=bool, required=True)
            args = parser.parse_args()
            logger.info("post body: {0}".format(args))

            pattern = "^[a-z0-9][a-z0-9-]{0,253}[a-z0-9]$"
            result = re.fullmatch(pattern, args["name"])
            if result is not None:
                try:
                    args["identifier"] = args["name"]
                    output = pjt.pm_create_project(user_id, args)
                    return output
                except Exception as e:
                    import traceback
                    traceback.print_exc()
                    return {"message": str(e)}, 400
            else:
                return util.respond(400, 'Error while creating project',
                                    error=apiError.invalid_project_name(args['name']))
        else:
            return {"message": "your role art not PM/administrator"}, 401


class Project(Resource):
    @jwt_required
    def get(self, project_id):
        role_id = get_jwt_identity()["role_id"]

        if role_id in (3, 5):
            try:
                output = pjt.pm_get_project(project_id)
                return output
            except Exception as e:
                return util.respond(500, "Error when getting project info.",
                                    error=apiError.uncaught_exception(e))
        else:
            return util.respond(401, "Error when getting project info.",
                                error=apiError.not_allowed(get_jwt_identity()['user_account']
                                                           , [3, 5]))

    @jwt_required
    def put(self, project_id):
        role_id = get_jwt_identity()["role_id"]

        if role_id in (3, 5):
            # user_id = get_jwt_identity()["user_id"]
            # print("user_id={0}".format(user_id))
            parser = reqparse.RequestParser()
            parser.add_argument('name', type=str)
            parser.add_argument('display', type=str)
            parser.add_argument('user_id', type=int)
            parser.add_argument('description', type=str)
            parser.add_argument('disabled', type=bool)
            # parser.add_argument('homepage', type=str)
            args = parser.parse_args()
            logger.info("put body: {0}".format(args))
            try:
                output = pjt.pm_update_project(logger, app, project_id, args)
                return output
            except Exception as e:
                return {"message": str(e)}, 400
        else:
            return {"message": "your role art not PM/administrator"}, 401

    @jwt_required
    def delete(self, project_id):
        role_id = get_jwt_identity()["role_id"]

        status = pjt.verify_project_user(logger, project_id,
                                         get_jwt_identity()['user_id'])
        if (role_id == 3 and status) or (role_id == 5):
            try:
                output = pjt.pm_delete_project(logger, app, project_id)
                return output
            except Exception as e:
                return {"message": str(e)}, 400
        else:
            return {"message": "you are not an administrator, and you are not a PM in this project."}, 401


class GitProjects(Resource):
    @jwt_required
    def get(self):
        output = pjt.get_all_git_projects(logger, app)
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


class ProjectsByUser(Resource):
    @jwt_required
    def get(self, user_id):
        if int(user_id) == get_jwt_identity()['user_id'] or get_jwt_identity(
        )['role_id'] in (3, 5):
            output = pjt.get_projects_by_user(logger, app, user_id)
            return output
        else:
            return {'message': 'Access token is missing or invalid'}, 401


class UserLogin(Resource):
    def post(self):
        parser = reqparse.RequestParser()
        parser.add_argument('username', type=str, required=True)
        parser.add_argument('password', type=str, required=True)
        args = parser.parse_args()
        output = user.login(args)
        return output


class UserForgetPassword(Resource):
    def post(self):
        parser = reqparse.RequestParser()
        parser.add_argument('mail', type=str, required=True)
        parser.add_argument('user_account', type=str, required=True)
        args = parser.parse_args()
        try:
            status = user.user_forgot_password(args)
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
        )['role_id'] in (3, 5):
            user_info = user.get_user_info(user_id)
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
            parser.add_argument('phone', type=str)
            parser.add_argument('email', type=str)
            parser.add_argument('status', type=str)
            args = parser.parse_args()
            try:
                output = user.update_info(user_id, args)
                return output
            except Exception as e:
                return jsonify({"message": str(e)}), 400
        else:
            return {
                'message': 'you dont have authorize to update user informaion'
            }, 401

    @jwt_required
    def delete(self, user_id):
        '''delete user'''
        if get_jwt_identity()["role_id"] == 5:
            try:
                output = user.delete_user(user_id)
                return output
            except Exception as e:
                return {"message": str(e)}, 400
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
            output = user.change_user_status(user_id, args)
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
            parser.add_argument('phone', type=str, required=True)
            parser.add_argument('login', type=str, required=True)
            parser.add_argument('password', type=str, required=True)
            parser.add_argument('role_id', type=int, required=True)
            parser.add_argument('status', type=str)
            args = parser.parse_args()
            output = user.create_user(args)
            return output
        else:
            return {"message": "your role art not administrator"}, 401


class UserList(Resource):
    @jwt_required
    def get(self):
        if get_jwt_identity()["role_id"] in (3, 5):
            output = user.user_list()
            return output
        else:
            return {"message": "your role art not administrator"}, 401


class ProjectUserList(Resource):
    @jwt_required
    def get(self, project_id):
        if get_jwt_identity()["role_id"] in (1, 3, 5):
            parser = reqparse.RequestParser()
            parser.add_argument('exclude', type=int)
            args = parser.parse_args()
            output = user.user_list_by_project(project_id, args)
            return output
        else:
            return {"message": "your role art not administrator"}, 401


class ProjectAddMember(Resource):
    @jwt_required
    def post(self, project_id):
        status = pjt.verify_project_user(logger, project_id,
                                         get_jwt_identity()['user_id'])
        if (get_jwt_identity()["role_id"] == 5) or (get_jwt_identity()["role_id"] == 3 and status):
            parser = reqparse.RequestParser()
            parser.add_argument('user_id', type=int, required=True)
            args = parser.parse_args()
            output = user.project_add_member(project_id, args)
            return output
        else:
            return {"message": "your role are not PM or administrator"}, 401


class ProjectDeleteMember(Resource):
    @jwt_required
    def delete(self, project_id, user_id):
        if get_jwt_identity()["role_id"] in (3, 5):
            output = user.remove_from_project(project_id, user_id)
            return output
        else:
            return {"message": "your role are not PM or administrator"}, 401


class ProjectWikiList(Resource):
    @jwt_required
    def get(self, project_id):
        status = pjt.verify_project_user(logger, project_id,
                                         get_jwt_identity()['user_id'])
        if status or get_jwt_identity()['role_id'] == 5:
            output = wk.get_wiki_list_by_project(project_id)
            return output
        else:
            return {
                "message": "your are not in this project or not administrator"
            }, 401


class ProjectWiki(Resource):
    @jwt_required
    def get(self, project_id, wiki_name):
        status = pjt.verify_project_user(logger,  project_id,
                                         get_jwt_identity()['user_id'])
        if status or get_jwt_identity()['role_id'] == 5:
            output, status_code = wk.get_wiki_by_project(project_id, wiki_name)
            return output, status_code
        else:
            return {
                "message": "your are not in this project or not administrator"
            }, 401

    @jwt_required
    def put(self, project_id, wiki_name):
        status = pjt.verify_project_user(logger, project_id,
                                         get_jwt_identity()['user_id'])
        if status or get_jwt_identity()['role_id'] == 5:
            parser = reqparse.RequestParser()
            parser.add_argument('wiki_text', type=str, required=True)
            args = parser.parse_args()
            output, status_code = wk.put_wiki_by_project(project_id, wiki_name, args, get_jwt_identity()['user_id'])
            return output, status_code
        else:
            return {
                "message": "your are not in this project or not administrator"
            }, 401

    @jwt_required
    def delete(self, project_id, wiki_name):
        status = pjt.verify_project_user(logger, project_id,
                                         get_jwt_identity()['user_id'])
        if status or get_jwt_identity()['role_id'] == 5:
            output, status_code = wk.delete_wiki_by_project(project_id, wiki_name)
            return output, status_code
        else:
            return {
                "message": "your are not in this project or not administrator"
            }, 401


# Get Project Version List
class ProjectVersionList(Resource):
    @jwt_required
    def get(self, project_id):
        status = pjt.verify_project_user(logger, project_id,
                                         get_jwt_identity()['user_id'])
        if status or get_jwt_identity()['role_id'] == 5:
            output = vn.get_version_list_by_project(project_id)
            return output
        else:
            return {
                "message": "your are not in this project or not administrator"
            }, 401


# Create  Project Version
class ProjectVersion(Resource):
    @jwt_required
    def post(self, project_id):
        status = pjt.verify_project_user(logger, project_id,
                                         get_jwt_identity()['user_id'])
        if status or get_jwt_identity()['role_id'] == 5:
            root_parser = reqparse.RequestParser()
            root_parser.add_argument('version', type=dict, required=True)
            root_args = root_parser.parse_args()
            output, status_code = vn.post_version_by_project(project_id, root_args)
            return output, status_code
        else:
            return {
                "message": "your are not in this project or not administrator"
            }, 401


# Get Project Version Information
class ProjectVersionInfo(Resource):
    @jwt_required
    def get(self, project_id, version_id):
        status = pjt.verify_project_user(logger, project_id,
                                         get_jwt_identity()['user_id'])
        if status or get_jwt_identity()['role_id'] == 5:
            output, status_code = vn.get_version_by_version_id(version_id)
            return output, status_code
        else:
            return {
                "message": "your are not in this project or not administrator"
            }, 401

    @jwt_required
    def put(self, project_id, version_id):
        status = pjt.verify_project_user(logger, project_id,
                                         get_jwt_identity()['user_id'])
        if status or get_jwt_identity()['role_id'] == 5:
            root_parser = reqparse.RequestParser()
            root_parser.add_argument('version', type=dict, required=True)
            root_args = root_parser.parse_args()
            print(root_args)
            output, status_code = vn.put_version_by_version_id(version_id, root_args)
            return output, status_code
        else:
            return {
                "message": "your are not in this project or not administrator"
            }, 401

    @jwt_required
    def delete(self, project_id, version_id):
        status = pjt.verify_project_user(logger, project_id,
                                         get_jwt_identity()['user_id'])
        if status or get_jwt_identity()['role_id'] == 5:
            output, status_code = vn.delete_version_by_version_id(version_id)
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
                output = user.get_role_list()
                return output
            except Exception as e:
                return {"message": str(e)}, 400
        else:
            return {"message": "your role art not RD/PM/administrator"}, 401


class GitProjectBranches(Resource):
    @jwt_required
    def get(self, repository_id):
        role_id = get_jwt_identity()["role_id"]

        if role_id in (1, 3, 5):
            project_id = repository_id
            try:
                output = pjt.get_git_project_branches(logger, app, project_id)
                return output
            except Exception as e:
                return {"message": str(e)}, 400
        else:
            return {"message": "your role art not RD/PM/administrator"}, 401

    @jwt_required
    def post(self, repository_id):
        role_id = get_jwt_identity()["role_id"]

        if role_id in (1, 3, 5):
            project_id = repository_id
            parser = reqparse.RequestParser()
            parser.add_argument('branch', type=str, required=True)
            parser.add_argument('ref', type=str, required=True)
            args = parser.parse_args()
            logger.info("post body: {0}".format(args))
            output = pjt.create_git_project_branch(logger, app, project_id,
                                                   args)
            return output
        else:
            return {"message": "your role art not RD/PM/administrator"}, 401


class GitProjectBranch(Resource):
    @jwt_required
    def get(self, repository_id, branch_name):
        role_id = get_jwt_identity()["role_id"]

        if role_id in (1, 3, 5):
            project_id = repository_id
            branch = branch_name
            output = pjt.get_git_project_branch(logger, app, project_id,
                                                branch)
            return output
        else:
            return {"message": "your role art not RD/PM/administrator"}, 401

    @jwt_required
    def delete(self, repository_id, branch_name):
        role_id = get_jwt_identity()["role_id"]

        if role_id in (1, 3, 5):
            project_id = repository_id
            branch = branch_name
            output = pjt.delete_git_project_branch(logger, app, project_id,
                                                   branch)
            return output
        else:
            return {"message": "your role art not RD/PM/administrator"}, 401


class GitProjectRepositories(Resource):
    @jwt_required
    def get(self, repository_id, branch_name):
        role_id = get_jwt_identity()["role_id"]

        if role_id in (1, 3, 5):
            project_id = repository_id
            branch = branch_name
            output = pjt.get_git_project_repositories(logger, app, project_id,
                                                      branch)
            return output
        else:
            return {"message": "your role art not RD/PM/administrator"}, 401


class GitProjectFiles(Resource):
    @jwt_required
    def post(self, repository_id):
        role_id = get_jwt_identity()["role_id"]

        if role_id in (1, 3, 5):
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
            return {"message": "your role art not RD/PM/administrator"}, 401

    @jwt_required
    def put(self, repository_id):
        role_id = get_jwt_identity()["role_id"]

        if role_id in (1, 3, 5):
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
            return {"message": "your role art not RD/PM/administrator"}, 401


class GitProjectFile(Resource):
    @jwt_required
    def get(self, repository_id, branch_name, file_path):
        role_id = get_jwt_identity()["role_id"]

        if role_id in (1, 3, 5):
            project_id = repository_id
            branch = branch_name
            output = pjt.get_git_project_file(logger, app, project_id, branch,
                                              file_path)
            return output

        else:
            return {"message": "your role art not RD/PM/administrator"}, 401

    @jwt_required
    def delete(self, repository_id, branch_name, file_path):
        role_id = get_jwt_identity()["role_id"]

        if role_id in (1, 3, 5):
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
            return {"message": "your role art not RD/PM/administrator"}, 401


class GitProjectTags(Resource):
    @jwt_required
    def get(self, repository_id):
        role_id = get_jwt_identity()["role_id"]

        if role_id in (1, 3, 5):
            project_id = repository_id
            output = pjt.get_git_project_tags(logger, app, project_id)
            return output
        else:
            return {"message": "your role art not RD/PM/administrator"}, 401

    @jwt_required
    def post(self, repository_id):
        role_id = get_jwt_identity()["role_id"]

        if role_id in (1, 3, 5):
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
            return {"message": "your role art not RD/PM/administrator"}, 401


class GitProjectTag(Resource):
    @jwt_required
    def delete(self, repository_id, tag_name):
        role_id = get_jwt_identity()["role_id"]

        if role_id in (1, 3, 5):
            project_id = repository_id
            output = pjt.delete_git_project_tag(logger, app, project_id,
                                                tag_name)
            return output
        else:
            return {"message": "your role art not RD/PM/administrator"}, 401


class GitProjectDirectory(Resource):
    @jwt_required
    def post(self, repository_id, directory_path):
        role_id = get_jwt_identity()["role_id"]

        if role_id in (1, 5):
            project_id = repository_id
            directory_path = directory_path + "%2F%2Egitkeep"
            parser = reqparse.RequestParser()
            parser.add_argument('branch', type=str, required=True)
            parser.add_argument('commit_message', type=str, required=True)
            args = parser.parse_args()
            logger.info("post body: {0}".format(args))
            output = pjt.create_git_project_directory(logger, app, project_id,
                                                      directory_path, args)
            return output
        else:
            return {"message": "your role art not RD/administrator"}, 401

    @jwt_required
    def put(self, repository_id, directory_path):
        role_id = get_jwt_identity()["role_id"]

        if role_id in (1, 5):
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
            return output
        else:
            return {"message": "your role art not RD/administrator"}, 401

    @jwt_required
    def delete(self, repository_id, directory_path):
        role_id = get_jwt_identity()["role_id"]

        if role_id in (1, 5):
            project_id = repository_id
            parser = reqparse.RequestParser()
            parser.add_argument('branch', type=str, required=True)
            parser.add_argument('commit_message', type=str, required=True)
            args = parser.parse_args()
            logger.info("delete body: {0}".format(args))
            output = pjt.delete_git_project_directory(logger, app, project_id,
                                                      directory_path, args)
            return output
        else:
            return {"message": "your role art not RD/administrator"}, 401


class GitProjectMergeBranch(Resource):
    @jwt_required
    def post(self, repository_id):
        role_id = get_jwt_identity()["role_id"]

        if role_id in (1, 5):
            project_id = repository_id
            parser = reqparse.RequestParser()
            parser.add_argument('schemas', type=dict, required=True)
            args = parser.parse_args()["schemas"]
            logger.info("post body: {0}".format(args))
            output = pjt.create_git_project_mergebranch(
                logger, app, project_id, args)
            return output
        else:
            return {"message": "your role art not RD/administrator"}, 401


class GitProjectBranchCommmits(Resource):
    @jwt_required
    def get(self, repository_id):
        role_id = get_jwt_identity()["role_id"]

        if role_id in (1, 5):
            project_id = repository_id
            parser = reqparse.RequestParser()
            parser.add_argument('branch', type=str, required=True)
            args = parser.parse_args()
            logger.info("get body: {0}".format(args))
            output = pjt.get_git_project_branch_commits(
                logger, project_id, args['branch'])
            return output
        else:
            return {"message": "your role art not RD/administrator"}, 401


class GitProjectNetwork(Resource):
    @jwt_required
    def get(self, repository_id):
        role_id = get_jwt_identity()["role_id"]

        if role_id in (1, 5):
            project_id = repository_id
            output = pjt.get_git_project_network(logger, app, project_id)
            return output
        else:
            return {"message": "your role art not RD/administrator"}, 401


class GitProjectId(Resource):
    @jwt_required
    def get(self, repository_id):
        return pjt.get_git_project_id(logger, app, repository_id)


class PipelineExec(Resource):
    @jwt_required
    def get(self, repository_id):
        output_array = pipe.pipeline_exec_list(repository_id)
        return jsonify({'message': 'success', 'data': output_array})


class PipelineExecLogs(Resource):
    @jwt_required
    def get(self):
        parser = reqparse.RequestParser()
        parser.add_argument('repository_id', type=int, required=True)
        parser.add_argument('pipelines_exec_run', type=int, required=True)
        args = parser.parse_args()
        return pipe.pipeline_exec_logs(args)


class PipelineSoftware(Resource):
    @jwt_required
    def get(self):
        pipe_out_list = pipe.pipeline_software()
        output_list = []
        for pipe_out in pipe_out_list:
            if 'detail' in pipe_out:
                pipe_out['detail'] = json.loads(pipe_out['detail'].replace(
                    "'", '"'))
            output_list.append(pipe_out)
        return jsonify({'message': 'success', 'data': output_list})


class PipelineYaml(Resource):
    @jwt_required
    def get(self, repository_id, branch_name):
        output_array = pipe.get_ci_yaml(repository_id, branch_name)
        return output_array

    @jwt_required
    def post(self, repository_id, branch_name):
        parser = reqparse.RequestParser()
        parser.add_argument('detail')
        args = parser.parse_args()
        output = pipe.generate_ci_yaml(args, repository_id, branch_name)
        return output


class PipelinePhaseYaml(Resource):
    @jwt_required
    def get(self, repository_id, branch_name):
        return pipe.get_phase_yaml(repository_id, branch_name)


class IssueByProject(Resource):
    @jwt_required
    def get(self, project_id):
        status = pjt.verify_project_user(logger, project_id,
                                         get_jwt_identity()['user_id'])
        if status or get_jwt_identity()['role_id'] == 5:
            parser = reqparse.RequestParser()
            parser.add_argument('fixed_version_id', type=int)
            args = parser.parse_args()
            output, status_code = iss.get_issue_by_project(
                logger, app, project_id, args)
            return output, status_code
        else:
            return {'message': 'Dont have authorization to access issue list on project: {0}' \
                .format(project_id)}, 401


class IssueByTreeByProject(Resource):
    @jwt_required
    def get(self, project_id):
        status = pjt.verify_project_user(logger, project_id,
                                         get_jwt_identity()['user_id'])
        if status or get_jwt_identity()['role_id'] == 5:
            output, status_code = iss.get_issue_by_tree_by_project(
                logger, app, project_id)
            return output, status_code
        else:
            return {'message': 'Dont have authorization to access issue by tree on project: {0}' \
                .format(project_id)}, 401


class IssueByStatusByProject(Resource):
    @jwt_required
    def get(self, project_id):
        status = pjt.verify_project_user(logger, project_id,
                                         get_jwt_identity()['user_id'])
        if status or get_jwt_identity()['role_id'] == 5:
            output, status_code = iss.get_issue_by_status_by_project(
                logger, app, project_id)
            return output, status_code
        else:
            return {'message': 'Dont have authorization to access issue by status on project: {0}' \
                .format(project_id)}, 401


class IssueByDateByProject(Resource):
    @jwt_required
    def get(self, project_id):
        status = pjt.verify_project_user(logger, project_id,
                                         get_jwt_identity()['user_id'])
        if status or get_jwt_identity()['role_id'] == 5:
            output, status_code = iss.get_issue_by_date_by_project(
                logger, app, project_id)
            return output, status_code
        else:
            return {'message': 'Dont have authorization to access issue by date on project: {0}' \
                .format(project_id)}, 401


class IssuesProgressByProject(Resource):
    @jwt_required
    def get(self, project_id):
        status = pjt.verify_project_user(logger, project_id,
                                         get_jwt_identity()['user_id'])
        if status or get_jwt_identity()['role_id'] == 5:
            parser = reqparse.RequestParser()
            parser.add_argument('fixed_version_id', type=int)
            args = parser.parse_args()
            logger.debug("show fixed_version_id: {0}".format(
                args['fixed_version_id']))
            output_array = iss.get_issueProgress_by_project(
                logger, app, project_id, args)
            return output_array
        else:
            return {'message': 'Dont have authorization to access issue progress on project: {0}' \
                .format(project_id)}, 401


class IssuesProgressAllVersionByProject(Resource):
    @jwt_required
    def get(self, project_id):
        status = pjt.verify_project_user(logger, project_id,
                                         get_jwt_identity()['user_id'])
        if status or get_jwt_identity()['role_id'] == 5:
            output_array = iss.get_issueProgress_allVersion_by_project(
                logger, app, project_id)
            return output_array
        else:
            return {'message': 'Dont have authorization to access issue projess all version on project: {0}' \
                .format(project_id)}, 401


class IssuesStatisticsByProject(Resource):
    @jwt_required
    def get(self, project_id):
        status = pjt.verify_project_user(logger, project_id,
                                         get_jwt_identity()['user_id'])
        if status or get_jwt_identity()['role_id'] == 5:
            parser = reqparse.RequestParser()
            parser.add_argument('fixed_version_id', type=int)
            args = parser.parse_args()
            logger.debug("show fixed_version_id: {0}".format(
                args['fixed_version_id']))
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
        parser.add_argument('done_ratio', type=int, required=True)
        parser.add_argument('estimated_hours', type=int, required=True)

        # Attachment upload
        parser.add_argument('upload_file', type=werkzeug.datastructures.FileStorage, location='files')
        parser.add_argument('upload_filename', type=str)
        parser.add_argument('upload_description', type=str)

        args = parser.parse_args()
        output = iss.create_issue(args, get_jwt_identity()['user_id'])
        return output


class Issue(Resource):
    @jwt_required
    def get(self, issue_id):
        output = iss.get_issue_rd(issue_id)
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

        # Attachment upload
        parser.add_argument('upload_file', type=werkzeug.datastructures.FileStorage, location='files')
        parser.add_argument('upload_filename', type=str)
        parser.add_argument('upload_description', type=str)

        args = parser.parse_args()
        output = iss.update_issue_rd(logger, app, issue_id, args, get_jwt_identity()['user_id'])
        return output

    @jwt_required
    def delete(self, issue_id):
        status = iss.verify_issue_user(logger, app, issue_id,
                                       get_jwt_identity()['user_id'])
        if status or get_jwt_identity()['role_id'] == 5:
            output = iss.delete_issue(issue_id)
            return output
        else:
            return util.respond(401, "Error when deleting issues",
                                error=apiError.not_allowed(
                                    get_jwt_identity()['user_account'],
                                    [1, 3, 5]
                                ))


class IssueStatus(Resource):
    @jwt_required
    def get(self):
        output = iss.get_issue_status()
        return jsonify({'message': 'success', 'data': output})


class IssuePrioriry(Resource):
    @jwt_required
    def get(self):
        output = iss.get_issue_priority()
        return jsonify({'message': 'success', 'data': output})


class IssueTracker(Resource):
    @jwt_required
    def get(self):
        output = iss.get_issue_trackers()
        return jsonify({'message': 'success', 'data': output})


class IssueRDbyUser(Resource):
    @jwt_required
    def get(self, user_id):
        if int(user_id) == get_jwt_identity()['user_id'] or get_jwt_identity(
        )['role_id'] in (3, 5):
            output = iss.get_issue_by_user(user_id)
            return output
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
        output = iss.get_issue_statistics(args, get_jwt_identity()['user_id'])
        return output


class OpenIssueStatistics(Resource):
    @jwt_required
    def get(self):
        output = iss.get_open_issue_statistics(get_jwt_identity()['user_id'])
        return output


class IssueWeekStatistics(Resource):
    @jwt_required
    def get(self):
        output = iss.get_issue_statistics_in_period(
            logger, app, 'week',
            get_jwt_identity()['user_id'])
        return output


class IssueMonthStatistics(Resource):
    @jwt_required
    def get(self):
        output = iss.get_issue_statistics_in_period(
            logger, app, 'month',
            get_jwt_identity()['user_id'])
        return output


class DashboardIssuePriority(Resource):
    @jwt_required
    def get(self, user_id):
        if int(user_id) == get_jwt_identity()['user_id'] or get_jwt_identity(
        )['role_id'] in (3, 5):
            return iss.count_priority_number_by_issues(user_id)
        else:
            return {'message': 'Access token is missing or invalid'}, 401


class DashboardIssueProject(Resource):
    @jwt_required
    def get(self, user_id):
        if int(user_id) == get_jwt_identity()['user_id'] or get_jwt_identity(
        )['role_id'] in (3, 5):
            return iss.count_project_number_by_issues(logger, app, user_id)
        else:
            return {'message': 'Access token is missing or invalid'}, 401


class DashboardIssueType(Resource):
    @jwt_required
    def get(self, user_id):
        if int(user_id) == get_jwt_identity()['user_id'] or get_jwt_identity(
        )['role_id'] in (3, 5):
            return iss.count_type_number_by_issues(logger, app, user_id)
        else:
            return {'message': 'Access token is missing or invalid'}, 401


class RequirementByIssue(Resource):

    # 用issues ID 取得目前所有的需求清單
    @jwt_required
    def get(self, issue_id):
        # temp = get_jwt_identity()
        print(get_jwt_identity())
        output = requirement.get_requirements_by_issue_id(issue_id)
        return jsonify({'message': 'success', 'data': output})

    # 用issues ID 新建立需求清單
    @jwt_required
    def post(self, issue_id):
        parser = reqparse.RequestParser()
        parser.add_argument('project_id', type=int)
        # parser.add_argument('flow_info', type=str)
        args = parser.parse_args()
        output = requirement.post_requirement_by_issue_id(issue_id, args)
        return jsonify({'message': 'success', 'data': output})


class Requirement(Resource):

    # 用requirement_id 取得目前需求流程
    @jwt_required
    def get(self, requirement_id):
        # temp = get_jwt_identity()
        output = requirement.get_requirement_by_rqmt_id(requirement_id)
        return jsonify({'message': 'success', 'data': output})

    # 用requirement_id 刪除目前需求流程
    @jwt_required
    def delete(self, requirement_id):
        # temp = get_jwt_identity()
        output = {}
        output = requirement.del_requirement_by_rqmt_id(requirement_id)
        return jsonify({'message': 'success'})

    # 用requirement_id 更新目前需求流程
    @jwt_required
    def put(self, requirement_id):
        output = {}
        parser = reqparse.RequestParser()
        parser.add_argument('flow_info', type=str)
        args = parser.parse_args()
        output = requirement.modify_requirement_by_rqmt_id(requirement_id, args)
        return jsonify({'message': 'success'})


class GetFlowType(Resource):
    @jwt_required
    def get(self):
        output = flow.get_flow_support_type()
        return jsonify({'message': 'success', 'data': output})


class FlowByIssue(Resource):

    # 用issues ID 取得目前所有的需求清單
    @jwt_required
    def get(self, issue_id):
        requirement_ids = requirement.check_requirement_by_issue_id(issue_id)
        if not requirement_ids:
            return jsonify({'message': 'success', 'data': {}})
        output = []
        for requirement_id in requirement_ids:
            result = flow.get_flow_by_requirement_id(requirement_id)
            if len(result) > 0:
                output.append({
                    'requirement_id': requirement_id,
                    'flow_data': result
                })
        return jsonify({'message': 'success', 'data': output})

    # 用issues ID 新建立需求清單
    @jwt_required
    def post(self, issue_id):
        output = {}
        parser = reqparse.RequestParser()
        parser.add_argument('project_id', type=int)
        parser.add_argument('type_id', type=int)
        parser.add_argument('name', type=str)
        parser.add_argument('description', type=str)
        args = parser.parse_args()
        check = requirement.check_requirement_by_issue_id(issue_id)
        if not check:
            requirements = requirement.post_requirement_by_issue_id(issue_id, args)
            requirement_id = requirements['requirement_id'][0]
        else:
            requirement_id = check[0]

        output = flow.post_flow_by_requirement_id(int(issue_id), requirement_id, args)
        return util.success(output, has_date=True)


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

    # 用requirement_id 取得目前需求流程
    @jwt_required
    def get(self, flow_id):
        output = flow.get_flow_by_flow_id(flow_id)
        return jsonify({'message': 'success', 'data': output})

    # 用requirement_id 刪除目前需求流程
    @jwt_required
    def delete(self, flow_id):
        output = flow.disabled_flow_by_flow_id(flow_id)
        return util.success(output, has_date=True)

    # 用requirement_id 更新目前需求流程
    @jwt_required
    def put(self, flow_id):
        parser = reqparse.RequestParser()
        parser.add_argument('serial_id', type=int)
        parser.add_argument('type_id', type=int)
        parser.add_argument('name', type=str)
        parser.add_argument('description', type=str)
        args = parser.parse_args()
        output = flow.modify_flow_by_flow_id(flow_id, args)
        return util.success(output, has_date=True)


class ParameterType(Resource):
    @jwt_required
    def get(self):
        output = parameter.get_parameter_types()
        print(output)
        return jsonify({'message': 'success', 'data': output})


class ParameterByIssue(Resource):

    # 用issues ID 取得目前所有的需求清單
    @jwt_required
    def get(self, issue_id):
        output = parameter.get_parameters_by_issue_id(issue_id)
        return jsonify({'message': 'success', 'data': output})

    # 用issues ID 新建立需求清單
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
        output = parameter.post_parameters_by_issue_id(issue_id, args)
        return jsonify({'message': 'success', 'data': output})


class Parameter(Resource):

    # 用requirement_id 取得目前需求流程
    @jwt_required
    def get(self, parameter_id):
        output = parameter.get_parameters_by_param_id(parameter_id)
        return jsonify({'message': 'success', 'data': output})

    # 用requirement_id 刪除目前需求流程
    @jwt_required
    def delete(self, parameter_id):
        output = parameter.del_parameters_by_param_id(parameter_id)
        return jsonify({'message': 'success', 'data': output})

    # 用requirement_id 更新目前需求流程
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
        output = parameter.modify_parameters_by_param_id(parameter_id, args)
        return jsonify({'message': 'success', "data": output})


class TestCaseByIssue(Resource):

    # 用issues ID 取得目前所有的目前測試案例
    @jwt_required
    def get(self, issue_id):
        output = {}
        output = testCase.get_testcase_by_issue_id(issue_id)
        return jsonify({'message': 'success', 'data': output})

    # 用issues ID 新建立測試案例
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
        output = testCase.post_testcase_by_issue_id(issue_id, args)
        return jsonify({'message': 'success', 'data': output})

class TestCaseByProject(Resource):

    # 用issues ID 取得目前所有的目前測試案例
    @jwt_required
    def get(self, project_id):
        output = testCase.get_testcase_by_project_id(project_id)
        return jsonify({'message': 'success', 'data': output})

    # 用issues ID 新建立測試案例
    @jwt_required
    def post(self, project_id):
        output = {}
        parser = reqparse.RequestParser()
        parser.add_argument('name', type=str)
        parser.add_argument('data', type=str)
        parser.add_argument('type_id', type=int)
        parser.add_argument('description', type=str)
        args = parser.parse_args()
        output = testCase.post_testcase_by_project_id(project_id, args)
        return jsonify({'message': 'success', 'data': output})


class TestCase(Resource):

    # 用testCase_id 取得目前測試案例
    @jwt_required
    def get(self, testCase_id):
        output = testCase.get_test_case_by_tc_id(testCase_id)
        return jsonify({'message': 'success', 'data': output})

    # 用testCase_id 刪除目前測試案例
    @jwt_required
    def delete(self, testCase_id):
        output = {}
        output = testCase.del_testcase_by_tc_id(testCase_id)
        return jsonify({'message': 'success', 'data': output})

    # 用testCase_id 更新目前測試案例
    @jwt_required
    def put(self, testCase_id):
        output = {}
        parser = reqparse.RequestParser()
        parser.add_argument('data')
        parser.add_argument('name', type=str)
        parser.add_argument('type_id', type=int)
        parser.add_argument('description', type=str)
        args = parser.parse_args()
        output = testCase.modify_testCase_by_tc_id(testCase_id, args)
        return jsonify({'message': 'success', 'data': output})


class GetTestCaseAPIMethod(Resource):
    @jwt_required
    def get(self):
        output = {}
        output = testCase.get_api_method()
        return jsonify({'message': 'success', 'data': output})


class GetTestCaseType(Resource):
    @jwt_required
    def get(self):
        output = {}
        output = testCase.get_testcase_type_wrapped()
        return jsonify({'message': 'get_testCase_typesuccess', 'data': output})


class TestItemByTestCase(Resource):

    # 用issues ID 取得目前所有的目前測試案例
    @jwt_required
    def get(self, testCase_id):
        output = {}
        output = testItem.get_testItem_by_testCase_id(testCase_id)
        return jsonify({'message': 'success', 'data': output})

    # 用issues ID 新建立測試案例
    @jwt_required
    def post(self, testCase_id):
        output = {}
        parser = reqparse.RequestParser()
        parser.add_argument('project_id', type=int)
        parser.add_argument('name', type=str)
        parser.add_argument('issue_id', type=int)
        parser.add_argument('is_passed', type=bool)
        args = parser.parse_args()
        output = testItem.post_testitem_by_testcase_id(testCase_id, args)
        return jsonify({'message': 'success', 'data': output})


class TestItem(Resource):

    # item_id 取得目前測試項目
    @jwt_required
    def get(self, item_id):
        output = testItem.get_testitem_by_ti_id(item_id)
        return jsonify({'message': 'success', 'data': output})

    # item_id 刪除目前測試項目
    @jwt_required
    def delete(self, item_id):
        output = testItem.del_testItem_by_ti_id(item_id)
        return jsonify({'message': 'success', 'data': output})

    # item_id 更新目前測試項目
    @jwt_required
    def put(self, item_id):
        output = {}
        parser = reqparse.RequestParser()
        print(parser)
        parser.add_argument('name', type=str)
        parser.add_argument('is_passed', type=bool)
        args = parser.parse_args()
        output = testItem.modify_testItem_by_ti_id(item_id, args)
        return jsonify({'message': 'success', 'data': output})


class TestValueByTestItem(Resource):

    # 用issues ID 取得目前所有的目前測試案例
    @jwt_required
    def get(self, item_id):
        output = testValue.get_testValue_by_testItem_id(item_id)
        return jsonify({'message': 'success', 'data': output})

    # 用issues ID 新建立測試案例
    @jwt_required
    def post(self, item_id):
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
        output = testValue.post_testValue_by_testItem_id(item_id, args)
        return jsonify({'message': 'success', 'data': output})


class GetTestValueLocation(Resource):
    @jwt_required
    def get(self):
        output = {}
        output = testValue.get_testValue_httpLocation()
        return jsonify({'message': 'success', 'data': output})


class GetTestValueType(Resource):
    @jwt_required
    def get(self):
        output = {}
        output = testValue.get_testValue_httpType()
        return jsonify({'message': 'success', 'data': output})


class TestValue(Resource):

    @jwt_required
    def get(self, value_id):
        output = testValue.get_testValue_by_tv_id(value_id)
        return jsonify({'message': 'success', 'data': output})

    @jwt_required
    def delete(self, value_id):
        output = testValue.del_testValue_by_tv_id(value_id)
        return jsonify({'message': 'success', 'data': output})

    @jwt_required
    def put(self, value_id):
        parser = reqparse.RequestParser()
        parser.add_argument('key', type=str)
        parser.add_argument('value', type=str)
        parser.add_argument('type_id', type=str)
        parser.add_argument('location_id', type=str)
        args = parser.parse_args()
        output = testValue.modify(value_id, args)
        return jsonify({'message': 'success', 'data': output})


class TestResult(Resource):
    @jwt_required
    def post(self):
        parser = reqparse.RequestParser()
        parser.add_argument('project_id', type=int, required=True)
        parser.add_argument('total', type=int, required=True)
        parser.add_argument('fail', type=int, required=True)
        parser.add_argument('branch', type=str, required=True)
        parser.add_argument('report', type=str, required=True)
        args = parser.parse_args()
        output = testResult.save(args)
        return output


class GetPostmanReport(Resource):
    @jwt_required
    def get(self, project_id):
        return testResult.get_report(project_id)


class ExportToPostman(Resource):
    @jwt_required
    def get(self, project_id):
        jwt_identity = get_jwt_identity()
        parser = reqparse.RequestParser()
        parser.add_argument('target', type=str, required=True)
        args = parser.parse_args()
        target = args['target']
        output = ci.export_to_postman(project_id, target, jwt_identity)
        return output


class DumpByIssue(Resource):
    @jwt_required
    def get(self, issue_id):
        output = iss.dump(logger, issue_id)
        return output


class CreateCheckmarxScan(Resource):
    @jwt_required
    def post(self):
        parser = reqparse.RequestParser()
        parser.add_argument('cm_project_id', type=int, required=True)
        parser.add_argument('repo_id', type=int, required=True)
        parser.add_argument('scan_id', type=int, required=True)
        args = parser.parse_args()
        return cm.create_scan(args)


class GetCheckmarxLatestScan(Resource):
    @jwt_required
    def get(self, project_id):
        return cm.get_latest_scan_wrapped(project_id)


class GetCheckmarxLatestScanStats(Resource):
    @jwt_required
    def get(self, project_id):
        return cm.get_latest_scan_stats_wrapped(project_id)


class GetCheckmarxLatestReport(Resource):
    @jwt_required
    def get(self, project_id):
        return cm.get_latest_report_wrapped(project_id)


class GetCheckmarxReport(Resource):
    @jwt_required
    def get(self, report_id):
        return cm.get_report(report_id)


class GetCheckmarxScanStatus(Resource):
    @jwt_required
    def get(self, scan_id):
        return cm.get_scan_status_wrapped(scan_id)


class RegisterCheckmarxReport(Resource):
    @jwt_required
    def post(self, scan_id):
        return cm.register_report(scan_id)


class GetCheckmarxReportStatus(Resource):
    @jwt_required
    def get(self, report_id):
        return cm.get_report_status_wrapped(report_id)


class GetCheckmarxScanStatistics(Resource):
    @jwt_required
    def get(self, scan_id):
        return cm.get_scan_statistics_wrapped(scan_id)


class SonarReport(Resource):
    @jwt_required
    def get(self, project_id):
        role_id = get_jwt_identity()["role_id"]

        if role_id in (3, 5):
            try:
                output = pjt.get_sonar_report(logger, app, project_id)
                return output
            except Exception as e:
                return {"message": str(e)}, 400
        else:
            return {"message": "your role art not PM/administrator"}, 401


class GetTestSummary(Resource):
    @jwt_required
    def get(self, project_id):
        role_id = get_jwt_identity()["role_id"]

        if role_id in (3, 5):
            try:
                return pjt.get_test_summary(logger, app, project_id, cm)
            except Exception as e:
                return {"message": str(e)}, 400
        else:
            return {"message": "your role art not PM/administrator"}, 401


class ProjectFiles(Resource):
    @jwt_required
    def post(self, project_id):
        plan_project_id = pjt.get_plan_project_id(project_id)
        if plan_project_id < 0:
            return util.respond(404, 'Error while uploading a file to a project.',
                                error=apiError.project_not_found(project_id))

        parser = reqparse.RequestParser()
        parser.add_argument('filename', type=str)
        parser.add_argument('version_id', type=str)
        parser.add_argument('description', type=str)
        args = parser.parse_args()
        return redmine.rm_upload_to_project(plan_project_id, args)

    @jwt_required
    def get(self, project_id):
        plan_project_id = pjt.get_plan_project_id(project_id)
        return redmine.rm_list_file(plan_project_id)


class DownloadFile(Resource):
    @jwt_required
    def get(self):
        parser = reqparse.RequestParser()
        parser.add_argument('id', type=int)
        parser.add_argument('filename', type=str)
        args = parser.parse_args()
        return redmine.rm_download_attachment(args)


class RedmineFile(Resource):
    @jwt_required
    def delete(self, file_id):
        return redmine.rm_delete_attachment(file_id)


class SystemGitCommitID(Resource):
    def get(self):
        if os.path.exists("git_commit"):
            with open("git_commit") as f:
                git_commit_id = f.read().splitlines()[0]
                return {"message": "success", "data": {"git_commit_id": "{0}".format(git_commit_id)}}
        else:
            return {"message": "git_commit file is not exist"}, 400


# Project list
api.add_resource(TotalProjectList, '/project/list')

# Project(redmine & gitlab & db)
api.add_resource(CreateProject, '/project')
api.add_resource(Project, '/project/<sint:project_id>')

# Gitlab project
api.add_resource(GitProjects, '/git_projects')
api.add_resource(GitOneProject, '/git_one_project/<sint:project_id>')
api.add_resource(GitProjectWebhooks, '/git_project_webhooks/<sint:project_id>')

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
                 '/repositories/rd/<repository_id>/commits')
api.add_resource(GitProjectNetwork, '/repositories/<repository_id>/overview')
api.add_resource(GitProjectId, '/repositories/<repository_id>/id')

# Project
api.add_resource(ProjectsByUser, '/projects_by_user/<int:user_id>')
api.add_resource(ProjectUserList, '/project/<sint:project_id>/user/list')
api.add_resource(ProjectAddMember, '/project/<sint:project_id>/member')
api.add_resource(ProjectDeleteMember,
                 '/project/<sint:project_id>/member/<int:user_id>')
api.add_resource(ProjectWikiList, '/project/<sint:project_id>/wiki')
api.add_resource(ProjectWiki, '/project/<sint:project_id>/wiki/<wiki_name>')
api.add_resource(ProjectVersionList, '/project/<sint:project_id>/version/list')
api.add_resource(ProjectVersion, '/project/<sint:project_id>/version')
api.add_resource(ProjectVersionInfo,
                 '/project/<sint:project_id>/version/<int:version_id>')

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
api.add_resource(PipelinePhaseYaml,
                 '/pipelines/<repository_id>/branch/<branch_name>/phase_yaml')
api.add_resource(
    PipelineYaml,
    '/pipelines/<repository_id>/branch/<branch_name>/generate_ci_yaml')

# issue
api.add_resource(IssueByProject, '/project/<sint:project_id>/issues')
api.add_resource(IssueByTreeByProject, '/project/<sint:project_id>/issues_by_tree')
api.add_resource(IssueByStatusByProject,
                 '/project/<sint:project_id>/issues_by_status')
api.add_resource(IssueByDateByProject, '/project/<sint:project_id>/issues_by_date')
api.add_resource(IssuesProgressByProject,
                 '/project/<sint:project_id>/issues_progress')
api.add_resource(IssuesProgressAllVersionByProject,
                 '/project/<sint:project_id>/issues_progress/all_version')
api.add_resource(IssuesStatisticsByProject,
                 '/project/<sint:project_id>/issues_statistics')
api.add_resource(IssueCreate, '/issues')
api.add_resource(Issue, '/issues/<issue_id>')
api.add_resource(IssueStatus, '/issues_status')
api.add_resource(IssuePrioriry, '/issues_priority')
api.add_resource(IssueTracker, '/issues_tracker')
api.add_resource(IssueRDbyUser, '/issues_by_user/rd/<user_id>')
api.add_resource(IssueStatistics, '/issues/statistics')
api.add_resource(OpenIssueStatistics, '/issues/open_statistics')
api.add_resource(IssueWeekStatistics, '/issues/week_statistics')
api.add_resource(IssueMonthStatistics, '/issues/month_statistics')

# dashboard
api.add_resource(DashboardIssuePriority,
                 '/dashboard_issues_priority/rd/<user_id>')
api.add_resource(DashboardIssueProject, '/dashboard_issues_project/<user_id>')
api.add_resource(DashboardIssueType, '/dashboard_issues_type/<user_id>')

# testPhase Requirement
api.add_resource(RequirementByIssue, '/requirements_by_issue/<issue_id>')
api.add_resource(Requirement, '/requirements/<requirement_id>')

# testPhase Flow

api.add_resource(FlowByIssue, '/flows_by_issue/<issue_id>')
# api.add_resource(FlowByRequirement, '/flows_by_requirement/<requirement_id>')
api.add_resource(GetFlowType, '/flows/support_type')
api.add_resource(Flow, '/flows/<flow_id>')

# testPhase Parameters FLow
api.add_resource(ParameterByIssue, '/parameters_by_issue/<issue_id>')
api.add_resource(Parameter, '/parameters/<parameter_id>')
api.add_resource(ParameterType, '/parameter_types')

# testPhase TestCase Support Case Type
api.add_resource(GetTestCaseType, '/testCases/support_type')

# testPhase TestCase
api.add_resource(TestCaseByIssue, '/testCases_by_issue/<issue_id>')
api.add_resource(TestCaseByProject, '/testCases_by_project/<project_id>')
api.add_resource(TestCase, '/testCases/<testCase_id>')

# testPhase TestCase Support API Method
api.add_resource(GetTestCaseAPIMethod, '/testCases/support_RestfulAPI_Method')

# testPhase TestItem Support API Method
api.add_resource(TestItemByTestCase, '/testItems_by_testCase/<testCase_id>')
api.add_resource(TestItem, '/testItems/<item_id>')

# testPhase Testitem Value
api.add_resource(GetTestValueLocation, '/testValues/support_locations')
api.add_resource(GetTestValueType, '/testValues/support_types')
api.add_resource(TestValueByTestItem, '/testValues_by_testItem/<item_id>')
api.add_resource(TestValue, '/testValues/<value_id>')

# TestResult writing
api.add_resource(TestResult, '/testResults')
api.add_resource(GetPostmanReport, '/postman_report/<sint:project_id>')

# Export tests to postman json format
api.add_resource(ExportToPostman, '/export_to_postman/<sint:project_id>')

# Checkmarx report generation
api.add_resource(CreateCheckmarxScan, '/checkmarx/create_scan')
api.add_resource(GetCheckmarxLatestScan, '/checkmarx/latest_scan/<sint:project_id>')
api.add_resource(GetCheckmarxLatestScanStats,
                 '/checkmarx/latest_scan_stats/<sint:project_id>')
api.add_resource(GetCheckmarxLatestReport,
                 '/checkmarx/latest_report/<sint:project_id>')
api.add_resource(GetCheckmarxReport, '/checkmarx/report/<report_id>')
api.add_resource(GetCheckmarxScanStatus, '/checkmarx/scan_status/<scan_id>')
api.add_resource(GetCheckmarxScanStatistics, '/checkmarx/scan_stats/<scan_id>')
api.add_resource(RegisterCheckmarxReport, '/checkmarx/report/<scan_id>')
api.add_resource(GetCheckmarxReportStatus,
                 '/checkmarx/report_status/<report_id>')

# Get everything by issue_id
api.add_resource(DumpByIssue, '/dump_by_issue/<issue_id>')

# Get Sonarqube report by project_id
api.add_resource(SonarReport, '/sonar_report/<sint:project_id>')

# Get three test results
api.add_resource(GetTestSummary, '/project/<sint:project_id>/test_summary')

# Files
api.add_resource(ProjectFiles, '/project/<sint:project_id>/file')
api.add_resource(DownloadFile, '/download')
api.add_resource(RedmineFile, '/file/<int:file_id>')

# git commit
api.add_resource(SystemGitCommitID, '/system_git_commit_id')

if __name__ == "__main__":
    db.init_app(app)
    jsonwebtoken.init_app(app)
    app.run(host='0.0.0.0', port=10009, debug=(config.get('DEBUG') is True))
