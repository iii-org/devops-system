from flask import Flask
from flask import Response
from flask import jsonify
from flask import request as flask_req
from flask_restful import Resource, Api, reqparse
from flask_jwt_extended import jwt_required

import logging
from logging import handlers
import json
import datetime
from model import db
from jsonwebtoken import jsonwebtoken

import resources.util as util
import resources.auth as auth
import resources.issue as issue
import resources.project as project
import resources.pipeline as pipeline


app = Flask(__name__)
app.config.from_object('config')
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = datetime.timedelta(days=1)
api = Api(app)

handler = handlers.TimedRotatingFileHandler(
    'devops-api.log', when='D'\
        , interval=1, backupCount=14)
handler.setFormatter(logging.Formatter(
    '%(asctime)s %(filename)s [line:%(lineno)d] %(levelname)s %(message)s'\
        , '%Y %b %d, %a %H:%M:%S'))
logger = logging.getLogger('devops.api')
logger.setLevel(logging.DEBUG)
logger.addHandler(handler)

ut = util.util()
au = auth.auth()
iss = issue.Issue(logger, app)
pjt = project.Project(logger, app)
pipe = pipeline.Pipeline()

headers = {
    'Content-Type': 'application/json',
    'Authorization': 'Bearer {0}'.format(au.get_token(logger))
}

class Index(Resource):

    def get(self):
        iss.create_data_into_project_relationship(logger)
        return {"message": "DevOps api is working"}


class Issue_by_user(Resource):

    @jwt_required
    def get(self, user_account):
        output = iss.get_issues_by_user(logger, app, user_account)
        return {"issue_number": output.json()}


class Issue(Resource):

    @jwt_required
    def get(self, issue_id):
        output = iss.get_issue(logger, app, issue_id)
        return output.json()

    @jwt_required
    def put(self, issue_id):
        parser = reqparse.RequestParser()
        parser.add_argument('status_id', type=int)
        parser.add_argument('done_ratio', type=int)
        parser.add_argument('notes')
        args = parser.parse_args()
        logger.info("put body: {0}".format(args))
        output = iss.update_issue(logger, app, issue_id, args)


class IssueStatus(Resource):

    @jwt_required
    def get (self):
        output = iss.get_issue_status(logger, app)
        return output.json()


class RedmineProject(Resource):

    @jwt_required
    def get(self, user_account):
        output = iss.get_project(logger, app, user_account)
        return {"projects": output.json()["user"]["memberships"]}


class Pipelines_gitrepository(Resource):

    @jwt_required
    def get(self):
        url = "https://10.50.1.55/v3/projects/c-7bl58:p-wxgdj/sourcecoderepositories"

        output = ut.callgetapi(url, logger, headers)
        return output.json()['data']


class Pipelines(Resource):

    @jwt_required
    def get(self):
        url = "https://10.50.1.55/v3/projects/c-7bl58:p-wxgdj/pipelines"
        # get hook project list
        output = ut.callgetapi(url, logger, headers)
        return output.json()['data']

    @jwt_required
    def post(self):
        url = "https://10.50.1.55/v3/projects/c-7bl58:p-wxgdj/pipelines"
        parameter = {
            "type": "pipeline",
            "sourceCodeCredentialId": "user-j8mp5:p-wxgdj-gitlab-root",
            "repositoryUrl": "http://10.50.0.20/root/devops-flask",
            "triggerWebhookPr": False,
            "triggerWebhookPush": True,
            "triggerWebhookTag": False
        }
        output = ut.callpostapi(url, parameter, logger, headers)
        return output.json()


class PipelineID(Resource):

    @jwt_required
    def delete(self, pipelineid):
        url = "https://10.50.1.55/v3/projects/c-7bl58:p-wxgdj/pipelines/{0}".format(pipelineid)
        output = ut.calldeleteapi(url, logger, headers)
        return "Successful"

    @jwt_required
    def post(self, pipelineid):
        url = "https://10.50.1.55/v3/projects/c-7bl58:p-wxgdj/pipelines/{0}".format(pipelineid)
        logger.info("flask_req.data")
        parameter = {"branch": "master"}
        url = url+"?action=run"
        logger.info("url {0}".format(url))
        logger.info("data {0}".format(json.dumps(parameter)))
        logger.info("headers {0}".format(headers))
        output = ut.callpostapi(url, parameter, logger,headers)
        return "successful"


class Get_pipeline_branchs(Resource):

    @jwt_required
    def get(self, pipelineid):
        url = "https://10.50.1.55/v3/projects/c-7bl58:p-wxgdj/pipelines/{0}/branches".format(pipelineid)
        output = ut.callgetapi(url, logger, headers)
        return output.json()


class PipelineExecutions(Resource):

    @jwt_required
    def get(self):
        url = "https://10.50.1.55/v3/projects/c-7bl58:p-wxgdj/pipelineexecutions?order=desc"

        output = ut.callgetapi(url, logger, headers)
        return output.json()['data']


class PipelineExecutionsOne(Resource):

    @jwt_required
    def get(self, pipelineexecutionsid):
        url = "https://10.50.1.55/v3/projects/c-7bl58:p-wxgdj/pipelineexecutions/{0}".format(pipelineexecutionsid)

        output = ut.callgetapi(url, logger, headers)
        return output.json()['stages']

    
class GitProjects(Resource):

    @jwt_required
    def get (self):
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
    def get (self, user_id):
        output_array = pjt.get_project_list(logger, user_id)
        return jsonify(output_array)


class UserLogin(Resource):

    def post(self):
        parser = reqparse.RequestParser()
        parser.add_argument('username', type=str, required=True)
        parser.add_argument('password', type=str, required=True)
        args = parser.parse_args()
        token = au.user_login(logger, args)
        if token is None:
            return None, 400
        else:
            return jsonify({"token": token})


class UserForgetPassword(Resource):

    @jwt_required
    def post(self):
        parser = reqparse.RequestParser()
        parser.add_argument('mail', type=str, required=True)
        parser.add_argument('user_account', type=str, required=True)
        args = parser.parse_args()
        status = au.user_forgetpassword(logger, args)


class UserInfo(Resource):

    @jwt_required
    def get (self, user_id):
        user_info = au.user_info(logger, user_id)
        return jsonify(user_info)

    @jwt_required
    def post(self, user_id):
        parser = reqparse.RequestParser()
        parser.add_argument('name', type=str)
        parser.add_argument('username', type=str)
        parser.add_argument('password', type=str)
        parser.add_argument('phone', type=int)
        parser.add_argument('email', type=str)
        parser.add_argument('group', type=str)
        parser.add_argument('role', type=str)
        args = parser.parse_args()
        au.update_user_info(logger, user_id, args)


class GitProjectBranches(Resource):

    @jwt_required
    def get(self, repository_id):
        project_id = repository_id
        output = pjt.get_git_project_branches(logger, app, project_id)
        branch_list = []
        for idx, i in enumerate(output.json()):
            branch = {
                "id": idx,
                "name": i["name"],
                "last_commit_message": i["commit"]["message"],
                "last_commit_time": i["commit"]["committed_date"],
                "uuid": i["commit"]["id"]
            }
            branch_list.append(branch)
        return branch_list

    @jwt_required
    def post(self, repository_id):
        project_id = repository_id
        parser = reqparse.RequestParser()
        parser.add_argument('branch', type=str)
        parser.add_argument('ref', type=str)
        args = parser.parse_args()
        logger.info("post body: {0}".format(args))
        output = pjt.create_git_project_branch(logger, app, project_id, args)
        return output.json()


class GitProjectBranch(Resource):

    @jwt_required
    def get(self, repository_id, branch_name):
        project_id = repository_id
        branch = branch_name
        output = pjt.get_git_project_branch(logger, app, project_id, branch)
        return output.json()

    @jwt_required
    def delete(self, repository_id, branch_name):
        project_id = repository_id
        branch = branch_name
        output = pjt.delete_git_project_branch(logger, app, project_id, branch)
        if str(output) == "<Response [204]>":
            return "Success Delete Branch"
        else:
            return str(output)


class GitProjectRepositories(Resource):

    @jwt_required
    def get(self, repository_id, branch_name):
        project_id = repository_id
        branch = branch_name
        output = pjt.get_git_project_repositories(logger, app, project_id, branch)
        return output.json()


class GitProjectFiles(Resource):

    @jwt_required
    def post(self, repository_id):
        project_id = repository_id
        parser = reqparse.RequestParser()
        parser.add_argument('branch', type=str)
        parser.add_argument('file_path', type=str)
        parser.add_argument('start_branch', type=str)
        parser.add_argument('encoding', type=str)
        parser.add_argument('author_email', type=str)
        parser.add_argument('author_name', type=str)
        parser.add_argument('content', type=str)
        parser.add_argument('commit_message', type=str)
        args = parser.parse_args()
        logger.info("post body: {0}".format(args))
        output = pjt.create_git_project_file(logger, app, project_id, args)
        if str(output) == "<Response [201]>":
            result = {
                "message": "success",
                "data": {
                    "file_path": output.json()["file_path"],
                    "branch_name": output.json()["branch"]
                }
            }
        else:
            result = "error"
        return result

    @jwt_required
    def put(self, repository_id):
        project_id = repository_id
        parser = reqparse.RequestParser()
        parser.add_argument('branch', type=str)
        parser.add_argument('file_path', type=str)
        parser.add_argument('start_branch', type=str)
        parser.add_argument('encoding', type=str)
        parser.add_argument('author_email', type=str)
        parser.add_argument('author_name', type=str)
        parser.add_argument('content', type=str)
        parser.add_argument('commit_message', type=str)
        args = parser.parse_args()
        logger.info("put body: {0}".format(args))
        output = pjt.update_git_project_file(logger, app, project_id, args)
        if str(output) == "<Response [200]>":
            result = {
                "message": "success",
                "data": {
                    "file_path": output.json()["file_path"],
                    "branch_name": output.json()["branch"]
                }
            }
        else:
            result = "error"
        return result


class GitProjectFile(Resource):

    @jwt_required
    def get(self, repository_id, branch_name, file_path):
        project_id = repository_id
        branch = branch_name
        output = pjt.get_git_project_file(logger, app, project_id, branch, file_path)
        if str(output) == "<Response [200]>":
            result = {
                "message": "success",
                "data": {
                    "file_name": output.json()["file_name"],
                    "file_path": output.json()["file_path"],
                    "size": output.json()["size"],
                    "encoding": output.json()["encoding"],
                    "content": output.json()["content"],
                    "content_sha256": output.json()["content_sha256"],
                    "ref": output.json()["ref"],
                    "last_commit_id": output.json()["last_commit_id"]
                }
            }
        else:
            result = "error"
        return result

    @jwt_required
    def delete(self, repository_id, branch_name, file_path):
        project_id = repository_id
        branch = branch_name
        parser = reqparse.RequestParser()
        parser.add_argument('commit_message', type=str)
        args = parser.parse_args()
        logger.info("delete body: {0}".format(args))
        output = pjt.delete_git_project_file(logger, app, project_id, branch, file_path, args)
        if str(output) == "<Response [204]>":
            return "Success Delete FI"
        else:
            return str(output)


class GitProjectTags(Resource):

    @jwt_required
    def get (self, repository_id):
        project_id = repository_id
        output = pjt.get_git_project_tags(logger, app, project_id)
        return output.json()

    @jwt_required
    def post(self, repository_id):
        project_id = repository_id
        parser = reqparse.RequestParser()
        parser.add_argument('tag_name', type=str)
        parser.add_argument('ref', type=str)
        parser.add_argument('message', type=str)
        parser.add_argument('release_description', type=str)
        args = parser.parse_args()
        logger.info("post body: {0}".format(args))
        output = pjt.create_git_project_tags(logger, app, project_id, args)
        return output.json()


class GitProjectTag(Resource):
    
    @jwt_required
    def delete(self, repository_id, tag_name):
        project_id = repository_id
        output = pjt.delete_git_project_tag(logger, app, project_id, tag_name)
        if str(output) == "<Response [204]>":
            return "Success Delete Tag"
        else:
            return str(output)

class GitProjectDirectory(Resource):

    def post(self, repository_id, directory_name):
        project_id = repository_id
        directory_path = directory_name + "%2F%2Egitkeep"
        parser = reqparse.RequestParser()
        parser.add_argument('branch', type=str)
        parser.add_argument('commit_message', type=str)
        args = parser.parse_args()
        logger.info("post body: {0}".format(args))
        output = pjt.create_git_project_directory(logger, app, project_id, directory_path, args)
        if str(output) == "<Response [201]>":
            result = {
                "name": directory_name,
                "commit_message": args["commit_message"]
            }
        else:
            result = "error"
        return result


class PipelineInfo(Resource):

    @jwt_required
    def get (self, project_id):
        output = pipe.pipeline_info(logger, project_id)
        return jsonify(output)


class PipelineExec(Resource):

    @jwt_required
    def get (self, project_id):
        output_array = pipe.pipeline_exec(logger, project_id)
        return jsonify(output_array)


api.add_resource(Index, '/')

# Redmine issue
api.add_resource(Issue, '/issue/<issue_id>')
api.add_resource(Issue_by_user, '/issues_by_user/<user_account>')
api.add_resource(IssueStatus, '/issues_status')
api.add_resource(RedmineProject, '/redmine_project/<user_account>')

# Rancher pipeline
api.add_resource(Pipelines_gitrepository, '/pipelines_gitrepository')
api.add_resource(Pipelines, '/pipelines')
api.add_resource(PipelineID, '/pipelines/<pipelineid>')
api.add_resource(Get_pipeline_branchs, '/pipelines/<pipelineid>/branches')
api.add_resource(PipelineExecutions, '/pipelineexecutions')
api.add_resource(PipelineExecutionsOne, '/pipelineexecutions/<pipelineexecutionsid>')

# Gitlab project
api.add_resource(GitProjects, '/git_projects')
api.add_resource(GitOneProject, '/git_one_project/<project_id>')
api.add_resource(GitProjectWebhooks, '/git_project_webhooks/<project_id>')
api.add_resource(GitProjectBranches, '/repositories/rd/<repository_id>/branch')
api.add_resource(GitProjectBranch, '/repositories/rd/<repository_id>/branch/<branch_name>')
api.add_resource(GitProjectRepositories, '/repositories/rd/<repository_id>/branch/<branch_name>/tree')
api.add_resource(GitProjectFiles, '/repositories/rd/<repository_id>/branch/files')
api.add_resource(GitProjectFile, '/repositories/rd/<repository_id>/branch/<branch_name>/files/<file_path>')
api.add_resource(GitProjectTags, '/repositories/rd/<repository_id>/tags')
api.add_resource(GitProjectTag, '/repositories/rd/<repository_id>/tags/<tag_name>')
api.add_resource(GitProjectDirectory, '/repositories/rd/<repository_id>/directory/<directory_name>')

# Project
api.add_resource(ProjectList, '/project/rd/<user_id>')

# User
api.add_resource(UserLogin, '/user/login')
api.add_resource(UserForgetPassword, '/user/forgetPassword')
api.add_resource(UserInfo, '/user/<user_id>')

# pipeline
api.add_resource(PipelineInfo, '/pipelines/rd/<project_id>/pipelines_info')
api.add_resource(PipelineExec, '/pipelines/rd/<project_id>/pipelines_exec')

if __name__ == "__main__":
    db.init_app(app)
    jsonwebtoken.init_app(app)
    app.run(host='0.0.0.0', port=10009)
