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


class RedmineIssue_by_user(Resource):

    @jwt_required
    def get(self, user_account):
        output = iss.redmine_get_issues_by_user(logger, app, user_account)
        return {"issue_number": output.json()}


class RedmineIssue(Resource):

    @jwt_required
    def get(self, issue_id):
        output = iss.redmine_get_issue(logger, app, issue_id)
        return output.json()

    @jwt_required
    def put(self, issue_id):
        parser = reqparse.RequestParser()
        parser.add_argument('status_id', type=int)
        parser.add_argument('tracker_id', type=int)
        args = parser.parse_args()
        logger.info("put body: {0}".format(args))
        output = iss.redmine_update_issue(logger, app, issue_id, args)


class RedmineIssueStatus(Resource):

    @jwt_required
    def get (self):
        output = iss.redmine_get_issue_status(logger, app)
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
        return jsonify({'message': 'success', 'data': output_array})


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

    def post(self):
        parser = reqparse.RequestParser()
        parser.add_argument('mail', type=str, required=True)
        parser.add_argument('user_account', type=str, required=True)
        args = parser.parse_args()
        try:
            status = au.user_forgetpassword(logger, args)
            return jsonify({"message": "success"})
        except Exception as err:
            return jsonify({"message": err})


class UserInfo(Resource):

    @jwt_required
    def get (self, user_id):
        user_info = au.user_info(logger, user_id)
        return jsonify({'message': 'success', 'data': user_info})

    @jwt_required
    def put(self, user_id):
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
        return jsonify({'message': 'success'})


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


class GitProjectFile(Resource):

    @jwt_required
    def get(self, repository_id, branch_name, file_path):
        project_id = repository_id
        branch = branch_name
        output = pjt.get_git_project_file(logger, app, project_id, branch, file_path)
        return output.json()

    @jwt_required
    def post(self, repository_id, branch_name, file_path):
        project_id = repository_id
        branch = branch_name
        parser = reqparse.RequestParser()
        parser.add_argument('start_branch', type=str)
        parser.add_argument('encoding', type=str)
        parser.add_argument('author_email', type=str)
        parser.add_argument('author_name', type=str)
        parser.add_argument('content', type=str)
        parser.add_argument('commit_message', type=str)
        args = parser.parse_args()
        logger.info("post body: {0}".format(args))
        output = pjt.create_git_project_file(logger, app, project_id, branch, file_path, args)
        return output.json()

    @jwt_required
    def put(self, repository_id, branch_name, file_path):
        project_id = repository_id
        branch = branch_name
        parser = reqparse.RequestParser()
        parser.add_argument('start_branch', type=str)
        parser.add_argument('encoding', type=str)
        parser.add_argument('author_email', type=str)
        parser.add_argument('author_name', type=str)
        parser.add_argument('content', type=str)
        parser.add_argument('commit_message', type=str)
        args = parser.parse_args()
        logger.info("put body: {0}".format(args))
        output = pjt.update_git_project_file(logger, app, project_id, branch, file_path, args)
        return output.json()

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


class PipelineInfo(Resource):

    @jwt_required
    def get (self, project_id):
        output = pipe.pipeline_info(logger, project_id)
        return jsonify(output)


class PipelineExec(Resource):

    @jwt_required
    def get (self, project_id):
        output_array = pipe.pipeline_exec(logger, project_id)
        return jsonify({'message': 'success', 'data': output_array})


class IssuesIdList(Resource):

    @jwt_required
    def get (self, project_id):
        output_array = iss.get_issuesId_List(logger, project_id)
        return jsonify(output_array)


class IssueRD(Resource):

    @jwt_required
    def get (self, issue_id):
        return jsonify({'message': 'success', 'data': iss.get_issue_rd(logger, issue_id)})
    
    @jwt_required
    def put (self, issue_id):
        parser = reqparse.RequestParser()
        parser.add_argument('tracker', type=int)
        parser.add_argument('status', type=int)
        args = parser.parse_args()
        output = iss.update_issue_rd(logger, issue_id, args)
        if output[1] is 200:
            return {'message': 'success'}
        else:
            return {'message': output[0]}, 400


class IssueStatus(Resource):

    @jwt_required
    def get (self):
        output = iss.get_issue_status(logger)
        if output[1] is 200:
            return {'message': 'success', 'data': output[0]}
        else:
            return {'message': output[0]}, 400


class IssuePrioriry(Resource):

    @jwt_required
    def get (self):
        output = iss.get_issue_priority(logger)
        if output[1] is 200:
            return {'message': 'success', 'data': output[0]}
        else:
            return {'message': output[0]}, 400


class IssueCategory(Resource):

    @jwt_required
    def get (self):
        output = iss.get_issue_category(logger)
        if output[1] is 200:
            return {'message': 'success', 'data': output[0]}
        else:
            return {'message': output[0]}, 400


class IssueCategoryByProject(Resource):

    @jwt_required
    def get (self, project_id):
        output = iss.get_issue_category_by_project(logger, project_id)
        if output[1] is 200:
            return {'message': 'success', 'data': output[0]}
        else:
            return {'message': output[0]}, 400

api.add_resource(Index, '/')

# Redmine issue
api.add_resource(RedmineIssue, '/redmine_issue/<issue_id>')
api.add_resource(RedmineIssue_by_user, '/redmine_issues_by_user/<user_account>')
api.add_resource(RedmineIssueStatus, '/redmine_issues_status')
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
api.add_resource(GitProjectFile, '/repositories/rd/<repository_id>/branch/<branch_name>/files/<file_path>')

# Project
api.add_resource(ProjectList, '/project/rd/<user_id>')

# User
api.add_resource(UserLogin, '/user/login')
api.add_resource(UserForgetPassword, '/user/forgetPassword')
api.add_resource(UserInfo, '/user/<user_id>')

# pipeline
api.add_resource(PipelineInfo, '/pipelines/rd/<project_id>/pipelines_info')
api.add_resource(PipelineExec, '/pipelines/rd/<project_id>/pipelines_exec')

# issue
api.add_resource(IssuesIdList, '/project/rd/<project_id>/issues')
api.add_resource(IssueRD, '/issues/rd/<issue_id>')
api.add_resource(IssueStatus, '/issues_status')
api.add_resource(IssuePrioriry, '/issues_priority')
api.add_resource(IssueCategory, '/issues_category')
api.add_resource(IssueCategoryByProject, '/issues_category/<project_id>')

if __name__ == "__main__":
    db.init_app(app)
    jsonwebtoken.init_app(app)
    app.run(host='0.0.0.0', port=10009)
