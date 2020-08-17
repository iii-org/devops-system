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

import resources.util as util
import resources.auth as auth
import resources.issue as issue
import resources.redmine as redmine
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
redmine = redmine.Redmine(logger, app)
iss = issue.Issue()
pjt = project.Project(logger, app)
pipe = pipeline.Pipeline()

class Index(Resource):

    def get(self):
        iss.create_data_into_project_relationship(logger)
        return {"message": "DevOps api is working"}


class RedmineProjectList(Resource):

    @jwt_required
    def get(self):
        output = pjt.get_redmine_project_list(logger, app)
        return output.json()


class RedmineOneProject(Resource):

    @jwt_required
    def get(self, project_id):
        output = pjt.get_redmine_one_project(logger, app, project_id)
        return output.json()


class RedmineIssue_by_user(Resource):

    @jwt_required
    def get(self, user_account):
        output = redmine.redmine_get_issues_by_user(logger, app, user_account)
        return {"issue_number": output.json()}


class RedmineIssue(Resource):

    @jwt_required
    def get(self, issue_id):
        output = redmine.redmine_get_issue(logger, app, issue_id)
        return output.json()

    @jwt_required
    def put(self, issue_id):
        parser = reqparse.RequestParser()
        parser.add_argument('status_id', type=int)
        parser.add_argument('tracker_id', type=int)
        args = parser.parse_args()
        logger.info("put body: {0}".format(args))
        output = redmine.redmine_update_issue(logger, app, issue_id, args)


class RedmineIssueStatus(Resource):

    @jwt_required
    def get (self):
        output = redmine.redmine_get_issue_status(logger, app)
        return output.json()


class RedmineProject(Resource):

    @jwt_required
    def get(self, user_account):
        output = redmine.get_project(logger, app, user_account)
        return {"projects": output.json()["user"]["memberships"]}

    
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
        if int(user_id) == get_jwt_identity()['user_id']:
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
        token = au.user_login(logger, args)
        if token is None:
            return jsonify({"message": "Coult not get token"}), 500
        else:
            return jsonify({"message": "success", "data": {"token": token}})


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
    def get (self, user_id):
        if int(user_id) == get_jwt_identity()['user_id']:
            user_info = au.user_info(logger, user_id)
            return jsonify({'message': 'success', 'data': user_info})
        else:
            return {'message': 'Access token is missing or invalid'}, 401

    @jwt_required
    def put(self, user_id):
        if int(user_id) == get_jwt_identity()['user_id']:
            parser = reqparse.RequestParser()
            parser.add_argument('name', type=str)
            parser.add_argument('username', type=str)
            parser.add_argument('password', type=str)
            parser.add_argument('phone', type=int)
            parser.add_argument('email', type=str)
            parser.add_argument('group', type=str)
            parser.add_argument('role', type=str)
            args = parser.parse_args()
            try:
                au.update_user_info(logger, user_id, args)
                return jsonify({'message': 'success'})
            except Exception as error:
                return jsonify({"message": str(error)}), 400
        else:
            return {'message': 'Access token is missing or invalid'}, 401

    @jwt_required
    def delete (self, user_id):
        '''delete user'''
        try:
            au.delete_user(logger, user_id)
            return jsonify({'message': 'success'})
        except Exception as error:
            return jsonify({"message": str(error)}), 400


class User(Resource):

    @jwt_required
    def post (self):
        '''create user'''
        parser = reqparse.RequestParser()
        parser.add_argument('name', type=str)
        parser.add_argument('username', type=str, required=True)
        parser.add_argument('email', type=str, required=True)
        parser.add_argument('phone', type=int, required=True)
        parser.add_argument('login', type=str, required=True)
        parser.add_argument('password', type=str, required=True)
        parser.add_argument('group_id', action='append')
        parser.add_argument('role_id', type=int, required=True)
        args = parser.parse_args()
        output = au.create_user(logger, args, app)
        return output

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
        parser.add_argument('branch', type=str, required=True)
        parser.add_argument('ref', type=str, required=True)
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
        parser.add_argument('commit_message', type=str, required=True)
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
        parser.add_argument('tag_name', type=str, required=True)
        parser.add_argument('ref', type=str, required=True)
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

    @jwt_required
    def post(self, repository_id, directory_path):
        project_id = repository_id
        directory_path = directory_path + "%2F%2Egitkeep"
        parser = reqparse.RequestParser()
        parser.add_argument('branch', type=str, required=True)
        parser.add_argument('commit_message', type=str, required=True)
        args = parser.parse_args()
        logger.info("post body: {0}".format(args))
        output = pjt.create_git_project_directory(logger, app, project_id, directory_path, args)
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
        output = pjt.update_git_project_directory(logger, app, project_id, directory_path, args)
        return output.json()

    @jwt_required
    def delete(self, repository_id, directory_path):
        project_id = repository_id
        parser = reqparse.RequestParser()
        parser.add_argument('branch', type=str, required=True)
        parser.add_argument('commit_message', type=str, required=True)
        args = parser.parse_args()
        logger.info("delete body: {0}".format(args))
        output = pjt.delete_git_project_directory(logger, app, project_id, directory_path, args)
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
        output = pjt.create_git_project_mergebranch(logger, app, project_id, args)
        return output.json()


class GitProjectBranchCommmits(Resource):

    @jwt_required
    def get(self, repository_id):
        project_id = repository_id
        parser = reqparse.RequestParser()
        parser.add_argument('branch', type=str, required=True)
        args = parser.parse_args()
        logger.info("get body: {0}".format(args))
        output = pjt.get_git_project_branch_commits(logger, app, project_id, args)
        return output.json()


class GitProjectNetwork(Resource):

    @jwt_required
    def get(self, repository_id):
        project_id = repository_id
        output = pjt.get_git_project_network(logger, app, project_id)
        return output


class PipelineInfo(Resource):

    @jwt_required
    def get (self, project_id):
        output = pipe.pipeline_info(logger, project_id)
        return jsonify(output)


class PipelineExec(Resource):

    @jwt_required
    def get (self, repository_id):
        output_array = pipe.pipeline_exec_list(logger, app, repository_id)
        return jsonify({'message': 'success', 'data': output_array})


class PipelineExecLogs(Resource):

    @jwt_required
    def get (self):
        parser = reqparse.RequestParser()
        parser.add_argument('repository_id', type=int)
        parser.add_argument('pipelines_exec_run', type=int)
        args = parser.parse_args()
        output_array = pipe.pipeline_exec_logs(logger, app, args)
        return jsonify({'message': 'success', 'data': output_array})

class PipelineSoftware(Resource):

    @jwt_required
    def get (self):
        pipe_out_list = pipe.pipeline_software(logger)
        output_list =[]
        for pipe_out in pipe_out_list:
            if 'detail' in pipe_out:
                pipe_out['detail'] = json.loads(pipe_out['detail'].replace("'",'"'))
            output_list.append(pipe_out)
        return jsonify({'message': 'success', 'data': output_list})


class PipelineGenerateYaml(Resource):

    @jwt_required
    def get (self, repository_id, branch_name):
        output_array = pipe.get_ci_yaml(logger, app, repository_id, branch_name)
        return jsonify({'message': 'success', 'data': output_array})

    @jwt_required
    def post (self, repository_id, branch_name):
        parser = reqparse.RequestParser()
        parser.add_argument('detail')
        args = parser.parse_args()
        output_array = pipe.generate_ci_yaml(logger, args, app, repository_id, branch_name)


class IssuesIdList(Resource):

    @jwt_required
    def get (self, project_id):
        output_array = iss.get_issuesId_List(logger, project_id)
        return jsonify(output_array)


class IssueRD(Resource):

    @jwt_required
    def get (self, issue_id):
        return jsonify({'message': 'success', 'data': iss.get_issue_rd(logger, app, issue_id)})
    
    @jwt_required
    def put (self, issue_id):
        parser = reqparse.RequestParser()
        parser.add_argument('tracker_id', type=int)
        parser.add_argument('status_id', type=int)
        parser.add_argument('priority_id', type=int)
        parser.add_argument('description')
        parser.add_argument('parent_id', type=int)
        parser.add_argument('subject')
        parser.add_argument('start_date')
        parser.add_argument('due_date')
        parser.add_argument('done_retio', type=int)
        parser.add_argument('notes')
        args = parser.parse_args()
        output = iss.update_issue_rd(logger, app, issue_id, args)
        return jsonify({'message': 'success'})

class IssueStatus(Resource):

    @jwt_required
    def get (self):
        output = iss.get_issue_status(logger, app)
        return jsonify({'message': 'success', 'data': output})


class IssuePrioriry(Resource):

    @jwt_required
    def get (self):
        output = iss.get_issue_priority(logger, app)
        return jsonify({'message': 'success', 'data': output})

class IssueTracker(Resource):

    @jwt_required
    def get (self):
        output = iss.get_issue_trackers(logger, app)
        return jsonify({'message': 'success', 'data': output})

class IssueRDbyUser(Resource):

    @jwt_required
    def get (self, user_id):
        if int(user_id) == get_jwt_identity()['user_id']:
            output = iss.get_issue_by_user(logger, app, user_id)
            return jsonify({'message': 'success', 'data': output})
        else:
            return {'message': 'Access token is missing or invalid'}, 401


class DashboardIssuePriority(Resource):

    @jwt_required
    def get (self, user_id):
        if int(user_id) == get_jwt_identity()['user_id']:
            output = iss.count_prioriry_number_by_issues(logger, app, user_id)
            return jsonify({'message': 'success', 'data': output})
        else:
            return {'message': 'Access token is missing or invalid'}, 401


class DashboardIssueProject(Resource):

    @jwt_required
    def get (self, user_id):
        if int(user_id) == get_jwt_identity()['user_id']:
            output = iss.count_project_number_by_issues(logger, app, user_id)
            return jsonify({'message': 'success', 'data': output})
        else:
            return {'message': 'Access token is missing or invalid'}, 401


class DashboardIssueType(Resource):

    @jwt_required
    def get (self, user_id):
        if int(user_id) == get_jwt_identity()['user_id']:
            output = iss.count_type_number_by_issues(logger, app, user_id)
            return jsonify({'message': 'success', 'data': output})
        else:
            return {'message': 'Access token is missing or invalid'}, 401


api.add_resource(Index, '/')

# Redmine project
api.add_resource(RedmineProjectList , '/project/list')
api.add_resource(RedmineOneProject , '/project/<project_id>')

# Redmine issue
api.add_resource(RedmineIssue, '/redmine_issue/<issue_id>')
api.add_resource(RedmineIssue_by_user, '/redmine_issues_by_user/<user_account>')
api.add_resource(RedmineIssueStatus, '/redmine_issues_status')
api.add_resource(RedmineProject, '/redmine_project/<user_account>')

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
api.add_resource(GitProjectDirectory, '/repositories/rd/<repository_id>/directory/<directory_path>')
api.add_resource(GitProjectMergeBranch, '/repositories/rd/<repository_id>/merge_branches')
api.add_resource(GitProjectBranchCommmits, '/repositories/rd/<repository_id>/commits')
api.add_resource(GitProjectNetwork, '/repositories/<repository_id>/overview')


# Project
api.add_resource(ProjectList, '/project/rd/<user_id>')

# User
api.add_resource(UserLogin, '/user/login')
api.add_resource(UserForgetPassword, '/user/forgetPassword')
api.add_resource(UserInfo, '/user/<user_id>')
api.add_resource(User, '/user')

# pipeline
api.add_resource(PipelineExec, '/pipelines/rd/<repository_id>/pipelines_exec')
api.add_resource(PipelineExecLogs, '/pipelines/rd/logs')
api.add_resource(PipelineSoftware, '/pipelines/software')
api.add_resource(PipelineGenerateYaml, '/pipelines/<repository_id>/branch/<branch_name>/generate_ci_yaml')

# issue
api.add_resource(IssuesIdList, '/project/rd/<project_id>/issues')
api.add_resource(IssueRD, '/issues/rd/<issue_id>')
api.add_resource(IssueStatus, '/issues_status')
api.add_resource(IssuePrioriry, '/issues_priority')
api.add_resource(IssueTracker, '/issues_tracker')
api.add_resource(IssueRDbyUser, '/issues_by_user/rd/<user_id>')

# dashboard
api.add_resource(DashboardIssuePriority, '/dashboard_issues_priority/rd/<user_id>')
api.add_resource(DashboardIssueProject, '/dashboard_issues_project/<user_id>')
api.add_resource(DashboardIssueType, '/dashboard_issues_type/<user_id>')



if __name__ == "__main__":
    db.init_app(app)
    jsonwebtoken.init_app(app)
    app.run(host='0.0.0.0', port=10009)
