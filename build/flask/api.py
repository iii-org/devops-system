from flask import Flask
from flask import Response
from flask import jsonify
from flask import request as flask_req
from flask_restful import Resource, Api, reqparse
import logging
from logging import handlers
import json

import resources.util as util
import resources.auth as auth
import resources.issue as issue
import resources.project as project

app = Flask(__name__)
app.config.from_object('config')
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

headers = {
    'Content-Type': 'application/json',
    'Authorization': 'Bearer {0}'.format(au.get_token(logger))
}


class Index(Resource):

    def get(self):
        return {"message": "DevOps api is working"}

class Issue_by_user(Resource):

    def get(self, user_account):
        output = iss.get_issues_by_user(logger, app, user_account)
        return {"issue_number": output.json()}


class Issue(Resource):

    def get(self, issue_id):
        output = iss.get_issue(logger, app, issue_id)

    def put(self, issue_id):
        parser = reqparse.RequestParser()
        parser.add_argument('status_id', type=int)
        parser.add_argument('done_ratio', type=int)
        parser.add_argument('notes')
        args = parser.parse_args()
        logger.info("put body: {0}".format(args))
        output = iss.update_issue(logger, app, issue_id, args)


class IssueStatus(Resource):

    def get (self):
        output = iss.get_issue_status(logger, app)
        return output.json()


class ProjectNumber(Resource):

    def get(self, user_account):
        output = iss.get_project(logger, app, user_account)
        return {"project_number": output.json()["user"]["memberships"]}


class GitProject(Resource):
    
    def get (self):
        output = pjt.get_all_git_project(logger, app)
        return output.json()


class GitRepository(Resource):

    def get(self):
        url = "https://10.50.1.55/v3/projects/c-7bl58:p-wxgdj/sourcecoderepositories"

        output = ut.callgetapi(url, logger, headers)
        return output.json()['data']


class Pipelines(Resource):
    
    def get(self):
        url = "https://10.50.1.55/v3/projects/c-7bl58:p-wxgdj/pipelines"
        # get hook project list
        output = ut.callgetapi(url, logger, headers)
        return output.json()['data']
    
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
    
    def delete(self, pipelineid):
        url = "https://10.50.1.55/v3/projects/c-7bl58:p-wxgdj/pipelines/{0}".format(pipelineid)
        output = ut.calldeleteapi(url, logger, headers)
        return "Successful"
    
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

    def get(self, pipelineid):
        url = "https://10.50.1.55/v3/projects/c-7bl58:p-wxgdj/pipelines/{0}/branches".format(pipelineid)
        output = ut.callgetapi(url, logger, headers)
        return output.json()

class PipelineExecutions(Resource):

    def get(self):
        url = "https://10.50.1.55/v3/projects/c-7bl58:p-wxgdj/pipelineexecutions?order=desc"

        output = ut.callgetapi(url, logger, headers)
        return output.json()['data']


class PipelineExecutionsOne(Resource):

    def get(self, pipelineexecutionsid):
        url = "https://10.50.1.55/v3/projects/c-7bl58:p-wxgdj/pipelineexecutions/{0}".format(pipelineexecutionsid)

        output = ut.callgetapi(url, logger, headers)
        return output.json()['stages']


class GitOneProject(Resource):

    def get(self, project_id):
        output = pjt.get_one_git_project(logger, app, project_id)
        return output.json()

    def put(self, project_id):
        parser = reqparse.RequestParser()
        parser.add_argument('name', type=str)
        parser.add_argument('visibility', type=str)
        args = parser.parse_args()
        logger.info("put body: {0}".format(args))
        output = pjt.update_project(logger, app, project_id, args)
        

api.add_resource(Index, '/')
api.add_resource(Issue, '/issue/<issue_id>')
api.add_resource(Issue_by_user, '/issues_by_user/<user_account>')
api.add_resource(IssueStatus, '/issues_status')
api.add_resource(ProjectNumber, '/project/<user_account>')
api.add_resource(GitProject, '/git_project')
api.add_resource(GitRepository, '/gitrepository')
api.add_resource(Pipelines, '/pipelines')
api.add_resource(PipelineID, '/pipelines/<pipelineid>')
api.add_resource(Get_pipeline_branchs, '/pipelines/<pipelineid>/branches')
api.add_resource(PipelineExecutions, '/pipelineexecutions')
api.add_resource(PipelineExecutionsOne, '/pipelineexecutions/<pipelineexecutionsid>')

api.add_resource(GitOneProject, '/git_one_project/<project_id>')

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=10009)
