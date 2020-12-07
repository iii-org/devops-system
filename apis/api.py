import datetime
import os
import traceback
from os.path import isfile

from flask import Flask
from flask_cors import CORS
from flask_restful import Resource, Api
from sqlalchemy.orm.exc import NoResultFound
from sqlalchemy_utils import database_exists, create_database, drop_database
from werkzeug.routing import IntegerConverter

import config
import model
import resources.apiError as apiError
import resources.checkmarx as checkmarx
import resources.pipeline as pipeline
import resources.role as role
import util
from jsonwebtoken import jsonwebtoken
from model import db
from resources import project, gitlab, issue, user, redmine, wiki, version, sonar, apiTest, postman, mock, harbor, kubernetesClient
import migrate 
from resources.logger import logger

app = Flask(__name__)
for key in ['JWT_SECRET_KEY',
            'SQLALCHEMY_DATABASE_URI',
            'SQLALCHEMY_TRACK_MODIFICATIONS',
            'WTF_CSRF_CHECK_DEFAULT',
            'JSON_AS_ASCII'
            ]:
    app.config[key] = config.get(key)

app.config['JWT_ACCESS_TOKEN_EXPIRES'] = datetime.timedelta(days=1)
api = Api(app, errors=apiError.custom_errors)
CORS(app)


class SignedIntConverter(IntegerConverter):
    regex = r'-?\d+'


app.url_map.converters['sint'] = SignedIntConverter


@app.errorhandler(Exception)
def internal_error(exception):
    if type(exception) is NoResultFound:
        return util.respond(404, 'Resource not found.',
                            error=apiError.resource_not_found())
    traceback.print_exc()
    if type(exception) is apiError.DevOpsError:
        return util.respond(exception.status_code, exception.message, error=exception.error_value)

    return util.respond(500, "Unexpected internal error",
                        error=apiError.uncaught_exception(exception))


# noinspection PyMethodMayBeStatic
class SystemGitCommitID(Resource):
    def get(self):
        if os.path.exists("git_commit"):
            with open("git_commit") as f:
                git_commit_id = f.read().splitlines()[0]
                return util.success({"git_commit_id": "{0}".format(git_commit_id)})
        else:
            raise apiError.DevOpsError(400, "git_commit file is not exist.")


def initialize(db_uri):
    if database_exists(db_uri):
        return
    logger.info('Initializing...')
    if config.get('DEBUG'):
        print('Initializing...')
    # Create database
    create_database(db_uri)
    db.create_all()
    # Fill alembic revision with latest
    head = None
    revs = []
    downs = []
    for fn in os.listdir('apis/alembic/versions'):
        fp = 'apis/alembic/versions/%s' % fn
        if not isfile(fp):
            continue
        with open(fp, "r") as f:
            o = {}
            for line in f:
                rev = 'None'
                if line.startswith('revision'):
                    revs.append(line.split('=')[1].strip()[1:-1])
                elif line.startswith('down_revision'):
                    downs.append(line.split('=')[1].strip()[1:-1])

    for rev in revs:
        is_head = True
        for down in downs:
            if down == rev:
                is_head = False
                break
        if is_head:
            head = rev
            break
    if head is not None:
        v = model.AlembicVersion(version_num=head)
        db.session.add(v)
        db.session.commit()
    # Create dummy project
    new = model.Project(id=-1, name='__dummy_project')
    db.session.add(new)
    db.session.commit()
    # Init admin
    args = {
        'login': config.get('ADMIN_INIT_LOGIN'),
        'email': config.get('ADMIN_INIT_EMAIL'),
        'password': config.get('ADMIN_INIT_PASSWORD'),
        'phone': '00000000000',
        'name': '初始管理者',
        'role_id': 5,
        'status': 'enable'
    }
    user.create_user(args)
    migrate.init()


# Projects
api.add_resource(project.ListMyProjects, '/project/list')
api.add_resource(project.SingleProject, '/project', '/project/<sint:project_id>')
api.add_resource(project.ProjectsByUser, '/projects_by_user/<int:user_id>')
api.add_resource(project.ProjectUserList, '/project/<sint:project_id>/user/list')
api.add_resource(project.ProjectMember, '/project/<sint:project_id>/member',
                 '/project/<sint:project_id>/member/<int:user_id>')
api.add_resource(wiki.ProjectWikiList, '/project/<sint:project_id>/wiki')
api.add_resource(wiki.ProjectWiki, '/project/<sint:project_id>/wiki/<wiki_name>')
api.add_resource(version.ProjectVersionList, '/project/<sint:project_id>/version/list')
api.add_resource(version.ProjectVersion, '/project/<sint:project_id>/version',
                 '/project/<sint:project_id>/version/<int:version_id>')
api.add_resource(project.TestSummary, '/project/<sint:project_id>/test_summary')

# Gitlab project
api.add_resource(gitlab.GitProjectBranches, '/repositories/<repository_id>/branches')
api.add_resource(gitlab.GitProjectBranch,
                 '/repositories/rd/<repository_id>/branch/<branch_name>')
api.add_resource(gitlab.GitProjectRepositories,
                 '/repositories/rd/<repository_id>/branch/<branch_name>/tree')
api.add_resource(gitlab.GitProjectFile,
                 '/repositories/rd/<repository_id>/branch/files',
                 '/repositories/rd/<repository_id>/branch/<branch_name>/files/<file_path>')
api.add_resource(gitlab.GitProjectTag,
                 '/repositories/rd/<repository_id>/tags/<tag_name>',
                 '/repositories/rd/<repository_id>/tags')
api.add_resource(gitlab.GitProjectBranchCommits,
                 '/repositories/rd/<repository_id>/commits')
api.add_resource(gitlab.GitProjectNetwork, '/repositories/<repository_id>/overview')
api.add_resource(gitlab.GitProjectId, '/repositories/<repository_id>/id')
api.add_resource(gitlab.GitProjectIdFromURL, '/repositories/id')

# User
api.add_resource(user.Login, '/user/login')
api.add_resource(user.UserForgetPassword, '/user/forgetPassword')
api.add_resource(user.UserStatus, '/user/<int:user_id>/status')
api.add_resource(user.SingleUser, '/user', '/user/<int:user_id>')
api.add_resource(user.UserList, '/user/list')
api.add_resource(user.UserSaConfig, '/user/<int:user_id>/config')

# Role
api.add_resource(role.RoleList, '/user/role/list')

# pipeline
api.add_resource(pipeline.PipelineExec, '/pipelines/rd/<repository_id>/pipelines_exec')
api.add_resource(pipeline.PipelineExecLogs, '/pipelines/rd/logs')
api.add_resource(pipeline.PipelineSoftware, '/pipelines/software')
api.add_resource(pipeline.PipelinePhaseYaml,
                 '/pipelines/<repository_id>/branch/<branch_name>/phase_yaml')
api.add_resource(pipeline.PipelineYaml,
                 '/pipelines/<repository_id>/branch/<branch_name>/generate_ci_yaml')

# issue
api.add_resource(issue.IssueByProject, '/project/<sint:project_id>/issues')
api.add_resource(issue.IssueByTreeByProject, '/project/<sint:project_id>/issues_by_tree')
api.add_resource(issue.IssueByStatusByProject,
                 '/project/<sint:project_id>/issues_by_status')
api.add_resource(issue.IssueByDateByProject, '/project/<sint:project_id>/issues_by_date')
api.add_resource(issue.IssuesProgressByProject,
                 '/project/<sint:project_id>/issues_progress')
api.add_resource(issue.IssuesProgressAllVersionByProject,
                 '/project/<sint:project_id>/issues_progress/all_version')
api.add_resource(issue.IssuesStatisticsByProject,
                 '/project/<sint:project_id>/issues_statistics')
api.add_resource(issue.SingleIssue, '/issues', '/issues/<issue_id>')
api.add_resource(issue.IssueStatus, '/issues_status')
api.add_resource(issue.IssuePriority, '/issues_priority')
api.add_resource(issue.IssueTracker, '/issues_tracker')
api.add_resource(issue.IssueRDbyUser, '/issues_by_user/rd/<user_id>')
api.add_resource(issue.MyIssueStatistics, '/issues/statistics')
api.add_resource(issue.MyOpenIssueStatistics, '/issues/open_statistics')
api.add_resource(issue.MyIssueWeekStatistics, '/issues/week_statistics')
api.add_resource(issue.MyIssueMonthStatistics, '/issues/month_statistics')

# dashboard
api.add_resource(issue.DashboardIssuePriority, '/dashboard_issues_priority/<user_id>')
api.add_resource(issue.DashboardIssueProject, '/dashboard_issues_project/<user_id>')
api.add_resource(issue.DashboardIssueType, '/dashboard_issues_type/<user_id>')

# testPhase Requirement
api.add_resource(issue.RequirementByIssue, '/requirements_by_issue/<issue_id>')
api.add_resource(issue.Requirement, '/requirements/<requirement_id>')

# testPhase Flow
api.add_resource(issue.FlowByIssue, '/flows_by_issue/<issue_id>')
api.add_resource(issue.GetFlowType, '/flows/support_type')
api.add_resource(issue.Flow, '/flows/<flow_id>')

# testPhase Parameters FLow
api.add_resource(issue.ParameterByIssue, '/parameters_by_issue/<issue_id>')
api.add_resource(issue.Parameter, '/parameters/<parameter_id>')
api.add_resource(issue.ParameterType, '/parameter_types')

# testPhase TestCase Support Case Type
api.add_resource(apiTest.GetTestCaseType, '/testCases/support_type')

# testPhase TestCase
api.add_resource(apiTest.TestCaseByIssue, '/testCases_by_issue/<issue_id>')
api.add_resource(apiTest.TestCaseByProject, '/testCases_by_project/<project_id>')
api.add_resource(apiTest.TestCase, '/testCases/<testCase_id>')

# testPhase TestCase Support API Method
api.add_resource(apiTest.GetTestCaseAPIMethod, '/testCases/support_RestfulAPI_Method')

# testPhase TestItem Support API Method
api.add_resource(apiTest.TestItemByTestCase, '/testItems_by_testCase/<testCase_id>')
api.add_resource(apiTest.TestItem, '/testItems/<item_id>')

# testPhase Testitem Value
api.add_resource(apiTest.GetTestValueLocation, '/testValues/support_locations')
api.add_resource(apiTest.GetTestValueType, '/testValues/support_types')
api.add_resource(apiTest.TestValueByTestItem, '/testValues_by_testItem/<item_id>')
api.add_resource(apiTest.TestValue, '/testValues/<value_id>')

# Postman tests
api.add_resource(postman.ExportToPostman, '/export_to_postman/<sint:project_id>')
api.add_resource(postman.PostmanResults, '/postman_results/<sint:project_id>')
api.add_resource(postman.PostmanReport, '/testResults', '/postman_report/<sint:project_id>')

# Checkmarx report generation
api.add_resource(checkmarx.CreateCheckmarxScan, '/checkmarx/create_scan')
api.add_resource(checkmarx.GetCheckmarxScans, '/checkmarx/scans/<sint:project_id>')
api.add_resource(checkmarx.GetCheckmarxLatestScan, '/checkmarx/latest_scan/<sint:project_id>')
api.add_resource(checkmarx.GetCheckmarxLatestScanStats,
                 '/checkmarx/latest_scan_stats/<sint:project_id>')
api.add_resource(checkmarx.GetCheckmarxLatestReport,
                 '/checkmarx/latest_report/<sint:project_id>')
api.add_resource(checkmarx.GetCheckmarxReport, '/checkmarx/report/<report_id>')
api.add_resource(checkmarx.GetCheckmarxScanStatus, '/checkmarx/scan_status/<scan_id>')
api.add_resource(checkmarx.GetCheckmarxScanStatistics, '/checkmarx/scan_stats/<scan_id>')
api.add_resource(checkmarx.RegisterCheckmarxReport, '/checkmarx/report/<scan_id>')
api.add_resource(checkmarx.GetCheckmarxReportStatus,
                 '/checkmarx/report_status/<report_id>')
api.add_resource(checkmarx.GetCheckmarxProject,
                 '/checkmarx/get_cm_project_id/<sint:project_id>')

# Get everything by issue_id
api.add_resource(issue.DumpByIssue, '/dump_by_issue/<issue_id>')

# Get Sonarqube report by project_id
api.add_resource(sonar.SonarReport, '/sonar_report/<sint:project_id>')

# Files
api.add_resource(project.ProjectFile, '/project/<sint:project_id>/file')
api.add_resource(redmine.RedmineFile, '/download', '/file/<int:file_id>')

# System administrations
api.add_resource(SystemGitCommitID, '/system_git_commit_id')  # git commit

# Mocks
api.add_resource(mock.MockTestResult, '/mock/test_summary')

# Harbor
api.add_resource(harbor.HarborRepository,
                 '/harbor/projects/<int:project_id>',
                 '/harbor/repositories',
                 '/harbor/repositories/<project_name>/<repository_name>')
api.add_resource(harbor.HarborArtifact,
                 '/harbor/artifacts/<project_name>/<repository_name>')
api.add_resource(harbor.HarborProject, '/harbor/projects/<int:project_id>/summary')


# Test api
#api.add_resource(kubernetesClient.tmp_api,
#                 '/test_create_k8s_namespace')

if __name__ == "__main__":
    db.init_app(app)
    db.app = app
    jsonwebtoken.init_app(app)
    app.app_context().push()

    u = config.get('SQLALCHEMY_DATABASE_URI')
    try:
        initialize(u)
    except Exception as e:
        drop_database(u)
        raise e
    migrate.run()
    app.run(host='0.0.0.0', port=10009, debug=(config.get('DEBUG') is True))
