import datetime
import os
import traceback
from os.path import isfile

import werkzeug
from flask import Flask
from flask_cors import CORS
from flask_jwt_extended import jwt_required
from flask_restful import Resource, Api, reqparse
from sqlalchemy.orm.exc import NoResultFound
from sqlalchemy_utils import database_exists, create_database
from werkzeug.routing import IntegerConverter

import config
import migrate
import model
import resources.apiError as apiError
import resources.checkmarx as checkmarx
import resources.pipeline as pipeline
import resources.rancher as rancher
import util
import maintenance
from jsonwebtoken import jsonwebtoken
from model import db
from resources import logger, role as role, activity
from resources import project, gitlab, issue, user, redmine, wiki, version, sonarqube, apiTest, postman, mock, harbor, \
    webInspect

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
    if type(exception) is werkzeug.exceptions.NotFound:
        return util.respond(404, 'Path not found.',
                            error=apiError.path_not_found())
    if type(exception) is apiError.DevOpsError:
        traceback.print_exc()
        logger.logger.exception(str(exception))
        return util.respond(exception.status_code, exception.message, error=exception.error_value)
    traceback.print_exc()
    logger.logger.exception(str(exception))
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


class NexusVersion(Resource):
    @jwt_required
    def get(self):
        row = model.NexusVersion.query.one()
        return util.success({
            'api_version': row.api_version,
            'deploy_version': row.deploy_version
        })

    @jwt_required
    def post(self):
        role.require_admin()
        keys = ['api_version', 'deploy_version']
        parser = reqparse.RequestParser()
        for k in keys:
            parser.add_argument(k, type=str)
        args = parser.parse_args()
        row = model.NexusVersion.query.one()
        for k in keys:
            if args[k] is not None:
                setattr(row, k, args[k])
        db.session.commit()
        return util.success()


def initialize(db_uri):
    if database_exists(db_uri):
        return
    logger.logger.info('Initializing...')
    logger.logger.info(f'db_url is {db_uri}')
    if config.get('DEBUG'):
        print('Initializing...')
    # Create database
    create_database(db_uri)
    db.create_all()
    logger.logger.info('Database created.')
    # Fill alembic revision with latest
    head = None
    revs = []
    downs = []
    for fn in os.listdir('apis/alembic/versions'):
        fp = 'apis/alembic/versions/%s' % fn
        if not isfile(fp):
            continue
        with open(fp, "r") as f:
            for line in f:
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
    logger.logger.info(f'Alembic revision set to ${head}')
    # Create dummy project
    new = model.Project(id=-1, name='__dummy_project')
    db.session.add(new)
    db.session.commit()
    logger.logger.info('Project -1 created.')
    # Init admin
    args = {
        'login': config.get('ADMIN_INIT_LOGIN'),
        'email': config.get('ADMIN_INIT_EMAIL'),
        'password': config.get('ADMIN_INIT_PASSWORD'),
        'phone': '00000000000',
        'name': '初始管理者',
        'role_id': role.ADMIN.id,
        'status': 'enable'
    }
    user.create_user(args)
    logger.logger.info('Initial admin created.')
    migrate.init()
    logger.logger.info('Server initialized.')


# Projects
api.add_resource(project.ListMyProjects, '/project/list')
api.add_resource(project.SingleProject, '/project', '/project/<sint:project_id>')
api.add_resource(project.ProjectsByUser, '/projects_by_user/<int:user_id>')
api.add_resource(project.ProjectUserList, '/project/<sint:project_id>/user/list')
api.add_resource(project.ProjectUserResource, '/project/<sint:project_id>/resource')
api.add_resource(project.ProjectUserResourcePod, '/project/<sint:project_id>/resource/list/pod', 
                 '/project/<sint:project_id>/resource/list/pod/<pod_name>')
api.add_resource(project.ProjectUserResourcePodLog, 
                 '/project/<sint:project_id>/resource/list/pod/<pod_name>/log')
api.add_resource(project.ProjectUserResourceDeployment, '/project/<sint:project_id>/resource/list/deployment',
                 '/project/<sint:project_id>/resource/list/deployment/<deployment_name>')
api.add_resource(project.ProjectUserResourceService, '/project/<sint:project_id>/resource/list/service',
                 '/project/<sint:project_id>/resource/list/service/<service_name>')
api.add_resource(project.ProjectUserResourceSecret, '/project/<sint:project_id>/resource/list/secret',
                 '/project/<sint:project_id>/resource/list/secret/<secret_name>')
api.add_resource(project.ProjectUserResourceConfigMap, '/project/<sint:project_id>/resource/list/configmap',
                 '/project/<sint:project_id>/resource/list/configmap/<configmap_name>')
api.add_resource(project.ProjectUserResourceIngress, '/project/<sint:project_id>/resource/list/ingress',
                 '/project/<sint:project_id>/resource/list/ingress/<ingress_name>')
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
                 '/repositories/rd/<repository_id>/branch/<branch_name>',
                 '/repositories/<repository_id>/branch/<branch_name>')
api.add_resource(gitlab.GitProjectRepositories,
                 '/repositories/rd/<repository_id>/branch/<branch_name>/tree',
                 '/repositories/<repository_id>/branch/<branch_name>/tree')
api.add_resource(gitlab.GitProjectFile,
                 '/repositories/rd/<repository_id>/branch/files',
                 '/repositories/<repository_id>/branch/files',
                 '/repositories/rd/<repository_id>/branch/<branch_name>/files/<file_path>',
                 '/repositories<repository_id>/branch/<branch_name>/files/<file_path>')
api.add_resource(gitlab.GitProjectTag,
                 '/repositories/rd/<repository_id>/tags/<tag_name>',
                 '/repositories/<repository_id>/tags/<tag_name>',
                 '/repositories/rd/<repository_id>/tags',
                 '/repositories/<repository_id>/tags')
api.add_resource(gitlab.GitProjectBranchCommits,
                 '/repositories/rd/<repository_id>/commits',
                 '/repositories/<repository_id>/commits')
api.add_resource(gitlab.GitProjectNetwork, '/repositories/<repository_id>/overview')
api.add_resource(gitlab.GitProjectId, '/repositories/<repository_id>/id')
api.add_resource(gitlab.GitProjectIdFromURL, '/repositories/id')
api.add_resource(gitlab.GitProjectURLFromId, '/repositories/url')

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
api.add_resource(pipeline.PipelineExec, '/pipelines/rd/<repository_id>/pipelines_exec',
                 '/pipelines/<repository_id>/pipelines_exec')
api.add_resource(pipeline.PipelineExecAction, '/pipelines/<repository_id>/pipelines_exec/action')
api.add_resource(pipeline.PipelineExecLogs, '/pipelines/rd/logs',
                 '/pipelines/logs')
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
api.add_resource(issue.IssueRDbyUser, '/issues_by_user/rd/<user_id>',
                 '/issues_by_user/<user_id>')
api.add_resource(issue.MyIssueStatistics, '/issues/statistics')
api.add_resource(issue.MyOpenIssueStatistics, '/issues/open_statistics')
api.add_resource(issue.MyIssueWeekStatistics, '/issues/week_statistics')
api.add_resource(issue.MyIssueMonthStatistics, '/issues/month_statistics')

# dashboard
api.add_resource(issue.DashboardIssuePriority, '/dashboard_issues_priority/rd/<user_id>',
                 '/dashboard_issues_priority/<user_id>')
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
api.add_resource(postman.PostmanReport, '/testResults', '/postman_report/<int:id>')

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

# Sonarqube
api.add_resource(sonarqube.SonarScan, '/sonar_scan/<project_name>')
api.add_resource(sonarqube.SonarReport, '/sonar_report/<sint:project_id>')

# Files
api.add_resource(project.ProjectFile, '/project/<sint:project_id>/file')
api.add_resource(redmine.RedmineFile, '/download', '/file/<int:file_id>')

# System administrations
api.add_resource(SystemGitCommitID, '/system_git_commit_id')  # git commit

# Mocks
api.add_resource(mock.MockTestResult, '/mock/test_summary')
api.add_resource(mock.MockSesame, '/mock/sesame')

# Harbor
api.add_resource(harbor.HarborRepository,
                 '/harbor/projects/<int:nexus_project_id>',
                 '/harbor/repositories')
api.add_resource(harbor.HarborArtifact,
                 '/harbor/artifacts')
api.add_resource(harbor.HarborProject, '/harbor/projects/<int:nexus_project_id>/summary')

# WebInspect
api.add_resource(webInspect.WebInspectScan, '/webinspect/create_scan',
                 '/webinspect/list_scan/<project_name>')
api.add_resource(webInspect.WebInspectScanStatus, '/webinspect/status/<scan_id>')
api.add_resource(webInspect.WebInspectScanStatistics, '/webinspect/stats/<scan_id>')
api.add_resource(webInspect.WebInspectReport, '/webinspect/report/<scan_id>')

# Maintenance
api.add_resource(maintenance.update_db_rc_project_pipeline_id, '/maintenance/update_rc_pj_pipe_id')
api.add_resource(maintenance.secretes_into_rc_all, '/maintenance/secretes_into_rc_all', 
                 '/maintenance/secretes_into_rc_all/<secret_name>')
api.add_resource(maintenance.registry_into_rc_all, '/maintenance/registry_into_rc_all',
                 '/maintenance/registry_into_rc_all/<registry_name>')

# Raccher
api.add_resource(rancher.Catalogs, '/rancher/catalogs')

# Activity
api.add_resource(activity.AllActivities, '/all_activities')
api.add_resource(activity.ProjectActivities, '/project/<sint:project_id>/activities')

# System versions
api.add_resource(NexusVersion, '/system_versions')


if __name__ == "__main__":
    try:
        db.init_app(app)
        db.app = app
        jsonwebtoken.init_app(app)
        initialize(config.get('SQLALCHEMY_DATABASE_URI'))
        migrate.run()
        app.run(host='0.0.0.0', port=10009, debug=(config.get('DEBUG') is True))
    except Exception as e:
        ret = internal_error(e)
        if ret[1] == 404:
            logger.logger.exception(e)
        raise e
