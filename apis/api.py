import os
import sys
import threading

if f"{os.getcwd()}/apis" not in sys.path:
    sys.path.insert(1, f"{os.getcwd()}/apis")

import traceback
from os.path import isfile

import werkzeug
from flask import Flask
from flask_cors import CORS
from flask_jwt_extended import jwt_required
from flask_restful import Resource, Api, reqparse
from flask_socketio import SocketIO
from sqlalchemy.orm.exc import NoResultFound
from sqlalchemy_utils import database_exists, create_database
from werkzeug.routing import IntegerConverter

import plugins
from plugins import sideex, postman
import config
import migrate
import model
import system
import resources.apiError as apiError
import resources.pipeline as pipeline
import resources.rancher as rancher
import util
import routing_job
from jsonwebtoken import jsonwebtoken
from model import db
from resources import logger, role as role, activity, starred_project, devops_version, cicd
from resources import project, gitlab, issue, user, redmine, wiki, version, apiTest, mock, harbor, \
    template, release, sync_redmine, plugin, kubernetesClient, project_permission, quality, sync_project, \
    sync_user, router, deploy, alert, trace_order, tag, monitoring, lock, system_parameter, alert_message, \
    maintenance, issue_display_field, notification_message, project_relation
from apispec import APISpec
from flask_apispec.extension import FlaskApiSpec
from apispec.ext.marshmallow import MarshmallowPlugin


app = Flask(__name__)
for key in ['JWT_SECRET_KEY',
            'SQLALCHEMY_DATABASE_URI',
            'SQLALCHEMY_TRACK_MODIFICATIONS',
            'WTF_CSRF_CHECK_DEFAULT',
            'JSON_AS_ASCII'
            ]:
    app.config[key] = config.get(key)

# setting swagger config
app.config.update({
    'APISPEC_SPEC': APISpec(
        title='Devops API Project',
        version='v1',
        plugins=[MarshmallowPlugin()],
        openapi_version='2.0.0'
    ),
    'APISPEC_SWAGGER_URL': '/swagger/',  # URI to access API Doc JSON
    'APISPEC_SWAGGER_UI_URL': '/swagger-ui/'  # URI to access UI of API Doc
})
docs = FlaskApiSpec(app)


def add_resource(classes, level):
    if config.get("DOCUMENT_LEVEL") == "public":
        if level in ['public']:
            docs.register(classes)
    elif config.get("DOCUMENT_LEVEL") == "private":
        if level in ['public', 'private']:
            docs.register(classes)


app.config['PROPAGATE_EXCEPTIONS'] = True
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    "pool_pre_ping": True,
    "pool_recycle": 60,
    'pool_timeout': 300
}

api = Api(app, errors=apiError.custom_errors)
CORS(app)
socketio = SocketIO(app, message_queue='redis://devops-redis-service:6379', cors_allowed_origins="*",
                    logger=True, engineio_logger=True, timeout=60000)


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
    my_uuid = devops_version.set_deployment_uuid()
    logger.logger.info(f'Deployment UUID set as {my_uuid}.')
    migrate.init()
    logger.logger.info('Server initialized.')


api.add_resource(router.Router, '/router')
api.add_resource(router.RouterNameV2, '/v2/router/name')
add_resource(router.RouterNameV2, "public")
api.add_resource(router.UserRouteV2, '/v2/router/user_route')
add_resource(router.UserRouteV2, "public")

api.add_resource(project.GitRepoIdToCiPipeId,
                 '/git_repo_id_to_ci_pipe_id/<repository_id>')

# Projects
api.add_resource(project.ListMyProjects, '/project/list')
api.add_resource(project.CaculateProjectIssues, '/project/list/caculate')
api.add_resource(project.ListProjectsByUser, '/projects_by_user/<int:user_id>')
api.add_resource(project.SingleProject, '/project',
                 '/project/<sint:project_id>')
api.add_resource(project.SingleProjectByName,
                 '/project_by_name/<project_name>')
api.add_resource(project.ProjectUserList,
                 '/project/<sint:project_id>/user/list')
api.add_resource(project.ProjectPluginPod,
                 '/project/<sint:project_id>/plugin')
api.add_resource(project.ProjectPluginUsage,
                 '/project/<sint:project_id>/plugin/resource')
api.add_resource(project.ProjectUserResource,
                 '/project/<sint:project_id>/resource')

api.add_resource(project.ProjectUserResourcePods,
                 '/project/<sint:project_id>/resource/pods')
api.add_resource(project.ProjectUserResourcePod,
                 '/project/<sint:project_id>/resource/pods/<pod_name>')
api.add_resource(project.ProjectUserResourcePodLog,
                 '/project/<sint:project_id>/resource/pods/<pod_name>/log')

api.add_resource(starred_project.StarredProject,
                 '/project/<sint:project_id>/star')

api.add_resource(issue.DownloadProject,
                 '/project/<sint:project_id>/download/execute',
                 '/project/<sint:project_id>/download/is_exist',
                 '/project/<sint:project_id>/download')


api.add_resource(gitlab.SyncGitCommitIssueRelationByPjName,
                 '/project/issues_commit_by_name',
                 )
api.add_resource(pipeline.PipelineFile, '/project/<string:project_name>/pipeline_file')


# Project son relation
api.add_resource(gitlab.SyncGitCommitIssueRelation,
                 '/project/<sint:project_id>/issues_commit',
                 '/project/<sint:project_id>/issues_commit/<issue_id>',
                 )
api.add_resource(gitlab.GetCommitIssueHookByBranch, '/project/<sint:project_id>/issues_commit/by_branch')
api.add_resource(project.ProjectRelation, '/project/<sint:project_id>/relation')
api.add_resource(issue.IssueCommitRelation, '/issue/relation')
api.add_resource(project_relation.CheckhasSonProject, '/project/<sint:project_id>/has_son')
api.add_resource(project_relation.CheckhasSonProjectV2, '/v2/project/<sint:project_id>/has_son')
add_resource(project_relation.CheckhasSonProjectV2, "public")
api.add_resource(project_relation.GetProjectRootID, '/project/<sint:project_id>/root_project')
api.add_resource(project_relation.GetProjectRootIDV2, '/v2/project/<sint:project_id>/root_project')
add_resource(project_relation.GetProjectRootIDV2, "public")
api.add_resource(project_relation.SyncProjectRelation, '/project/sync_project_relation')
api.add_resource(project_relation.SyncProjectRelationV2, '/v2/project/sync_project_relation')
add_resource(project_relation.SyncProjectRelationV2, "public")
api.add_resource(project_relation.GetProjectFamilymembersByUser, '/project/<sint:project_id>/members')
api.add_resource(project_relation.GetProjectFamilymembersByUserV2, '/v2/project/<sint:project_id>/members')
add_resource(project_relation.GetProjectFamilymembersByUserV2, "public")

# Tag
api.add_resource(tag.Tags, '/tags')
api.add_resource(tag.Tag, '/tags/<int:tag_id>')
api.add_resource(tag.UserTags, '/user/tags')


# k8s Deployment
api.add_resource(project.ProjectUserResourceDeployments,
                 '/project/<sint:project_id>/resource/deployments')
api.add_resource(project.ProjectUserResourceDeployment,
                 '/project/<sint:project_id>/resource/deployments/<deployment_name>')

# List k8s Services
api.add_resource(project.ProjectUserResourceServices,
                 '/project/<sint:project_id>/resource/services')
api.add_resource(project.ProjectUserResourceService,
                 '/project/<sint:project_id>/resource/services/<service_name>')

# k8s Secrets
api.add_resource(project.ProjectUserResourceSecrets,
                 '/project/<sint:project_id>/resource/secrets')
api.add_resource(project.ProjectUserResourceSecret,
                 '/project/<sint:project_id>/resource/secrets/<secret_name>')

# k8s ConfigMaps
api.add_resource(project.ProjectUserResourceConfigMaps,
                 '/project/<sint:project_id>/resource/configmaps')
api.add_resource(project.ProjectUserResourceConfigMap,
                 '/project/<sint:project_id>/resource/configmaps/<configmap_name>')

# k8s Ingress
api.add_resource(project.ProjectUserResourceIngresses,
                 '/project/<sint:project_id>/resource/ingresses')

api.add_resource(project.ProjectMember, '/project/<sint:project_id>/member',
                 '/project/<sint:project_id>/member/<int:user_id>')
api.add_resource(wiki.ProjectWikiList, '/project/<sint:project_id>/wiki')
api.add_resource(wiki.ProjectWiki,
                 '/project/<sint:project_id>/wiki/<wiki_name>')
api.add_resource(version.ProjectVersionList,
                 '/project/<sint:project_id>/version/list')
api.add_resource(version.ProjectVersion, '/project/<sint:project_id>/version',
                 '/project/<sint:project_id>/version/<int:version_id>')
api.add_resource(template.TemplateList, '/template_list')
api.add_resource(template.TemplateListForCronJob, '/template_list_for_cronjob')
api.add_resource(template.SingleTemplate, '/template',
                 '/template/<repository_id>')
api.add_resource(template.ProjectPipelineBranches,
                 '/project/<repository_id>/pipeline/branches')
api.add_resource(template.ProjectPipelineDefaultBranch,
                 '/project/<repository_id>/pipeline/default_branch')
api.add_resource(project.ProjectEnvironment, '/project/<sint:project_id>/environments',
                 '/project/<sint:project_id>/environments/branch/<branch_name>')
api.add_resource(project.ProjectEnvironmentUrl,
                 '/project/<sint:project_id>/environments/branch/<branch_name>/urls')

# Gitlab project
api.add_resource(gitlab.GitProjectBranches,
                 '/repositories/<repository_id>/branches')
api.add_resource(gitlab.GitProjectBranch,
                 '/repositories/<repository_id>/branch/<branch_name>')
api.add_resource(gitlab.GitProjectRepositories,
                 '/repositories/<repository_id>/branch/<branch_name>/tree')
api.add_resource(gitlab.GitProjectFile,
                 '/repositories/<repository_id>/branch/files',
                 '/repositories/<repository_id>/branch/<branch_name>/files/<file_path>')
api.add_resource(gitlab.GitProjectTag,
                 '/repositories/<repository_id>/tags/<tag_name>',
                 '/repositories/<repository_id>/tags')
api.add_resource(gitlab.GitProjectBranchCommits,
                 '/repositories/<repository_id>/commits')
api.add_resource(gitlab.GitProjectMembersCommits,
                 '/repositories/<repository_id>/members_commits')
api.add_resource(gitlab.GitProjectNetwork,
                 '/repositories/<repository_id>/overview')
api.add_resource(gitlab.GitProjectId, '/repositories/<repository_id>/id')
api.add_resource(gitlab.GitProjectIdFromURL, '/repositories/id')
api.add_resource(gitlab.GitProjectURLFromId, '/repositories/url')
api.add_resource(gitlab.GitlabDomainConnection, '/repositories/is_ip', '/repositories/connection')


# User
api.add_resource(user.Login, '/user/login')
# input api in swagger (for swagger)
api.add_resource(user.LoginV2, '/v2/user/login')
add_resource(user.LoginV2, "public")


# api.add_resource(user.UserForgetPassword, '/user/forgetPassword')
api.add_resource(user.UserStatus, '/user/<int:user_id>/status')
api.add_resource(user.SingleUser, '/user', '/user/<int:user_id>')
api.add_resource(user.UserList, '/user/list')
api.add_resource(user.UserSaConfig, '/user/<int:user_id>/config')

# Role
api.add_resource(role.RoleList, '/user/role/list')

# pipeline
api.add_resource(pipeline.Pipeline,
                 '/pipelines/<repository_id>/pipelines')
api.add_resource(pipeline.PipelineExec,
                 '/pipelines/<repository_id>/pipelines_exec')
api.add_resource(pipeline.PipelineConfig,
                 '/pipelines/<repository_id>/config')
api.add_resource(pipeline.PipelineExecAction,
                 '/pipelines/<repository_id>/pipelines_exec/action')
api.add_resource(pipeline.PipelineExecLogs, '/pipelines/logs')
api.add_resource(pipeline.PipelinePhaseYaml,
                 '/pipelines/<repository_id>/branch/<branch_name>/phase_yaml')
api.add_resource(pipeline.PipelineYaml,
                 '/pipelines/<repository_id>/branch/<branch_name>/generate_ci_yaml')

# Websocket
socketio.on_namespace(rancher.RancherWebsocketLog('/rancher/websocket/logs'))
socketio.on_namespace(system_parameter.SyncTemplateWebsocketLog('/sync_template/websocket/logs'))
socketio.on_namespace(
    kubernetesClient.KubernetesPodExec('/k8s/websocket/pod_exec'))
socketio.on_namespace(issue.IssueSocket('/issues/websocket'))

# issue
api.add_resource(issue.IssueFamily, '/issue/<issue_id>/family')
api.add_resource(issue.IssueFamilyV2, '/v2/issue/<issue_id>/family')
add_resource(issue.IssueFamilyV2, 'public')
api.add_resource(issue.IssueByProject, '/project/<sint:project_id>/issues')
api.add_resource(issue.IssueByProjectV2, '/v2/project/<sint:project_id>/issues')
add_resource(issue.IssueByProjectV2, 'public')
api.add_resource(issue.IssueByUser, '/user/<sint:user_id>/issues')
api.add_resource(issue.IssueByUserV2, '/v2/user/<sint:user_id>/issues')
add_resource(issue.IssueByUserV2, 'public')

api.add_resource(issue.IssueByTreeByProject,
                 '/project/<sint:project_id>/issues_by_tree')
api.add_resource(issue.IssueByTreeByProjectV2,
                 '/v2/project/<sint:project_id>/issues_by_tree')
add_resource(issue.IssueByTreeByProjectV2, "public")
api.add_resource(issue.IssueByStatusByProject,
                 '/project/<sint:project_id>/issues_by_status')
api.add_resource(issue.IssueByStatusByProjectV2,
                 '/v2/project/<sint:project_id>/issues_by_status')
add_resource(issue.IssueByStatusByProjectV2, "public")                
# api.add_resource(issue.IssueByDateByProject,
#                  '/project/<sint:project_id>/issues_by_date')
api.add_resource(issue.IssuesProgressByProject,
                 '/project/<sint:project_id>/issues_progress')
api.add_resource(issue.IssuesProgressByProjectV2,
                 '/v2/project/<sint:project_id>/issues_progress')
add_resource(issue.IssuesProgressByProjectV2, "public")
api.add_resource(issue.IssuesStatisticsByProject,
                 '/project/<sint:project_id>/issues_statistics')
api.add_resource(issue.IssueFilterByProject, '/project/<sint:project_id>/issue_filter',
                 '/project/<sint:project_id>/issue_filter/<custom_filter_id>')


# api.add_resource(issue.IssueByVersion, '/issues_by_versions')
api.add_resource(issue.SingleIssue, '/issues', '/issues/<issue_id>')
api.add_resource(issue.SingleIssueV2, '/v2/issues/<issue_id>')
add_resource(issue.SingleIssueV2, "public")
api.add_resource(issue.CreateSingleIssueV2, '/v2/issues')
add_resource(issue.CreateSingleIssueV2, "public")
api.add_resource(issue.IssueStatus, '/issues_status')
api.add_resource(issue.IssueStatusV2, '/v2/issues_status')
add_resource(issue.IssueStatusV2, "public")
api.add_resource(issue.IssuePriority, '/issues_priority')
api.add_resource(issue.IssuePriorityV2, '/v2/issues_priority')
add_resource(issue.IssuePriorityV2, 'public')
api.add_resource(issue.IssueTracker, '/issues_tracker')
api.add_resource(issue.IssueTrackerV2, '/v2/issues_tracker')
add_resource(issue.IssueTrackerV2, 'public')
api.add_resource(issue.MyIssueStatistics, '/issues/statistics')
api.add_resource(issue.MyOpenIssueStatistics, '/issues/open_statistics')
api.add_resource(issue.MyIssueWeekStatistics, '/issues/week_statistics')
api.add_resource(issue.MyIssueMonthStatistics, '/issues/month_statistics')
api.add_resource(issue.Relation, '/issues/relation',
                 '/issues/relation/<int:relation_id>')
api.add_resource(issue.CheckIssueClosable, '/issues/<issue_id>/check_closable')


# Issue Field Display
api.add_resource(issue_display_field.IssueFieldDisplay, '/issue_field_display')

# Release
api.add_resource(release.Releases, '/project/<project_id>/releases')
api.add_resource(
    release.Release, '/project/<project_id>/releases/<release_name>')

# Plugins
api.add_resource(plugin.Plugins, '/plugins')
api.add_resource(plugin.Plugin, '/plugins/<plugin_name>')

# dashboard
api.add_resource(issue.DashboardIssuePriority,
                 '/dashboard_issues_priority/<user_id>')
api.add_resource(issue.DashboardIssueProject,
                 '/dashboard_issues_project/<user_id>')
api.add_resource(issue.DashboardIssueType, '/dashboard_issues_type/<user_id>')
api.add_resource(gitlab.GitTheLastHoursCommits,
                 '/dashboard/the_last_hours_commits')
api.add_resource(sync_redmine.ProjectMembersCount,
                 '/dashboard/project_members_count')
api.add_resource(sync_redmine.ProjectMembersDetail,
                 '/dashboard/project_members_detail')
api.add_resource(sync_redmine.ProjectMembers,
                 '/dashboard/<project_id>/project_members')
api.add_resource(sync_redmine.ProjectOverview, '/dashboard/project_overview')
api.add_resource(sync_redmine.RedmineProjects, '/dashboard/redmine_projects')
api.add_resource(sync_redmine.RedminProjectDetail,
                 '/dashboard/redmine_projects_detail')
api.add_resource(sync_redmine.RedmineIssueRank, '/dashboard/issue_rank')
api.add_resource(sync_redmine.UnclosedIssues,
                 '/dashboard/<user_id>/unclosed_issues')
api.add_resource(sync_redmine.PassingRate, '/dashboard/passing_rate')
api.add_resource(sync_redmine.PassingRateDetail,
                 '/dashboard/passing_rate_detail')

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
api.add_resource(apiTest.TestCases, '/test_cases')
api.add_resource(apiTest.TestCase, '/test_cases/<sint:tc_id>',
                 '/testCases/<sint:tc_id>')

api.add_resource(apiTest.GetTestCaseType, '/testCases/support_type')

# testPhase TestCase
api.add_resource(apiTest.TestCaseByIssue, '/testCases_by_issue/<issue_id>')
api.add_resource(apiTest.TestCaseByProject,
                 '/testCases_by_project/<project_id>')
# api.add_resource(apiTest.TestCase, '/testCases/<sint:tc_id>')

# testPhase TestCase Support API Method
api.add_resource(apiTest.GetTestCaseAPIMethod,
                 '/testCases/support_RestfulAPI_Method')

# testPhase TestItem Support API Method
api.add_resource(apiTest.TestItemByTestCase, '/testItems_by_testCase/<tc_id>')
api.add_resource(apiTest.TestItem, '/testItems/<item_id>')

# testPhase Testitem Value
api.add_resource(apiTest.GetTestValueLocation, '/testValues/support_locations')
api.add_resource(apiTest.GetTestValueType, '/testValues/support_types')
api.add_resource(apiTest.TestValueByTestItem,
                 '/testValues_by_testItem/<item_id>')
api.add_resource(apiTest.TestValue, '/testValues/<value_id>')

# Integrated test results
api.add_resource(project.TestSummary,
                 '/project/<sint:project_id>/test_summary')
api.add_resource(project.AllReports,
                 '/project/<sint:project_id>/test_reports')
api.add_resource(cicd.CommitCicdSummary,
                 '/project/<sint:project_id>/test_summary/<commit_id>')


# Get everything by issue_id
api.add_resource(issue.DumpByIssue, '/dump_by_issue/<issue_id>')


# Files
api.add_resource(project.ProjectFile, '/project/<sint:project_id>/file')
api.add_resource(redmine.RedmineFile, '/download', '/file/<int:file_id>')

api.add_resource(redmine.RedmineMail, '/mail')

# System administrations
api.add_resource(system.SystemGitCommitID,
                 '/system_git_commit_id')  # git commit
api.add_resource(system.SystemInfoReport, '/system_info_report')

# Mocks
# api.add_resource(mock.MockTestResult, '/mock/test_summary')
# api.add_resource(mock.MockSesame, '/mock/sesame')
# api.add_resource(mock.UserDefaultFromAd, '/mock/userdefaultad')

# Harbor
api.add_resource(harbor.HarborRepository,
                 '/harbor/projects/<int:nexus_project_id>',
                 '/harbor/repositories')
api.add_resource(harbor.HarborArtifact,
                 '/harbor/artifacts')
api.add_resource(harbor.HarborProject,
                 '/harbor/projects/<int:nexus_project_id>/summary')
api.add_resource(harbor.HarborRegistries, '/harbor/registries')
api.add_resource(harbor.HarborRegistry,
                 '/harbor/registries/<sint:registry_id>')
api.add_resource(harbor.HarborReplicationPolices,
                 '/harbor/replication/policies')
api.add_resource(harbor.HarborReplicationPolicy,
                 '/harbor/replication/policies/<sint:replication_policy_id>')
api.add_resource(harbor.HarborReplicationExecution,
                 '/harbor/replication/executions')
api.add_resource(harbor.HarborReplicationExecutionTasks,
                 '/harbor/replication/executions/<sint:execution_id>/tasks')
api.add_resource(harbor.HarborReplicationExecutionTaskLog,
                 '/harbor/replication/executions/<sint:execution_id>/tasks/<sint:task_id>/log')
api.add_resource(harbor.HarborCopyImageRetage, '/harbor/handle_image')

# Maintenance
api.add_resource(maintenance.UpdateDbRcProjectPipelineId,
                 '/maintenance/update_rc_pj_pipe_id')
api.add_resource(maintenance.SecretesIntoRcAll, '/maintenance/secretes_into_rc_all',
                 '/maintenance/secretes_into_rc_all/<secret_name>')
api.add_resource(maintenance.RegistryIntoRcAll, '/maintenance/registry_into_rc_all',
                 '/maintenance/registry_into_rc_all/<registry_name>')
api.add_resource(maintenance.UpdatePjHttpUrl,
                 '/maintenance/update_pj_http_url')

# Rancher
api.add_resource(rancher.Catalogs, '/rancher/catalogs',
                 '/rancher/catalogs/<catalog_name>')
api.add_resource(rancher.Catalogs_Refresh, '/rancher/catalogs_refresh')
api.add_resource(rancher.RancherDeleteAPP, '/rancher/delete_app')

# Activity
api.add_resource(activity.AllActivities, '/all_activities')
api.add_resource(activity.ProjectActivities,
                 '/project/<sint:project_id>/activities')


# Sync Redmine, Gitlab, Rancher
api.add_resource(sync_redmine.SyncRedmine, '/sync_redmine')
api.add_resource(sync_redmine.SyncRedmineNow, '/sync_redmine/now')
api.add_resource(gitlab.GitCountEachPjCommitsByDays,
                 '/sync_gitlab/count_each_pj_commits_by_days')
api.add_resource(rancher.RancherCountEachPjPiplinesByDays,
                 '/sync_rancher/count_each_pj_piplines_by_days')
api.add_resource(issue.ExecutIssueAlert, '/sync_issue_alert')

# Subadmin Projects Permission
api.add_resource(project_permission.AdminProjects,
                 '/project_permission/admin_projects')
api.add_resource(project_permission.SubadminProjects,
                 '/project_permission/subadmin_projects')
api.add_resource(project_permission.Subadmins, '/project_permission/subadmins')
api.add_resource(project_permission.SetPermission,
                 '/project_permission/set_permission')

# Quality
api.add_resource(quality.TestPlanList,
                 '/quality/<int:project_id>/testplan_list')
# api.add_resource(quality.TestPlan,
#                  '/quality/<int:project_id>/testplan/<int:testplan_id>')
api.add_resource(quality.TestFileByTestPlan,
                 '/quality/<int:project_id>/testfile_by_testplan/<int:testplan_id>')
api.add_resource(quality.TestFileList,
                 '/quality/<int:project_id>/testfile_list')
api.add_resource(quality.TestFile, '/quality/<int:project_id>/testfile/<software_name>',
                 '/quality/<int:project_id>/testfile/<software_name>/<test_file_name>')
api.add_resource(quality.TestPlanWithTestFile, '/quality/<int:project_id>/testplan_with_testfile',
                 '/quality/<int:project_id>/testplan_with_testfile/<int:item_id>')
api.add_resource(quality.Report, '/quality/<int:project_id>/report')

# System versions
api.add_resource(NexusVersion, '/system_versions')

# Sync Projects
api.add_resource(sync_project.SyncProject, '/sync_projects')

# Sync Users
api.add_resource(sync_user.SyncUser, '/sync_users')

# Centralized version check
api.add_resource(devops_version.DevOpsVersion, '/devops_version')
api.add_resource(devops_version.DevOpsVersionCheck, '/devops_version/check')
api.add_resource(devops_version.DevOpsVersionUpdate, '/devops_version/update')

# Deploy
api.add_resource(deploy.Clusters, '/deploy/clusters')
api.add_resource(deploy.Cluster, '/deploy/clusters/<int:cluster_id>')
api.add_resource(deploy.Registries, '/deploy/registries')
api.add_resource(deploy.Registry, '/deploy/registries/<int:registry_id>')

api.add_resource(deploy.ReleaseApplication,
                 '/deploy/release/<int:release_id>')

api.add_resource(deploy.Applications, '/deploy/applications')
api.add_resource(deploy.Application,
                 '/deploy/applications/<int:application_id>')

api.add_resource(deploy.RedeployApplication, '/deploy/applications/<int:application_id>/redeploy')

api.add_resource(deploy.UpdateApplication,
                 '/deploy/applications/<int:application_id>/update')

api.add_resource(deploy.Cronjob, '/deploy/applications/cronjob')
# Alert
api.add_resource(alert.ProjectAlert, '/project/<sint:project_id>/alert')
api.add_resource(alert.ProjectAlertUpdate, '/alert/<int:alert_id>')
api.add_resource(alert.DefaultAlertDaysUpdate, '/alert/default_days')

# Trace Order
api.add_resource(trace_order.TraceOrders, '/trace_order')
api.add_resource(trace_order.SingleTraceOrder, '/trace_order/<sint:trace_order_id>')
api.add_resource(trace_order.ExecuteTraceOrder, '/trace_order/execute')
api.add_resource(trace_order.GetTraceResult, '/trace_order/result')

# Monitoring
api.add_resource(monitoring.ServersAlive, '/monitoring/alive')
api.add_resource(monitoring.ServersAliveV2, '/v2/monitoring/alive')
add_resource(monitoring.ServersAliveV2, "public")
api.add_resource(monitoring.RedmineAlive, '/monitoring/redmine/alive')
api.add_resource(monitoring.RedmineAliveV2, '/v2/monitoring/redmine/alive')
add_resource(monitoring.RedmineAliveV2, "public")
api.add_resource(monitoring.GitlabAlive, '/monitoring/gitlab/alive')
api.add_resource(monitoring.GitlabAliveV2, '/v2/monitoring/gitlab/alive')
add_resource(monitoring.GitlabAliveV2, "public")
api.add_resource(monitoring.HarborAlive, '/monitoring/harbor/alive')
api.add_resource(monitoring.HarborAliveV2, '/v2/monitoring/harbor/alive')
add_resource(monitoring.HarborAliveV2, "public")
api.add_resource(monitoring.HarborStorage, '/monitoring/harbor/usage')
api.add_resource(monitoring.HarborStorageV2, '/v2/monitoring/harbor/usage')
add_resource(monitoring.HarborStorageV2, "public")
api.add_resource(monitoring.HarborProxy, '/monitoring/harbor/pull_limit')
api.add_resource(monitoring.HarborProxyV2, '/v2/monitoring/harbor/pull_limit')
add_resource(monitoring.HarborProxyV2, "public")
api.add_resource(monitoring.SonarQubeAlive, '/monitoring/sonarqube/alive')
api.add_resource(monitoring.SonarQubeAliveV2, '/v2/monitoring/sonarqube/alive')
add_resource(monitoring.SonarQubeAliveV2, "public")
api.add_resource(monitoring.RancherAlive, '/monitoring/rancher/alive')
api.add_resource(monitoring.RancherAliveV2, '/v2/monitoring/rancher/alive')
add_resource(monitoring.RancherAliveV2, "public")
api.add_resource(monitoring.RancherDefaultName, '/monitoring/rancher/default_name')
api.add_resource(monitoring.RancherDefaultNameV2, '/v2/monitoring/rancher/default_name')
add_resource(monitoring.RancherDefaultNameV2, "public")
api.add_resource(monitoring.K8sAlive, '/monitoring/k8s/alive')
api.add_resource(monitoring.K8sAliveV2, '/v2/monitoring/k8s/alive')
add_resource(monitoring.K8sAliveV2, "public")
api.add_resource(monitoring.CollectPodRestartTime, '/monitoring/k8s/collect_pod_restart_times_by_hour')
api.add_resource(monitoring.CollectPodRestartTimeV2, '/v2/monitoring/k8s/collect_pod_restart_times_by_hour')
add_resource(monitoring.CollectPodRestartTimeV2, "public")
api.add_resource(monitoring.PodAlert, '/monitoring/k8s/pod_alert')
api.add_resource(monitoring.PodAlertV2, '/v2/monitoring/k8s/pod_alert')
add_resource(monitoring.PodAlertV2, "private")
api.add_resource(monitoring.RemoveExtraExecutions, '/monitoring/k8s/remove_extra_executions')
api.add_resource(monitoring.RemoveExtraExecutionsV2, '/v2/monitoring/k8s/remove_extra_executions')
add_resource(monitoring.RemoveExtraExecutionsV2, "public")
api.add_resource(monitoring.GithubTokenVerify, '/monitoring/github/validate_token')
api.add_resource(monitoring.GithubTokenVerifyV2, '/v2/monitoring/github/validate_token')
add_resource(monitoring.GithubTokenVerifyV2, "public")


# System parameter
api.add_resource(system_parameter.SystemParameters, '/system_parameter', '/system_parameter/<int:param_id>')
api.add_resource(system_parameter.ParameterGithubVerifyExecuteStatus, '/system_parameter/github_verify/status')

# Status of Sync
api.add_resource(lock.LockStatus, '/lock')

# Alert message
api.add_resource(alert_message.AlertMessages, '/alert_message')

# message
api.add_resource(notification_message.MessageList, '/notification_message_list')
api.add_resource(notification_message.Message, '/notification_message', '/notification_message/<int:message_id>')
api.add_resource(notification_message.MessageReply, '/notification_message_reply/<int:user_id>')
socketio.on_namespace(notification_message.GetNotificationMessage('/get_notification_message'))

# routing job
api.add_resource(routing_job.DoJobByMonth, '/routing_job/by_month')


def start_prod():
    try:
        db.init_app(app)
        db.app = app
        jsonwebtoken.init_app(app)
        initialize(config.get('SQLALCHEMY_DATABASE_URI'))
        migrate.run()
        kubernetesClient.create_iiidevops_env_secret_namespace()
        threading.Thread(target=kubernetesClient.apply_cronjob_yamls).start()
        logger.logger.info('Apply k8s-yaml cronjob.')
        template.tm_get_template_list()
        logger.logger.info('Get the public and local template list')
        plugins.create_plugins_api_router(api)
        plugins.sync_plugins_in_db_and_code()
        with app.app_context():  # Prevent error appear(Working outside of application context.)
            kubernetesClient.create_cron_secret()
        return app
    except Exception as e:
        ret = internal_error(e)
        if ret[1] == 404:
            logger.logger.exception(e)
        raise e


if __name__ == "__main__":
    start_prod()
    socketio.run(app, host='0.0.0.0', port=10009, debug=config.get('DEBUG'),
                 use_reloader=config.get('USE_RELOADER'))
