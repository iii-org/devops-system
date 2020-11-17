import datetime
import os
import traceback

from flask import Flask
from flask import jsonify
from flask_cors import CORS
from flask_jwt_extended import jwt_required, get_jwt_identity
from flask_restful import Resource, Api, reqparse
from werkzeug.routing import IntegerConverter

import config
import resources.apiError as apiError
import resources.checkmarx as checkmarx
import resources.flow as flow
import resources.parameter as parameter
import resources.pipeline as pipeline
import resources.requirement as requirement
import resources.role as role
import resources.testCase as testCase
import resources.testItem as testItem
import resources.testValue as testValue
from jsonwebtoken import jsonwebtoken
from model import db
from resources import project, gitlab, util, issue, user, postman, redmine, wiki, version, sonar

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
def internal_error(e):
    traceback.print_exc()
    return util.respond(500, "Unexpected internal error",
                        error=apiError.uncaught_exception(e))


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
        return util.success(output, has_date_etc=True)


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
        return util.success(output, has_date_etc=True)

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
        return util.success(output, has_date_etc=True)


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


# noinspection PyMethodMayBeStatic
class SystemGitCommitID(Resource):
    def get(self):
        if os.path.exists("git_commit"):
            with open("git_commit") as f:
                git_commit_id = f.read().splitlines()[0]
                return util.success({"git_commit_id": "{0}".format(git_commit_id)})
        else:
            return util.respond(400, "git_commit file is not exist")


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
api.add_resource(gitlab.GitProjectMergeBranch,
                 '/repositories/rd/<repository_id>/merge_branches')
api.add_resource(gitlab.GitProjectBranchCommits,
                 '/repositories/rd/<repository_id>/commits')
api.add_resource(gitlab.GitProjectNetwork, '/repositories/<repository_id>/overview')
api.add_resource(gitlab.GitProjectId, '/repositories/<repository_id>/id')

# User
api.add_resource(user.Login, '/user/login')
api.add_resource(user.UserForgetPassword, '/user/forgetPassword')
api.add_resource(user.UserStatus, '/user/<int:user_id>/status')
api.add_resource(user.SingleUser, '/user', '/user/<int:user_id>')
api.add_resource(user.UserList, '/user/list')

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
api.add_resource(issue.DashboardIssuePriority,
                 '/dashboard_issues_priority/rd/<user_id>')
api.add_resource(issue.DashboardIssueProject, '/dashboard_issues_project/<user_id>')
api.add_resource(issue.DashboardIssueType, '/dashboard_issues_type/<user_id>')

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

# Postman tests
api.add_resource(postman.ExportToPostman, '/export_to_postman/<sint:project_id>')
api.add_resource(postman.PostmanReport, '/testResults', '/postman_report/<sint:project_id>')

# Checkmarx report generation
api.add_resource(checkmarx.CreateCheckmarxScan, '/checkmarx/create_scan')
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

# Get everything by issue_id
api.add_resource(issue.DumpByIssue, '/dump_by_issue/<issue_id>')

# Get Sonarqube report by project_id
api.add_resource(sonar.SonarReport, '/sonar_report/<sint:project_id>')

# Files
api.add_resource(project.ProjectFile, '/project/<sint:project_id>/file')
api.add_resource(redmine.RedmineFile, '/download', '/file/<int:file_id>')

# git commit
api.add_resource(SystemGitCommitID, '/system_git_commit_id')

if __name__ == "__main__":
    db.init_app(app)
    jsonwebtoken.init_app(app)
    app.run(host='0.0.0.0', port=10009, debug=(config.get('DEBUG') is True))
