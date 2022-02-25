from flask_apispec import marshal_with, doc, use_kwargs
from flask_apispec.views import MethodResource
from flask_jwt_extended import jwt_required
from flask_restful import Resource, reqparse
import util
from threading import Thread
from resources.project_relation import project_has_child, get_root_project_id, sync_project_relation, \
    get_project_family_members_by_user
from resources.issue import get_issue_list_by_project_helper, get_issue_by_tree_by_project, get_issue_by_status_by_project, \
    get_issue_progress_or_statistics_by_project, get_issue_by_date_by_project

from resources import role
from . import router_model


##### Project Relation ######

@doc(tags=['Project Relation'],description="Check project has son project or not")
@marshal_with(router_model.CheckhasSonProjectResponse)
class CheckhasSonProjectV2(MethodResource):
    @jwt_required
    def get(self, project_id):
        return {
            "has_child": project_has_child(project_id)
        }
    
class CheckhasSonProject(Resource):
    @jwt_required
    def get(self, project_id):
        return {
            "has_child": project_has_child(project_id)
        }

@doc(tags=['Project Relation'],description="Gey root project_id")
@marshal_with(router_model.GetProjectRootIDResponse)
class GetProjectRootIDV2(MethodResource):
    @jwt_required
    def get(self, project_id):
        return {"root_project_id": get_root_project_id(project_id)}

class GetProjectRootID(Resource):
    @jwt_required
    def get(self, project_id):
        return {"root_project_id": get_root_project_id(project_id)}

@doc(tags=['Project Relation'],description="Sync IIIDevops project's relationship with Redmine")
@marshal_with(util.CommonResponse)
class SyncProjectRelationV2(MethodResource):
    @jwt_required
    def post(self):
        Thread(target=sync_project_relation).start()
        return util.success()

class SyncProjectRelation(Resource):
    @jwt_required
    def post(self):
        Thread(target=sync_project_relation).start()
        return util.success()

@doc(tags=['Project Relation'],description="Get all sons' project members")
@marshal_with(router_model.GetProjectFamilymembersByUserResponse)
class GetProjectFamilymembersByUserV2(MethodResource):
    @jwt_required
    def get(self, project_id):
        return util.success(get_project_family_members_by_user(project_id))

class GetProjectFamilymembersByUser(Resource):
    @jwt_required
    def get(self, project_id):
        return util.success(get_project_family_members_by_user(project_id))


##### Project issue_list ######

@doc(tags=['Issue'], description="Get issue list by project")
@use_kwargs(router_model.IssueByProjectSchema, location="query")
# @marshal_with(route_model.IssueByProjectResponse)
@marshal_with(router_model.IssueByProjectResponseWithPage, code="with limit and offset")
class IssueByProjectV2(MethodResource):
    @ jwt_required
    def get(self, project_id, **kwargs):
        role.require_in_project(project_id, 'Error to get issue.')
        kwargs["project_id"] = project_id
        if kwargs.get("search") is not None and len(kwargs["search"]) < 2:
            output = []
        else:
            # output = get_issue_list_by_project(project_id, args)
            output = get_issue_list_by_project_helper(project_id, kwargs)
        return util.success(output)

class IssueByProject(Resource):
    @ jwt_required
    def get(self, project_id):
        role.require_in_project(project_id, 'Error to get issue.')
        parser = reqparse.RequestParser()
        parser.add_argument('fixed_version_id', type=str)
        parser.add_argument('status_id', type=str)
        parser.add_argument('tracker_id', type=str)
        parser.add_argument('assigned_to_id', type=str)
        parser.add_argument('priority_id', type=str)
        parser.add_argument('only_subproject_issues', type=bool, default=False)
        parser.add_argument('limit', type=int)
        parser.add_argument('offset', type=int)
        parser.add_argument('search', type=str)
        parser.add_argument('selection', type=str)
        parser.add_argument('sort', type=str)
        parser.add_argument('parent_id', type=str)
        parser.add_argument('due_date_start', type=str)
        parser.add_argument('due_date_end', type=str)
        parser.add_argument('with_point', type=bool)
        parser.add_argument('tags', type=str)
        args = parser.parse_args()
        args["project_id"] = project_id
        if args.get("search") is not None and len(args["search"]) < 2:
            output = []
        else:
            # output = get_issue_list_by_project(project_id, args)
            output = get_issue_list_by_project_helper(project_id, args)
        return util.success(output)

@doc(tags=['Issue'], description="Get issue list by tree by project")
# @marshal_with(route_model.IssueByTreeByProjectResponse)
class IssueByTreeByProjectV2(MethodResource):
    @ jwt_required
    def get(self, project_id):
        role.require_in_project(project_id, 'Error to get issue.')
        output = get_issue_by_tree_by_project(project_id)
        return util.success(output)

class IssueByTreeByProject(Resource):
    @ jwt_required
    def get(self, project_id):
        role.require_in_project(project_id, 'Error to get issue.')
        output = get_issue_by_tree_by_project(project_id)
        return util.success(output)

@doc(tags=['Issue'], description="Get issue list by status by project")
@marshal_with(router_model.IssueByStatusByProjectResponse)
class IssueByStatusByProjectV2(MethodResource):
    @ jwt_required
    def get(self, project_id):
        role.require_in_project(project_id)
        return get_issue_by_status_by_project(project_id)

class IssueByStatusByProject(Resource):
    @ jwt_required
    def get(self, project_id):
        role.require_in_project(project_id)
        return get_issue_by_status_by_project(project_id)

@doc(tags=['Issue'], description="Get issue Progress by tree by project")
@use_kwargs(router_model.IssuesProgressByProjectSchema, location="query")
@marshal_with(router_model.IssuesProgressByProjectResponse)
class IssuesProgressByProjectV2(MethodResource):
    @jwt_required
    def get(self, project_id, **kwargs):
        role.require_in_project(project_id)
        output = get_issue_progress_or_statistics_by_project(project_id,
                                                             kwargs, progress=True)
        return util.success(output)

class IssuesProgressByProject(Resource):
    @ jwt_required
    def get(self, project_id):
        role.require_in_project(project_id)
        parser = reqparse.RequestParser()
        parser.add_argument('fixed_version_id', type=int)
        args = parser.parse_args()
        output = get_issue_progress_or_statistics_by_project(project_id,
                                                             args, progress=True)
        return util.success(output)

@doc(tags=['Issue'], description="Get issue Progress by tree by project")
@use_kwargs(router_model.IssuesProgressByProjectSchema, location="query")
@marshal_with(router_model.IssuesStatisticsByProjectResponse)  
class IssuesStatisticsByProjectV2(MethodResource):
    @ jwt_required
    def get(self, project_id, **kwargs):
        print(kwargs)
        role.require_in_project(project_id)
        output = get_issue_progress_or_statistics_by_project(project_id,
                                                             kwargs, statistics=True)
        return util.success(output)

class IssuesStatisticsByProject(Resource):
    @ jwt_required
    def get(self, project_id):
        role.require_in_project(project_id)
        parser = reqparse.RequestParser()
        parser.add_argument('fixed_version_id', type=int)
        args = parser.parse_args()
        output = get_issue_progress_or_statistics_by_project(project_id,
                                                             args, statistics=True)
        return util.success(output)

@doc(tags=['Unknown'], description="Get issue list by date")
class IssueByDateByProjectV2(MethodResource):
    @ jwt_required
    def get(self, project_id):
        role.require_in_project(project_id)
        return get_issue_by_date_by_project(project_id)


class IssueByDateByProject(Resource):
    @ jwt_required
    def get(self, project_id):
        role.require_in_project(project_id)
        return get_issue_by_date_by_project(project_id)