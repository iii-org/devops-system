from flask_apispec import marshal_with, doc, use_kwargs
from flask_apispec.views import MethodResource
from flask_jwt_extended import jwt_required, get_jwt_identity
from flask_restful import Resource, reqparse
import util
import ast
import model
from threading import Thread
from resources.project_relation import project_has_child, get_root_project_id, sync_project_relation, \
    get_project_family_members_by_user, get_relation_list, remove_relation
from resources.issue import get_issue_list_by_project_helper, get_issue_by_tree_by_project, get_issue_by_status_by_project, \
    get_issue_progress_or_statistics_by_project, get_issue_by_date_by_project, get_custom_issue_filter, \
    create_custom_issue_filter, put_custom_issue_filter, get_lock_status, DownloadIssueAsExcel, pj_download_file_is_exist
from resources import project 
from resources import user

from sqlalchemy.orm.exc import NoResultFound
from model import CustomIssueFilter
from resources import role
from . import router_model
from model import db
from resources.apiError import DevOpsError
import resources.apiError as apiError
import threading
from flask import send_file
import nexus
from resources.redmine import redmine


##### Project Relation ######

@doc(tags=['Project'],description="Check project has son project or not")
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

@doc(tags=['Project'],description="Gey root project_id")
@marshal_with(router_model.GetProjectRootIDResponse)
class GetProjectRootIDV2(MethodResource):
    @jwt_required
    def get(self, project_id):
        return {"root_project_id": get_root_project_id(project_id)}

class GetProjectRootID(Resource):
    @jwt_required
    def get(self, project_id):
        return {"root_project_id": get_root_project_id(project_id)}

@doc(tags=['Sync'],description="Sync IIIDevops project's relationship with Redmine")
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

@doc(tags=['Project'],description="Get all sons' project members")
@marshal_with(router_model.GetProjectFamilymembersByUserResponse)
class GetProjectFamilymembersByUserV2(MethodResource):
    @jwt_required
    def get(self, project_id):
        return util.success(get_project_family_members_by_user(project_id))

class GetProjectFamilymembersByUser(Resource):
    @jwt_required
    def get(self, project_id):
        return util.success(get_project_family_members_by_user(project_id))


class ProjectRelationV2(MethodResource):
    @doc(tags=['Project'], description="Get all sons' project id")
    @marshal_with(router_model.ProjectRelationGetResponse)
    @jwt_required
    def get(self, project_id):
        return util.success(get_relation_list(project_id, []))

    @doc(tags=['Project'], description="Delete specific project and subproject relation")
    @use_kwargs(router_model.ProjectRelationDeleteSchema, location="form")
    @jwt_required
    def delete(self, project_id, **kwargs):
        return remove_relation(project_id, kwargs["parent_id"])

class ProjectRelation(Resource):
    @jwt_required
    def get(self, project_id):
        return util.success(get_relation_list(project_id, []))

    @jwt_required
    def delete(self, project_id):
        parser = reqparse.RequestParser()
        parser.add_argument('parent_id', type=int, required=True)
        args = parser.parse_args()
        return remove_relation(project_id, args["parent_id"])



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

@doc(tags=['Pending'], description="Get issue list by date")
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


##### Filter issue by project ######

class IssueFilterByProjectV2(MethodResource):
    @doc(tags=['Project'], description="Get project's issues' filter.")
    @marshal_with(router_model.IssueFilterByProjectGetResponse)
    @jwt_required
    def get(self, project_id):
        return util.success(get_custom_issue_filter(get_jwt_identity()['user_id'], project_id))


    @doc(tags=['Project'], description="Create project's issues' filter.")
    @use_kwargs(router_model.IssueFilterByProjectPostAndPutSchema, location="form")
    @marshal_with(router_model.IssueFilterByProjectPostResponse)
    @jwt_required
    def post(self, project_id, **kwargs):
        user_id = get_jwt_identity()['user_id']

        if kwargs["type"] != "issue_board" and kwargs.get("group_by") is not None:
            raise DevOpsError(400, "Column group_by is only available when type is issue_board",
                              error=apiError.argument_error("group_by"))
        if kwargs["type"] != "my_work" and kwargs.get("focus_tab") is not None:
            raise DevOpsError(400, "Column focus_tab is only available when type is my_work",
                              error=apiError.argument_error("focus_tab"))

        return util.success(create_custom_issue_filter(user_id, project_id, kwargs))

class IssueFilterByProjectWithFilterIDV2(MethodResource):
    @doc(tags=['Project'], description="Update project's issues' filter.")
    @use_kwargs(router_model.IssueFilterByProjectPostAndPutSchema, location="form")
    @marshal_with(router_model.IssueFilterByProjectPutResponse)
    @jwt_required
    def put(self, project_id, custom_filter_id, **kwargs):
        if kwargs["type"] != "issue_board" and kwargs.get("group_by") is not None:
            raise DevOpsError(400, "Column group_by is only available when type is issue_board",
                              error=apiError.argument_error("group_by"))
        if kwargs["type"] != "my_work" and kwargs.get("focus_tab") is not None:
            raise DevOpsError(400, "Column focus_tab is only available when type is my_work",
                              error=apiError.argument_error("focus_tab"))

        return util.success(put_custom_issue_filter(custom_filter_id, project_id, kwargs))

    @doc(tags=['Project'], description="Delete project's issues' filter.")
    @jwt_required
    def delete(self, project_id, custom_filter_id):
        CustomIssueFilter.query.filter_by(id=custom_filter_id).delete()
        db.session.commit()


class IssueFilterByProject(Resource):
    @jwt_required
    def get(self, project_id):
        return util.success(get_custom_issue_filter(get_jwt_identity()['user_id'], project_id))

    @jwt_required
    def post(self, project_id):
        user_id = get_jwt_identity()['user_id']
        parser = reqparse.RequestParser()
        parser.add_argument('name', type=str, required=True)
        parser.add_argument('type', type=str, required=True)
        parser.add_argument('assigned_to_id', type=str)
        parser.add_argument('fixed_version_id', type=str)
        parser.add_argument('focus_tab', type=str)
        parser.add_argument('group_by', type=dict)
        parser.add_argument('priority_id', type=str)
        parser.add_argument('show_closed_issues', type=bool)
        parser.add_argument('show_closed_versions', type=bool)
        parser.add_argument('status_id', type=str)
        parser.add_argument('tags', type=str)
        parser.add_argument('tracker_id', type=str)
        args = parser.parse_args()

        if args["type"] != "issue_board" and args.get("group_by") is not None:
            raise DevOpsError(400, "Column group_by is only available when type is issue_board",
                              error=apiError.argument_error("group_by"))
        if args["type"] != "my_work" and args.get("focus_tab") is not None:
            raise DevOpsError(400, "Column focus_tab is only available when type is my_work",
                              error=apiError.argument_error("focus_tab"))

        return util.success(create_custom_issue_filter(user_id, project_id, args))

    @jwt_required
    def put(self, project_id, custom_filter_id):
        parser = reqparse.RequestParser()
        parser.add_argument('name', type=str, required=True)
        parser.add_argument('type', type=str, required=True)
        parser.add_argument('assigned_to_id', type=str)
        parser.add_argument('fixed_version_id', type=str)
        parser.add_argument('focus_tab', type=str)
        parser.add_argument('group_by', type=dict)
        parser.add_argument('priority_id', type=str)
        parser.add_argument('show_closed_issues', type=bool)
        parser.add_argument('show_closed_versions', type=bool)
        parser.add_argument('status_id', type=str)
        parser.add_argument('tags', type=str)
        parser.add_argument('tracker_id', type=str)
        args = parser.parse_args()

        if args["type"] != "issue_board" and args.get("group_by") is not None:
            raise DevOpsError(400, "Column group_by is only available when type is issue_board",
                              error=apiError.argument_error("group_by"))
        if args["type"] != "my_work" and args.get("focus_tab") is not None:
            raise DevOpsError(400, "Column focus_tab is only available when type is my_work",
                              error=apiError.argument_error("focus_tab"))

        return util.success(put_custom_issue_filter(custom_filter_id, project_id, args))

    @jwt_required
    def delete(self, project_id, custom_filter_id):
        CustomIssueFilter.query.filter_by(id=custom_filter_id).delete()
        db.session.commit()

##### Download project issue as excel ######

class DownloadProjectExecuteV2(MethodResource):
    # download/execute
    @doc(tags=['Issue'], description="Execute download project's issues as excel.")
    @use_kwargs(router_model.DownloadProjectSchema, location="form")
    @marshal_with(util.CommonResponse)
    @jwt_required
    def post(self, project_id, **kwargs):
        if get_lock_status("download_pj_issues")["is_lock"]:
            return util.success("previous is still running")
        download_issue_excel = DownloadIssueAsExcel(kwargs, project_id, get_jwt_identity()["user_id"])
        threading.Thread(target=download_issue_excel.execute).start()
        return util.success()

class DownloadProjectIsExistV2(MethodResource):
    # download/is_exist
    @doc(tags=['Issue'], description="Check excel file is exist.")
    @marshal_with(router_model.DownloadProjectIsExistResponse)
    @jwt_required 
    def get(self, project_id):
        return util.success(pj_download_file_is_exist(project_id))

class DownloadProjectV2(MethodResource):
    # download/execute
    @doc(tags=['Issue'], description="Download project's issues' excel.")
    @jwt_required
    def patch(self, project_id):
        if not pj_download_file_is_exist(project_id)["file_exist"]:
            raise apiError.DevOpsError(
                404, 'This file can not be downloaded because it is not exist.',
                apiError.project_issue_file_not_exits(project_id))

        return send_file(f"../logs/project_excel_file/{project_id}.xlsx")

class DownloadProject(Resource):
    # download/execute
    @jwt_required
    def post(self, project_id):
        parser = reqparse.RequestParser()
        parser.add_argument('fixed_version_id', type=str)
        parser.add_argument('status_id', type=str)
        parser.add_argument('tracker_id', type=str)
        parser.add_argument('assigned_to_id', type=str)
        parser.add_argument('priority_id', type=str)
        parser.add_argument('search', type=str)
        parser.add_argument('selection', type=str)
        parser.add_argument('sort', type=str)
        parser.add_argument('parent_id', type=str)
        parser.add_argument('due_date_start', type=str)
        parser.add_argument('due_date_end', type=str)
        parser.add_argument('with_point', type=bool, default=True)
        parser.add_argument('levels', type=int, default=3)
        parser.add_argument('deploy_column', type=dict, action='append', required=True)
        args = parser.parse_args()

        if get_lock_status("download_pj_issues")["is_lock"]:
            return util.success("previous is still running")
        download_issue_excel = DownloadIssueAsExcel(args, project_id, get_jwt_identity()["user_id"])
        threading.Thread(target=download_issue_excel.execute).start()
        return util.success()

    # download/is_exist
    @jwt_required 
    def get(self, project_id):
        return util.success(pj_download_file_is_exist(project_id))

    # download/execute
    @jwt_required    
    def patch(self, project_id):
        if not pj_download_file_is_exist(project_id)["file_exist"]:
            raise apiError.DevOpsError(
                404, 'This file can not be downloaded because it is not exist.',
                apiError.project_issue_file_not_exits(project_id))

        return send_file(f"../logs/project_excel_file/{project_id}.xlsx")


##### List project ######
@doc(tags=['Project'], description="List projects")
@use_kwargs(router_model.ListMyProjectsSchema, location="query")
@marshal_with(router_model.ListMyProjectsResponse)
class ListMyProjectsV2(MethodResource):
    @jwt_required
    def get(self, **kwargs):
        print(kwargs)
        disabled = None
        if kwargs.get("disabled") is not None:
            disabled = kwargs["disabled"] == 1
        if kwargs.get('simple', 'false') == 'true':
            return util.success(
                {'project_list': project.get_project_list(get_jwt_identity()['user_id'], "simple", kwargs, disabled)})
        if role.is_role(role.RD):
            return util.success(
                {'project_list': project.get_project_list(get_jwt_identity()['user_id'], "rd", kwargs, disabled)})
        else:
            return util.success(
                {'project_list': project.get_project_list(get_jwt_identity()['user_id'], "pm", kwargs, disabled)})

class ListMyProjects(Resource):
    @jwt_required
    def get(self):
        parser = reqparse.RequestParser()
        parser.add_argument('simple', type=str)
        parser.add_argument('limit', type=int)
        parser.add_argument('offset', type=int)
        parser.add_argument('search', type=str)
        parser.add_argument('disabled', type=int)
        args = parser.parse_args()
        disabled = None
        if args.get("disabled") is not None:
            disabled = args["disabled"] == 1
        if args.get('simple', 'false') == 'true':
            return util.success(
                {'project_list': project.get_project_list(get_jwt_identity()['user_id'], "simple", args, disabled)})
        if role.is_role(role.RD):
            return util.success(
                {'project_list': project.get_project_list(get_jwt_identity()['user_id'], "rd", args, disabled)})
        else:
            return util.success(
                {'project_list': project.get_project_list(get_jwt_identity()['user_id'], "pm", args, disabled)})



@doc(tags=['Project'], description="List projects")
@use_kwargs(router_model.CalculateProjectIssuesSchema, location="query")
@marshal_with(router_model.CalculateProjectIssuesResponse)
class CalculateProjectIssuesV2(MethodResource):
    @jwt_required
    def get(self, **kwargs):
        
        project_ids = kwargs.get("project_ids").split(",")

        return util.success(
            {'project_list': project.get_project_issue_calculation(get_jwt_identity()['user_account'], project_ids)})


class CalculateProjectIssues(Resource):
    @jwt_required
    def get(self):
        parser = reqparse.RequestParser()
        parser.add_argument('project_ids', type=str, required=True)
        args = parser.parse_args()
        project_ids = args.get("project_ids").split(",")

        return util.success(
            {'project_list': project.get_project_issue_calculation(get_jwt_identity()['user_account'], project_ids)})

@doc(tags=['Project'], description="List projects by user")
@marshal_with(router_model.ListMyProjectsByUserResponse)
class ListProjectsByUserV2(MethodResource):
    @jwt_required
    def get(self, user_id):
        role.require_pm("Error while get project by user.")
        projects = project.get_projects_by_user(user_id)
        return util.success(projects)

class ListProjectsByUser(Resource):
    @jwt_required
    def get(self, user_id):
        role.require_pm("Error while get project by user.")
        projects = project.get_projects_by_user(user_id)
        return util.success(projects)


##### Single project ######

class SingleProjectV2(MethodResource):
    @doc(tags=['Project'], description="Get project info")
    @marshal_with(router_model.SingleProjectGetResponse)
    @jwt_required
    def get(self, project_id):
        role.require_pm("Error while getting project info.")
        role.require_in_project(
            project_id, "Error while getting project info.")
        return util.success(project.get_project_info(project_id))

    @doc(tags=['Project'], description="Update project info")
    @use_kwargs(router_model.SingleProjectPutSchema, location="form")
    @marshal_with(util.CommonResponse)
    @jwt_required
    def put(self, project_id, **kwargs):
        role.require_pm("Error while updating project info.", exclude_qa=True)
        role.require_in_project(
            project_id, "Error while updating project info.")
        project.check_project_args_patterns(kwargs)
        project.check_project_owner_id(kwargs['owner_id'], get_jwt_identity()[
            'user_id'], project_id)
        project.pm_update_project(project_id, kwargs)
        return util.success()

    @doc(tags=['Project'], description="Update project owner")
    @use_kwargs(router_model.SingleProjectPatchSchema, location="form")
    @marshal_with(util.CommonResponse)
    @jwt_required
    def patch(self, project_id, **kwargs):
        role.require_pm("Error while updating project info.", exclude_qa=True)
        role.require_in_project(
            project_id, "Error while updating project info.")
        project.check_project_args_patterns(kwargs)
        if kwargs.get('owner_id', None) is not None:
            project.check_project_owner_id(kwargs['owner_id'], get_jwt_identity()[
                'user_id'], project_id)
        project.nexus_update_project(project_id, kwargs)
        return util.success()

    @doc(tags=['Project'], description="Delete project")
    @marshal_with(util.CommonResponse)
    @jwt_required
    def delete(self, project_id):
        role.require_pm()
        role.require_in_project(project_id)
        role_id = get_jwt_identity()["role_id"]
        user_id = get_jwt_identity()["user_id"]
        if role_id == role.QA.id:
            if not bool(
                    model.Project.query.filter_by(
                        id=project_id,
                        creator_id=user_id
                    ).count()):
                raise apiError.NotAllowedError('Error while deleting project.')
        parser = reqparse.RequestParser()
        parser.add_argument('force_delete_project', type=bool)
        args = parser.parse_args()
        if args['force_delete_project'] is True:
            return project.delete_project(project_id, force_delete_project=True)
        else:
            return project.delete_project(project_id)


class SingleProjectCreateV2(MethodResource):
    @doc(tags=['Project'], description="Create project")
    @use_kwargs(router_model.SingleProjectPostSchema, location="form")
    @marshal_with(router_model.SingleProjectPostResponse)
    @jwt_required
    def post(self, **kwargs):
        role.require_pm()
        user_id = get_jwt_identity()["user_id"]
        
        if kwargs.get('arguments') is not None:
            kwargs['arguments'] = ast.literal_eval(kwargs['arguments'])
        project.check_project_args_patterns(kwargs)
        return util.success(project.create_project(user_id, kwargs))

class SingleProject(Resource):
    @jwt_required
    def get(self, project_id):
        role.require_pm("Error while getting project info.")
        role.require_in_project(
            project_id, "Error while getting project info.")
        return util.success(project.get_project_info(project_id))

    @jwt_required
    def put(self, project_id):
        role.require_pm("Error while updating project info.", exclude_qa=True)
        role.require_in_project(
            project_id, "Error while updating project info.")
        parser = reqparse.RequestParser()
        parser.add_argument('display', type=str, required=True)
        parser.add_argument('description', type=str)
        parser.add_argument('disabled', type=bool, required=True)
        parser.add_argument('start_date', type=str, required=True)
        parser.add_argument('due_date', type=str, required=True)
        parser.add_argument('owner_id', type=int, required=True)
        parser.add_argument('parent_id', type=int)
        parser.add_argument('is_inherit_members', type=bool)
        args = parser.parse_args()
        project.check_project_args_patterns(args)
        project.check_project_owner_id(args['owner_id'], get_jwt_identity()[
            'user_id'], project_id)
        project.pm_update_project(project_id, args)
        return util.success()

    @jwt_required
    def patch(self, project_id):
        role.require_pm("Error while updating project info.", exclude_qa=True)
        role.require_in_project(
            project_id, "Error while updating project info.")
        parser = reqparse.RequestParser()
        parser.add_argument('owner_id', type=int, required=False)
        args = parser.parse_args()
        project.check_project_args_patterns(args)
        if args.get('owner_id', None) is not None:
            project.check_project_owner_id(args['owner_id'], get_jwt_identity()[
                'user_id'], project_id)
        project.nexus_update_project(project_id, args)
        return util.success()

    @jwt_required
    def delete(self, project_id):
        role.require_pm()
        role.require_in_project(project_id)
        role_id = get_jwt_identity()["role_id"]
        user_id = get_jwt_identity()["user_id"]
        if role_id == role.QA.id:
            if not bool(
                    model.Project.query.filter_by(
                        id=project_id,
                        creator_id=user_id
                    ).count()):
                raise apiError.NotAllowedError('Error while deleting project.')
        return project.delete_project(project_id)

    @jwt_required
    def post(self):
        role.require_pm()
        user_id = get_jwt_identity()["user_id"]
        parser = reqparse.RequestParser()
        parser.add_argument('name', type=str, required=True)
        parser.add_argument('display', type=str)
        parser.add_argument('description', type=str)
        parser.add_argument('disabled', type=bool, required=True)
        parser.add_argument('template_id', type=int)
        parser.add_argument('tag_name', type=str)
        parser.add_argument('arguments', type=str)
        parser.add_argument('start_date', type=str, required=True)
        parser.add_argument('due_date', type=str, required=True)
        parser.add_argument('owner_id', type=int)
        parser.add_argument('parent_id', type=int)
        parser.add_argument('is_inherit_members', type=bool)
        args = parser.parse_args()
        if args['arguments'] is not None:
            args['arguments'] = ast.literal_eval(args['arguments'])
        project.check_project_args_patterns(args)
        return util.success(project.create_project(user_id, args))


@doc(tags=['Project'], description="Get project by project name.")
@marshal_with(router_model.SingleProjectByNameResponse)
class SingleProjectByNameV2(MethodResource):
    @jwt_required
    def get(self, project_name):
        project_id = nexus.nx_get_project(name=project_name).id
        role.require_pm("Error while getting project info.")
        role.require_in_project(
            project_id, "Error while getting project info.")
        return util.success(project.get_project_info(project_id))

class SingleProjectByName(Resource):
    @jwt_required
    def get(self, project_name):
        project_id = nexus.nx_get_project(name=project_name).id
        role.require_pm("Error while getting project info.")
        role.require_in_project(
            project_id, "Error while getting project info.")
        return util.success(project.get_project_info(project_id))

##### Project member ######

class ProjectMemberV2(MethodResource):
    @doc(tags=['User'], description="Create project member.")
    @use_kwargs(router_model.SingleProjectPutSchema, location="form")
    @marshal_with(util.CommonResponse)
    @jwt_required
    def post(self, project_id, **kwargs):
        role.require_pm()
        role.require_in_project(project_id)
        return project.project_add_member(project_id, kwargs['user_id'])

@doc(tags=['User'], description="Delete project member.")
@marshal_with(util.CommonResponse)
class ProjectMemberDeleteV2(MethodResource):
    @jwt_required
    def delete(self, project_id, user_id):
        role.require_pm()
        role.require_in_project(project_id)
        return project.project_remove_member(project_id, user_id)

class ProjectMember(Resource):
    @jwt_required
    def post(self, project_id):
        role.require_pm()
        role.require_in_project(project_id)
        parser = reqparse.RequestParser()
        parser.add_argument('user_id', type=int, required=True)
        args = parser.parse_args()
        return project.project_add_member(project_id, args['user_id'])

    @jwt_required
    def delete(self, project_id, user_id):
        role.require_pm()
        role.require_in_project(project_id)
        return project.project_remove_member(project_id, user_id)

class ProjectUserListV2(MethodResource):
    @doc(tags=['User'], description="Get users which able to add in the project.")
    @use_kwargs(router_model.ProjectUserListSchema, location="query")
    @marshal_with(router_model.ProjectUserListResponse)
    @jwt_required
    def get(self, project_id, **kwargs):
        return util.success({'user_list': user.user_list_by_project(project_id, kwargs)})

class ProjectUserList(Resource):
    @jwt_required
    def get(self, project_id):
        parser = reqparse.RequestParser()
        parser.add_argument('exclude', type=int)
        args = parser.parse_args()
        return util.success({'user_list': user.user_list_by_project(project_id, args)})

##### Project report ######

@doc(tags=['Project'], description="Get project test summary.")
@marshal_with(router_model.TestSummaryResponse)
class TestSummaryV2(MethodResource):
    @jwt_required
    def get(self, project_id):
        role.require_in_project(project_id)
        return project.get_test_summary(project_id)

class TestSummary(Resource):
    @jwt_required
    def get(self, project_id):
        role.require_in_project(project_id)
        return project.get_test_summary(project_id)


@doc(tags=['Project'], description="Get project all test reports' zip.")
class AllReportsV2(MethodResource):
    @jwt_required
    def get(self, project_id):
        role.require_pm()
        role.require_in_project(project_id)
        return send_file(project.get_all_reports(project_id),
                         attachment_filename='reports.zip', as_attachment=True)

class AllReports(Resource):
    @jwt_required
    def get(self, project_id):
        role.require_pm()
        role.require_in_project(project_id)
        return send_file(project.get_all_reports(project_id),
                         attachment_filename='reports.zip', as_attachment=True)

class ProjectFileV2(MethodResource):
    @doc(tags=['File'], description="Upload file to project.")
    @jwt_required
    def post(self, project_id):
        try:
            plan_project_id = project.get_plan_project_id(project_id)
        except NoResultFound:
            raise apiError.DevOpsError(404, 'Error while uploading a file to a project.',
                                       error=apiError.project_not_found(project_id))

        parser = reqparse.RequestParser()
        parser.add_argument('filename', type=str)
        parser.add_argument('version_id', type=str)
        parser.add_argument('description', type=str)
        args = parser.parse_args()
        plan_operator_id = None
        if get_jwt_identity()['user_id'] is not None:
            operator_plugin_relation = nexus.nx_get_user_plugin_relation(
                user_id=get_jwt_identity()['user_id'])
            plan_operator_id = operator_plugin_relation.plan_user_id
        return redmine.rm_upload_to_project(plan_project_id, args, plan_operator_id)

    @doc(tags=['File'], description="Get project file list.")
    @marshal_with(router_model.ProjectFileGetResponse)
    @jwt_required
    def get(self, project_id):
        try:
            plan_project_id = project.get_plan_project_id(project_id)
        except NoResultFound:
            raise apiError.DevOpsError(404, 'Error while getting project files.',
                                       error=apiError.project_not_found(project_id))
        return util.success(redmine.rm_list_file(plan_project_id))

class ProjectFile(Resource):
    @jwt_required
    def post(self, project_id):
        try:
            plan_project_id = project.get_plan_project_id(project_id)
        except NoResultFound:
            raise apiError.DevOpsError(404, 'Error while uploading a file to a project.',
                                       error=apiError.project_not_found(project_id))

        parser = reqparse.RequestParser()
        parser.add_argument('filename', type=str)
        parser.add_argument('version_id', type=str)
        parser.add_argument('description', type=str)
        args = parser.parse_args()
        plan_operator_id = None
        if get_jwt_identity()['user_id'] is not None:
            operator_plugin_relation = nexus.nx_get_user_plugin_relation(
                user_id=get_jwt_identity()['user_id'])
            plan_operator_id = operator_plugin_relation.plan_user_id
        return redmine.rm_upload_to_project(plan_project_id, args, plan_operator_id)

    @jwt_required
    def get(self, project_id):
        try:
            plan_project_id = project.get_plan_project_id(project_id)
        except NoResultFound:
            raise apiError.DevOpsError(404, 'Error while getting project files.',
                                       error=apiError.project_not_found(project_id))
        return util.success(redmine.rm_list_file(plan_project_id))

##### Project plugin(k8s) ######

@doc(tags=['Plugin'], description="Get project plugin resource info.")
@marshal_with(router_model.ProjectPluginUsageResponse)
class ProjectPluginUsageV2(MethodResource):
    @jwt_required
    def get(self, project_id):
        role.require_in_project(
            project_id, "Error while getting project info.")
        return project.get_plugin_usage(project_id)

class ProjectPluginUsage(Resource):
    @jwt_required
    def get(self, project_id):
        role.require_in_project(
            project_id, "Error while getting project info.")
        return project.get_plugin_usage(project_id)

class ProjectUserResourceV2(MethodResource):
    @doc(tags=['K8s'], description="Get project k8s info.")
    @marshal_with(router_model.ProjectUserResourceResponse)
    @jwt_required
    def get(self, project_id):
        role.require_in_project(
            project_id, "Error while getting project info.")
        return project.get_kubernetes_namespace_Quota(project_id)

    @doc(tags=['K8s'], description="Update project k8s info.")
    # @use_kwargs(router_model.ProjectUserResourceSchema, location="form")
    @marshal_with(util.CommonResponse)
    @jwt_required
    def put(self, project_id):
        role.require_admin("Error while updating project resource.")
        parser = reqparse.RequestParser()
        parser.add_argument('memory', type=str, required=True)
        parser.add_argument('pods', type=int, required=True)
        parser.add_argument('secrets', type=int, required=True)
        parser.add_argument('configmaps', type=int, required=True)
        parser.add_argument('services.nodeports', type=int, required=True)
        parser.add_argument('persistentvolumeclaims', type=int, required=True)
        args = parser.parse_args()
        return project.update_kubernetes_namespace_Quota(project_id, args)

class ProjectUserResource(Resource):
    @jwt_required
    def get(self, project_id):
        role.require_in_project(
            project_id, "Error while getting project info.")
        return project.get_kubernetes_namespace_Quota(project_id)

    @jwt_required
    def put(self, project_id):
        role.require_admin("Error while updating project resource.")
        parser = reqparse.RequestParser()
        parser.add_argument('memory', type=str, required=True)
        parser.add_argument('pods', type=int, required=True)
        parser.add_argument('secrets', type=int, required=True)
        parser.add_argument('configmaps', type=int, required=True)
        parser.add_argument('services.nodeports', type=int, required=True)
        parser.add_argument('persistentvolumeclaims', type=int, required=True)
        args = parser.parse_args()
        return project.update_kubernetes_namespace_Quota(project_id, args)


@doc(tags=['System'], description="Check latest project has pod or not")
@use_kwargs(router_model.ProjectPluginPodSchema, location="query")
@marshal_with(router_model.ProjectPluginPodResponse)
class ProjectPluginPodV2(MethodResource):
    @jwt_required
    def get(self, project_id, **kwargs):
        role.require_in_project(
            project_id, "Error while getting project info.")
        return project.get_kubernetes_plugin_pods(project_id, kwargs.get("plugin_name"))

class ProjectPluginPod(Resource):
    @jwt_required
    def get(self, project_id):
        role.require_in_project(
            project_id, "Error while getting project info.")
        parser = reqparse.RequestParser()
        parser.add_argument('plugin_name', type=str)
        args = parser.parse_args()
        return project.get_kubernetes_plugin_pods(project_id, args.get("plugin_name"))

@doc(tags=['K8s'], description="Get project pod list")
@marshal_with(router_model.ProjectUserResourcePodsResponse)
class ProjectUserResourcePodsV2(MethodResource):
    @jwt_required
    def get(self, project_id):
        role.require_in_project(
            project_id, "Error while getting project info.")
        return project.get_kubernetes_namespace_pods(project_id)

class ProjectUserResourcePods(Resource):
    @jwt_required
    def get(self, project_id):
        role.require_in_project(
            project_id, "Error while getting project info.")
        return project.get_kubernetes_namespace_pods(project_id)

@doc(tags=['K8s'], description="Delete specific project pod.")
@marshal_with(router_model.ProjectUserResourcePodResponse)
class ProjectUserResourcePodV2(MethodResource):
    @jwt_required
    def delete(self, project_id, pod_name):
        role.require_in_project(
            project_id, "Error while getting project info.")
        return project.delete_kubernetes_namespace_pod(project_id, pod_name)

class ProjectUserResourcePod(Resource):
    @jwt_required
    def delete(self, project_id, pod_name):
        role.require_in_project(
            project_id, "Error while getting project info.")
        return project.delete_kubernetes_namespace_pod(project_id, pod_name)

@doc(tags=['K8s'], description="Get specific project pod.")
@use_kwargs(router_model.ProjectUserResourcePodLogSchema, location="query")
@marshal_with(router_model.ProjectUserResourcePodResponse)
class ProjectUserResourcePodLogV2(MethodResource):
    @jwt_required
    def get(self, project_id, pod_name, **kwargs):
        role.require_in_project(
            project_id, "Error while getting project info.")
        return project.get_kubernetes_namespace_pod_log(project_id, pod_name, kwargs['container_name'])

class ProjectUserResourcePodLog(Resource):
    @jwt_required
    def get(self, project_id, pod_name):
        role.require_in_project(
            project_id, "Error while getting project info.")
        parser = reqparse.RequestParser()
        parser.add_argument('container_name', type=str)
        args = parser.parse_args()
        return project.get_kubernetes_namespace_pod_log(project_id, pod_name, args['container_name'])

@doc(tags=['System'], description="Get specific project deployed environment.")
@marshal_with(router_model.ProjectEnvironmentGetResponse)
class ProjectEnvironmentGetV2(MethodResource):
    @jwt_required
    def get(self, project_id):
        role.require_in_project(
            project_id, "Error while getting project info.")
        return util.success(project.get_kubernetes_namespace_dev_environment(project_id))

class ProjectEnvironmentV2(MethodResource):
    @doc(tags=['System'], description="Redeploy specific project deployed environment.")
    @marshal_with(router_model.ProjectEnvironmentPutResponse)
    @jwt_required
    def put(self, project_id, branch_name):
        role.require_in_project(
            project_id, "Error while getting project info.")
        return project.put_kubernetes_namespace_dev_environment(project_id, branch_name)

    @doc(tags=['System'], description="Delete specific project deployed environment.")
    @marshal_with(router_model.ProjectEnvironmentDeleteResponse)
    @jwt_required
    def delete(self, project_id, branch_name):
        role.require_in_project(
            project_id, "Error while getting project info.")
        return project.delete_kubernetes_namespace_dev_environment(project_id, branch_name)


class ProjectEnvironment(Resource):
    @jwt_required
    def get(self, project_id):
        role.require_in_project(
            project_id, "Error while getting project info.")
        return util.success(project.get_kubernetes_namespace_dev_environment(project_id))

    @jwt_required
    def put(self, project_id, branch_name):
        role.require_in_project(
            project_id, "Error while getting project info.")
        return project.put_kubernetes_namespace_dev_environment(project_id, branch_name)

    @jwt_required
    def delete(self, project_id, branch_name):
        role.require_in_project(
            project_id, "Error while getting project info.")
        return project.delete_kubernetes_namespace_dev_environment(project_id, branch_name)

@doc(tags=['Pending'], description="Get specific project deployed environment's URL?")
# @marshal_with(router_model.ProjectEnvironmentUrlResponse)
class ProjectEnvironmentUrlV2(MethodResource):
    @jwt_required
    def get(self, project_id, branch_name):
        role.require_in_project(
            project_id, "Error while getting project info.")
        return util.success(project.get_kubernetes_namespace_dev_environment_urls(
            project_id, branch_name))

class ProjectEnvironmentUrl(Resource):
    @jwt_required
    def get(self, project_id, branch_name):
        role.require_in_project(
            project_id, "Error while getting project info.")
        return util.success(project.get_kubernetes_namespace_dev_environment_urls(
            project_id, branch_name))


##### k8s info ######
@doc(tags=['System'], description="Get specific project deployment list.")
@marshal_with(router_model.ProjectUserResourceDeploymentsResponse)
class ProjectUserResourceDeploymentsV2(MethodResource):
    @jwt_required
    def get(self, project_id):
        role.require_in_project(
            project_id, "Error while getting project info.")
        return project.get_kubernetes_namespace_deployment(project_id)


class ProjectUserResourceDeployments(Resource):
    @jwt_required
    def get(self, project_id):
        role.require_in_project(
            project_id, "Error while getting project info.")
        return project.get_kubernetes_namespace_deployment(project_id)


class ProjectUserResourceDeploymentV2(MethodResource):
    @doc(tags=['System'], description="Redeploy specific project deployment.")
    @marshal_with(router_model.ProjectUserResourceDeploymentResponse)
    @jwt_required
    def put(self, project_id, deployment_name):
        role.require_in_project(
            project_id, "Error while getting project info.")
        return project.put_kubernetes_namespace_deployment(project_id, deployment_name)

    @doc(tags=['System'], description="Delete specific project deployment.")
    @marshal_with(router_model.ProjectUserResourceDeploymentResponse)
    @jwt_required
    def delete(self, project_id, deployment_name):
        role.require_in_project(
            project_id, "Error while getting project info.")
        return project.delete_kubernetes_namespace_deployment(project_id, deployment_name)

class ProjectUserResourceDeployment(Resource):
    @jwt_required
    def put(self, project_id, deployment_name):
        role.require_in_project(
            project_id, "Error while getting project info.")
        return project.put_kubernetes_namespace_deployment(project_id, deployment_name)

    @jwt_required
    def delete(self, project_id, deployment_name):
        role.require_in_project(
            project_id, "Error while getting project info.")
        return project.delete_kubernetes_namespace_deployment(project_id, deployment_name)

@doc(tags=['System'], description="Get specific project service list.")
@marshal_with(router_model.ProjectUserResourceServicesResponse)
class ProjectUserResourceServicesV2(MethodResource):
    @jwt_required
    def get(self, project_id):
        role.require_in_project(
            project_id, "Error while getting project info.")
        return project.get_kubernetes_namespace_services(project_id)

class ProjectUserResourceServices(Resource):
    @jwt_required
    def get(self, project_id):
        role.require_in_project(
            project_id, "Error while getting project info.")
        return project.get_kubernetes_namespace_services(project_id)


class ProjectUserResourceServiceV2(MethodResource):
    @doc(tags=['System'], description="Delete specific project service.")
    @marshal_with(router_model.ProjectUserResourceServiceDeleteResponse)
    @jwt_required
    def delete(self, project_id, service_name):
        role.require_in_project(
            project_id, "Error while getting project info.")
        return project.delete_kubernetes_namespace_service(project_id, service_name)

class ProjectUserResourceService(Resource):
    @jwt_required
    def delete(self, project_id, service_name):
        role.require_in_project(
            project_id, "Error while getting project info.")
        return project.delete_kubernetes_namespace_service(project_id, service_name)


class ProjectUserResourceSecretsV2(MethodResource):
    @doc(tags=['K8s'], description="Get specific project k8s secret.")
    @marshal_with(router_model.ProjectUserResourceSecretsResponse)
    @jwt_required
    def get(self, project_id):
        role.require_in_project(
            project_id, "Error while getting project info.")
        return project.get_kubernetes_namespace_secrets(project_id)

class ProjectUserResourceSecrets(Resource):
    @jwt_required
    def get(self, project_id):
        role.require_in_project(
            project_id, "Error while getting project info.")
        return project.get_kubernetes_namespace_secrets(project_id)


class ProjectUserResourceSecretV2(MethodResource):
    @doc(tags=['K8s'], description="Get specific project k8s secret by secret name.")
    @marshal_with(router_model.ProjectUserResourceSecretGetResponse)
    @jwt_required
    def get(self, project_id, secret_name):
        role.require_in_project(
            project_id, "Error while getting project info.")
        return project.read_kubernetes_namespace_secret(project_id, secret_name)

    @doc(tags=['Pending'], description="Might not be used in project.")
    @use_kwargs(router_model.ProjectUserResourceSecretSchema, location="form")
    @marshal_with(util.CommonResponse)
    @jwt_required
    def post(self, project_id, secret_name, **kwargs):
        role.require_in_project(
            project_id, "Error while getting project info.")
        return project.create_kubernetes_namespace_secret(project_id, secret_name, kwargs["secrets"])

    @doc(tags=['K8s'], description="Update specific project k8s secret by secret name.")
    @use_kwargs(router_model.ProjectUserResourceSecretSchema, location="form")
    @marshal_with(util.CommonResponse)
    @jwt_required
    def put(self, project_id, secret_name, **kwargs):
        role.require_in_project(
            project_id, "Error while getting project info.")
        return project.put_kubernetes_namespace_secret(project_id, secret_name, kwargs["secrets"])

    @doc(tags=['K8s'], description="Delete specific project k8s secret by secret name.")
    @marshal_with(router_model.ProjectUserResourceSecretDeleteResponse)
    @jwt_required
    def delete(self, project_id, secret_name):
        role.require_in_project(
            project_id, "Error while getting project info.")
        return project.delete_kubernetes_namespace_secret(project_id, secret_name)


class ProjectUserResourceSecret(Resource):
    @jwt_required
    def get(self, project_id, secret_name):
        role.require_in_project(
            project_id, "Error while getting project info.")
        return project.read_kubernetes_namespace_secret(project_id, secret_name)

    @jwt_required
    def post(self, project_id, secret_name):
        role.require_in_project(
            project_id, "Error while getting project info.")
        parser = reqparse.RequestParser()
        parser.add_argument('secrets', type=dict, required=True)
        args = parser.parse_args()
        return project.create_kubernetes_namespace_secret(project_id, secret_name, args["secrets"])

    @jwt_required
    def put(self, project_id, secret_name):
        role.require_in_project(
            project_id, "Error while getting project info.")
        parser = reqparse.RequestParser()
        parser.add_argument('secrets', type=dict, required=True)
        args = parser.parse_args()
        return project.put_kubernetes_namespace_secret(project_id, secret_name, args["secrets"])

    @jwt_required
    def delete(self, project_id, secret_name):
        role.require_in_project(
            project_id, "Error while getting project info.")
        return project.delete_kubernetes_namespace_secret(project_id, secret_name)


class ProjectUserResourceConfigMapsV2(MethodResource):
    @doc(tags=['K8s'], description="Get specific project k8s configmap list.")
    @marshal_with(router_model.ProjectUserResourceConfigMapsResponse)
    @jwt_required
    def get(self, project_id):
        role.require_in_project(
            project_id, "Error while getting project info.")
        return project.get_kubernetes_namespace_configmaps(project_id)


class ProjectUserResourceConfigMaps(Resource):
    @jwt_required
    def get(self, project_id):
        role.require_in_project(
            project_id, "Error while getting project info.")
        return project.get_kubernetes_namespace_configmaps(project_id)

class ProjectUserResourceConfigMapV2(MethodResource):
    @doc(tags=['K8s'], description="Get specific project k8s configmap by configmap_na.")
    @marshal_with(router_model.ProjectUserResourceConfigMapResponse)
    @jwt_required
    def get(self, project_id, configmap_name):
        role.require_in_project(
            project_id, "Error while getting project info.")
        return project.read_kubernetes_namespace_configmap(project_id, configmap_name)

    @doc(tags=['K8s'], description="Delete specific project k8s configmap by configmap_na.")
    @marshal_with(router_model.ProjectUserResourceConfigMapsDeleteResponse)
    @jwt_required
    def delete(self, project_id, configmap_name):
        role.require_in_project(
            project_id, "Error while getting project info.")
        return project.delete_kubernetes_namespace_configmap(project_id, configmap_name)

    @doc(tags=['K8s'], description="Update specific project k8s configmap by configmap_name.")
    @use_kwargs(router_model.ProjectUserResourceConfigMapsSchema, location="form")
    @marshal_with(router_model.ProjectUserResourceConfigMapResponse)
    @jwt_required
    def put(self, project_id, configmap_name, **kwargs):
        role.require_in_project(
            project_id, "Error while getting project info.")
        return project.put_kubernetes_namespace_configmap(project_id, configmap_name, kwargs['configmaps'])

    @doc(tags=['K8s'], description="Create specific project k8s configmap by configmap_name.")
    @use_kwargs(router_model.ProjectUserResourceConfigMapsSchema, location="form")
    @marshal_with(router_model.ProjectUserResourceConfigMapResponse)
    @jwt_required
    def post(self, project_id, configmap_name, **kwargs):
        role.require_in_project(
            project_id, "Error while getting project info.")
        return project.create_kubernetes_namespace_configmap(project_id, configmap_name, kwargs['configmaps'])

class ProjectUserResourceConfigMap(Resource):
    @jwt_required
    def get(self, project_id, configmap_name):
        print(configmap_name)
        role.require_in_project(
            project_id, "Error while getting project info.")
        return project.read_kubernetes_namespace_configmap(project_id, configmap_name)

    @jwt_required
    def delete(self, project_id, configmap_name):
        role.require_in_project(
            project_id, "Error while getting project info.")
        return project.delete_kubernetes_namespace_configmap(project_id, configmap_name)

    @jwt_required
    def put(self, project_id, configmap_name):
        parser = reqparse.RequestParser()
        parser.add_argument('configmaps', type=dict, required=True)
        args = parser.parse_args()
        role.require_in_project(
            project_id, "Error while getting project info.")
        return project.put_kubernetes_namespace_configmap(project_id, configmap_name, args['configmaps'])

    @jwt_required
    def post(self, project_id, configmap_name):
        parser = reqparse.RequestParser()
        parser.add_argument('configmaps', type=dict, required=True)
        args = parser.parse_args()
        role.require_in_project(
            project_id, "Error while getting project info.")
        return project.create_kubernetes_namespace_configmap(project_id, configmap_name, args['configmaps'])


class ProjectUserResourceIngressesV2(MethodResource):
    @doc(tags=['K8s'], description="Get specific project k8s ingress list.")
    @marshal_with(router_model.ProjectUserResourceIngressesResponse)
    @jwt_required
    def get(self, project_id):
        role.require_in_project(
            project_id, "Error while getting project info.")
        return project.get_kubernetes_namespace_ingresses(project_id)


class ProjectUserResourceIngresses(Resource):
    @jwt_required
    def get(self, project_id):
        role.require_in_project(
            project_id, "Error while getting project info.")
        return project.get_kubernetes_namespace_ingresses(project_id)