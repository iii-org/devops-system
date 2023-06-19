from flask_restful import Resource, reqparse
from resources.handler.jwt import get_jwt_identity, jwt_required
from flask_apispec.views import MethodResource
import util
from flask_apispec import marshal_with, doc, use_kwargs
from . import router_model, control
from resources.gitlab import gitlab


class GitProjectBranches(Resource):
    @jwt_required
    def get(self, repository_id):
        return util.success({"branch_list": gitlab.gl_get_branches(repository_id)})

    @jwt_required
    def post(self, repository_id):
        parser = reqparse.RequestParser()
        parser.add_argument("branch", type=str, required=True)
        parser.add_argument("ref", type=str, required=True)
        args = parser.parse_args()
        return util.success(gitlab.gl_create_branch(repository_id, args))


class GitProjectBranchesV2(MethodResource):
    @doc(tags=["Gitlab"], description="get all branches in project")
    @jwt_required
    @marshal_with(router_model.GitlabGetProjectBranchesRes)
    def get(self, repository_id):
        return util.success({"branch_list": gitlab.gl_get_branches(repository_id)})

    @doc(tags=["Gitlab"], description="add branch for the project")
    @jwt_required
    @use_kwargs(router_model.GitlabPostProjectBranchesSch, location="json")
    @marshal_with(router_model.GitlabPostProjectBranchesRes)
    def post(self, repository_id, **kwargs):
        return util.success(gitlab.gl_create_branch(repository_id, kwargs))


class GitProjectBranch(Resource):
    @jwt_required
    def get(self, repository_id, branch_name):
        control.role_require_in_repo_project(repository_id)
        return util.success(gitlab.gl_get_branch(repository_id, branch_name))

    @jwt_required
    def delete(self, repository_id, branch_name):
        control.role_require_in_repo_project(repository_id)
        gitlab.gl_delete_branch(repository_id, branch_name)
        return util.success()


class GitProjectBranchV2(MethodResource):
    @doc(tags=["Gitlab"], description="get project branch info")
    @jwt_required
    @marshal_with(router_model.GitlabGetProjectBranchRes)
    def get(self, repository_id, branch_name):
        control.role_require_in_repo_project(repository_id)
        return util.success(gitlab.gl_get_branch(repository_id, branch_name))

    @doc(tags=["Gitlab"], description="delete project branch")
    @jwt_required
    @marshal_with(util.CommonResponse)
    def delete(self, repository_id, branch_name):
        control.role_require_in_repo_project(repository_id)
        gitlab.gl_delete_branch(repository_id, branch_name)
        return util.success()


class GitProjectRepositories(Resource):
    @jwt_required
    def get(self, repository_id, branch_name):
        control.role_require_in_repo_project(repository_id)
        return util.success(gitlab.gl_get_repository_tree(repository_id, branch_name))


class GitProjectRepositoriesV2(MethodResource):
    @doc(tags=["Gitlab"], description="get branch file type")
    @jwt_required
    @marshal_with(router_model.GitGetProjectRepositoriesRes)
    def get(self, repository_id, branch_name):
        control.role_require_in_repo_project(repository_id)
        return util.success(gitlab.gl_get_repository_tree(repository_id, branch_name))


class GitProjectFile(Resource):
    @jwt_required
    def post(self, repository_id):
        control.role_require_in_repo_project(repository_id)
        parser = reqparse.RequestParser()
        parser.add_argument("branch", type=str, required=True)
        parser.add_argument("file_path", type=str, required=True)
        parser.add_argument("start_branch", type=str)
        parser.add_argument("author_email", type=str)
        parser.add_argument("author_name", type=str)
        parser.add_argument("encoding", type=str)
        parser.add_argument("content", type=str, required=True)
        parser.add_argument("commit_message", type=str, required=True)
        args = parser.parse_args()
        return gitlab.gl_add_file(repository_id, args)

    @jwt_required
    def put(self, repository_id):
        control.role_require_in_repo_project(repository_id)
        parser = reqparse.RequestParser()
        parser.add_argument("branch", type=str, required=True)
        parser.add_argument("file_path", type=str, required=True)
        parser.add_argument("start_branch", type=str)
        parser.add_argument("author_email", type=str)
        parser.add_argument("author_name", type=str)
        parser.add_argument("encoding", type=str)
        parser.add_argument("content", type=str, required=True)
        parser.add_argument("commit_message", type=str, required=True)
        args = parser.parse_args()
        return gitlab.gl_update_file(repository_id, args)

    @jwt_required
    def get(self, repository_id, branch_name, file_path):
        control.role_require_in_repo_project(repository_id)
        return gitlab.gl_get_file(repository_id, branch_name, file_path)

    @jwt_required
    def delete(self, repository_id, branch_name, file_path):
        control.role_require_in_repo_project(repository_id)
        parser = reqparse.RequestParser()
        parser.add_argument("commit_message", type=str, required=True, location="args")
        args = parser.parse_args()
        gitlab.gl_delete_file(repository_id, file_path, args, branch_name)
        return util.success()
