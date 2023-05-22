import nexus
import util
from flask_apispec import doc, marshal_with, use_kwargs
from flask_apispec.views import MethodResource
from resources.handler.jwt import jwt_required
from flask_restful import Resource, reqparse
from resources import role
from resources.harbor import (
    hb_copy_artifact_and_re_tag,
    hb_create_registries,
    hb_create_replication_policy,
    hb_delete_artifact_tag,
    hb_delete_registries,
    hb_delete_replication_policy,
    hb_delete_repository,
    hb_execute_replication_policy,
    hb_get_project_summary,
    hb_get_registries,
    hb_get_replication_execution_task,
    hb_get_replication_executions,
    hb_get_replication_executions_tasks_log,
    hb_get_replication_policies,
    hb_get_replication_policy,
    hb_list_artifacts,
    hb_list_repositories,
    hb_ping_registries,
    hb_put_registries,
    hb_put_replication_policy,
    hb_update_repository,
    harbor_scan,
)

from . import router_model


def extract_names(repository_fullname: str = ""):
    # parser = reqparse.RequestParser()
    # parser.add_argument("repository_fullname", type=str, location=location)
    # args = parser.parse_args()
    # name = args["repository_fullname"]
    names = repository_fullname.split("/")
    return names[0], "/".join(names[1:])


class HarborRepositoriesV2(MethodResource):
    @doc(tags=["Harbor Repository"], description="Get Harbor Repositories.", security=util.security_params)
    @marshal_with(router_model.HarborRepositoryResponse)
    @jwt_required
    def get(self, nexus_project_id):
        role.require_in_project(nexus_project_id)
        project_name = nexus.nx_get_project(id=nexus_project_id).name
        return util.success(hb_list_repositories(project_name))


class HarborRepositoryV2(MethodResource):
    @doc(tags=["Harbor Repository"], description="Modified Harbor Repository.", security=util.security_params)
    @use_kwargs(router_model.HarborRepositoryPut, location=("json"))
    @jwt_required
    def put(self, **kwargs):
        project_name, repository_name = extract_names(kwargs.get("repository_fullname"))
        role.require_in_project(project_name=project_name)
        hb_update_repository(project_name, repository_name, kwargs)
        return util.success()

    @doc(tags=["Harbor Repository"], description="Delete Harbor Repository.", security=util.security_params)
    @use_kwargs(router_model.HarborRepositoryDel, location=("json"))
    @jwt_required
    def delete(self, **kwargs):
        project_name, repository_name = extract_names(kwargs.get("repository_fullname"))
        role.require_in_project(project_name=project_name)
        hb_delete_repository(project_name, repository_name)
        return util.success()


def check_tag_name(artifacts, tag_name):
    output = []
    if artifacts is None:
        return artifacts
    for artifact in artifacts:
        if artifact.get("name") == tag_name:
            output.append(artifact)
    return output


class HarborArtifactV2(MethodResource):
    @doc(tags=["Harbor Artifact"], description="Get Harbor Artifact.", security=util.security_params)
    @use_kwargs(router_model.HarborArtifactGet, location=("query"))
    @marshal_with(router_model.HarborArtifactResponse)
    @jwt_required
    def get(self, **kwargs):
        project_name, repository_name = extract_names(kwargs.get("repository_fullname"))
        role.require_in_project(project_name=project_name)
        artifacts = hb_list_artifacts(project_name, repository_name)
        if kwargs.get("tag_name", None) is not None:
            return util.success(check_tag_name(artifacts, kwargs.get("tag_name")))
        else:
            return util.success(artifacts)

    @doc(tags=["Harbor Artifact"], description="Delete Harbor Artifact.", security=util.security_params)
    @use_kwargs(router_model.HarborArtifactDel, location=("query"))
    @jwt_required
    def delete(self, **kwargs):
        project_name, repository_name = extract_names(kwargs.get("repository_fullname"))
        role.require_in_project(project_name=project_name)
        hb_delete_artifact_tag(project_name, repository_name, kwargs["digest"], kwargs["tag_name"])
        return util.success()


class HarborProjectV2(MethodResource):
    @doc(tags=["Harbor Project"], description="Get Harbor Project.", security=util.security_params)
    # @use_kwargs(router_model.HarborArtifactGet, location=("query"))
    @marshal_with(router_model.HarborProjectResponse)
    @jwt_required
    def get(self, nexus_project_id):
        role.require_in_project(nexus_project_id)
        project_id = nexus.nx_get_project_plugin_relation(nexus_project_id=nexus_project_id).harbor_project_id
        return util.success(hb_get_project_summary(project_id))


class HarborRegistryV2(MethodResource):
    @doc(tags=["Harbor Registry"], description="Get Harbor Registry.", security=util.security_params)
    # @use_kwargs(router_model.HarborArtifactGet, location=("query"))
    @marshal_with(router_model.HarborRegistryGetResponse)
    @jwt_required
    def get(self, registry_id):
        role.require_admin()
        return util.success(hb_get_registries(registry_id))

    @doc(tags=["Harbor Registry"], description="Put Harbor Registry.", security=util.security_params)
    @use_kwargs(router_model.HarborRegistryPut, location=("query"))
    @marshal_with(router_model.HarborRegistryPutResponse)
    @jwt_required
    def put(self, registry_id, **kwargs):
        role.require_admin()
        return util.success({"registry_id": hb_put_registries(registry_id, kwargs)})

    @doc(tags=["Harbor Registry"], description="Modified Harbor Registry.", security=util.security_params)
    # @use_kwargs(router_model.HarborRegistryPut, location=("query"))
    # @marshal_with(router_model.HarborRegistryDelResponse)
    @jwt_required
    def delete(self, registry_id):
        role.require_admin()
        hb_delete_registries(registry_id)
        return util.success()


class HarborRegistriesV2(MethodResource):
    @doc(tags=["Harbor Registry"], description="Get Harbor Registries.", security=util.security_params)
    # @use_kwargs(router_model.HarborRegistryPut, location=("args"))
    @marshal_with(router_model.HarborRegistriesGetResponse)
    @jwt_required
    def get(self):
        return util.success(hb_get_registries())

    @doc(tags=["Harbor Registry"], description="Add Harbor Registry.", security=util.security_params)
    @use_kwargs(router_model.HarborRegistryAdd)
    @marshal_with(router_model.HarborRegistryAddResponse)
    @jwt_required
    def post(self, **kwargs):
        role.require_admin()
        # parser = reqparse.RequestParser()
        # parser.add_argument("name", type=str, required=True)
        # parser.add_argument("type", type=str, required=True)
        # parser.add_argument("access_key", type=str, required=True)
        # parser.add_argument("access_secret", type=str, required=True)
        # parser.add_argument("location", type=str, required=False)
        # parser.add_argument("login_server", type=str, required=False)
        # parser.add_argument("description", type=str)
        # parser.add_argument("insecure", type=bool)
        # args = parser.parse_args()
        return util.success({"registry_id": hb_create_registries(kwargs)})


# class HarborRegistriesPing(Resource):
#     @doc(tags=["Harbor Registry"], description="Check Harbor Registry alive.", security=util.security_params)
#     @use_kwargs(router_model.HarborRegistryPing, location=("args"))
#     @marshal_with(router_model.HarborRegistryAddResponse)
#     @jwt_required
#     def post(self, **kwargs):
#         parser = reqparse.RequestParser()
#         parser.add_argument("registries_id", type=str, required=True)
#         args = parser.parse_args()
#         hb_ping_registries(kwargs)
#         return util.success()


class HarborReplicationPolicyV2(MethodResource):
    @doc(
        tags=["Harbor Replication Policy"], description="Get Harbor Replication Policy.", security=util.security_params
    )
    # @use_kwargs(router_model.HarborRegistryPing, location=("args"))
    @marshal_with(router_model.HarborReplicationPolicyResponse)
    @jwt_required
    def get(self, replication_policy_id):
        policies = hb_get_replication_policy(replication_policy_id)
        return util.success(policies)

    @doc(
        tags=["Harbor Replication Policy"],
        description="Modified Harbor Replication Policy.",
        security=util.security_params,
    )
    @use_kwargs(router_model.HarborReplicationPolicyPut)
    @marshal_with(router_model.HarborReplicationPolicyPutResponse)
    @jwt_required
    def put(self, replication_policy_id, **kwargs):
        # parser = reqparse.RequestParser()
        # parser.add_argument("policy_name", type=str, required=True)
        # parser.add_argument("repo_name", type=str, required=True)
        # parser.add_argument("image_name", type=str, required=True)
        # parser.add_argument("tag_name", type=str, required=True)
        # parser.add_argument("registry_id", type=int, required=True)
        # parser.add_argument("description", type=str, required=True)
        # parser.add_argument("dest_repo_name", type=str, required=True)
        # args = parser.parse_args()
        return util.success({"replication_policy_id": hb_put_replication_policy(kwargs, replication_policy_id)})

    @doc(
        tags=["Harbor Replication Policy"],
        description="Delete Harbor Replication Policy.",
        security=util.security_params,
    )
    # @use_kwargs(router_model.HarborReplicationPolicyPut, location=("args"))
    @marshal_with(router_model.HarborReplicationPolicyDelResponse)
    @jwt_required
    def delete(self, replication_policy_id):
        return util.success({"replication_policy_id": hb_delete_replication_policy(replication_policy_id)})


class HarborReplicationPolicesV2(MethodResource):
    @doc(
        tags=["Harbor Replication Policy"],
        description="Get Harbor Replication Policies.",
        security=util.security_params,
    )
    @use_kwargs(router_model.HarborReplicationPolicesGet, location=("query"))
    @marshal_with(router_model.HarborReplicationPolicesResponse)
    @jwt_required
    def get(self, **kwargs):
        # parser = reqparse.RequestParser()
        # parser.add_argument("name", type=str, location="args")
        # args = parser.parse_args()
        policies = hb_get_replication_policies(kwargs)
        return util.success(policies)

    @doc(
        tags=["Harbor Replication Policy"],
        description="Get Harbor Replication Policies.",
        security=util.security_params,
    )
    @use_kwargs(router_model.HarborReplicationPolicyAdd)
    @marshal_with(router_model.HarborReplicationPolicyAddResponse)
    @jwt_required
    def post(self, **kwargs):
        # parser = reqparse.RequestParser()
        # parser.add_argument("policy_name", type=str, required=True)
        # parser.add_argument("repo_name", type=str, required=True)
        # parser.add_argument("image_name", type=str, required=True)
        # parser.add_argument("tag_name", type=str, required=True)
        # parser.add_argument("registry_id", type=int, required=True)
        # parser.add_argument("description", type=str, required=True)
        # parser.add_argument("dest_repo_name", type=str, required=True)
        # args = parser.parse_args()
        return util.success({"policy_id": hb_create_replication_policy(kwargs)})


class HarborReplicationExecutionV2(MethodResource):
    @doc(
        tags=["Harbor Replication Execution"],
        description="Execution Harbor Replication Policy.",
        security=util.security_params,
    )
    @use_kwargs(router_model.HarborReplicationExecution)
    @marshal_with(router_model.HarborReplicationExecutionResponse)
    @jwt_required
    def post(self, **kwargs):
        # parser = reqparse.RequestParser()
        # parser.add_argument("policy_id", type=int)
        # args = parser.parse_args()
        output = hb_execute_replication_policy(kwargs.get("policy_id"))
        return util.success({"image_uri": output})

    @doc(
        tags=["Harbor Replication Execution"],
        description="Get Harbor Replication Policy Execution.",
        security=util.security_params,
    )
    @use_kwargs(router_model.HarborReplicationExecution, location=("query"))
    @marshal_with(router_model.HarborReplicationExecutionGetResponse)
    @jwt_required
    def get(self, **kwargs):
        # parser = reqparse.RequestParser()
        # parser.add_argument("policy_id", type=int, location="args")
        # args = parser.parse_args()
        output = hb_get_replication_executions(kwargs.get("policy_id"))
        return util.success({"executions": output})


class HarborReplicationExecutionTasksV2(MethodResource):
    @doc(
        tags=["Harbor Replication Execution"],
        description="Get Harbor Replication Policy Execution Tasks.",
        security=util.security_params,
    )
    # @use_kwargs(router_model.HarborReplicationExecution, location=("args"))
    @marshal_with(router_model.HarborReplicationExecutionTasksResponse)
    @jwt_required
    def get(self, execution_id):
        # print(execution_id)
        output = hb_get_replication_execution_task(execution_id)
        return util.success({"task": output})


class HarborReplicationExecutionTaskLogV2(MethodResource):
    @doc(
        tags=["Harbor Replication Execution"],
        description="Get Harbor Replication Policy Execution Tasks.",
        security=util.security_params,
    )
    # @use_kwargs(router_model.HarborReplicationExecution, location=("args"))
    @marshal_with(router_model.HarborReplicationExecutionTaskLogResponse)
    @jwt_required
    def get(self, execution_id, task_id):
        output = hb_get_replication_executions_tasks_log(execution_id, task_id)
        return util.success({"logs": output.text.splitlines()})


class HarborCopyImageReTagV2(MethodResource):
    @doc(
        tags=["Harbor Copy Image"],
        description="Get Harbor Replication Policy Execution Tasks.",
        security=util.security_params,
    )
    @use_kwargs(router_model.HarborCopyImageReTag, location=("form"))
    @marshal_with(router_model.HarborCopyImageReTagResponse)
    @jwt_required
    def post(self, **kwargs):
        # parser = reqparse.RequestParser()
        # parser.add_argument("project_name", type=str, required=True, location="form")
        # parser.add_argument("from_repo_name", type=str, required=True, location="form")
        # parser.add_argument("dest_repo_name", type=str, required=True, location="form")
        # parser.add_argument("from_tag", type=str, required=True, location="form")
        # parser.add_argument("dest_tag", type=str, required=True, location="form")
        # args = parser.parse_args()

        return util.success(
            hb_copy_artifact_and_re_tag(
                kwargs["project_name"],
                kwargs["from_repo_name"],
                kwargs["dest_repo_name"],
                kwargs["from_tag"],
                kwargs["dest_tag"],
            )
        )


@doc(
    tags=["Harbor Scan"],
    description="Create a harbor image scan record when pipeline execute",
)
class HarborScanV2(MethodResource):
    @use_kwargs(router_model.CreateHarborScan, location=("form"))
    def post(self, project_name, **kwargs):
        harbor_scan.create_harbor_scan(project_name, kwargs.get("branch"), kwargs.get("commit_id"))
        return util.success()


@doc(tags=["Harbor Scan"], description="Get harbor scan report")
class HarborScanReportV2(MethodResource):
    @use_kwargs(router_model.CreateHarborScan, location=("query"))
    def get(self, project_name, **kwargs):
        return util.success(
            harbor_scan.get_harbor_scan_report(project_name, kwargs.get("branch"), kwargs.get("commit_id"))
        )


@doc(tags=["Harbor Scan"], description="List harbor image scan by project")
class HarborScanListV2(MethodResource):
    @use_kwargs(router_model.HarborScanList, location="query")
    @jwt_required
    def get(self, project_id, **kwargs):
        return util.success(harbor_scan.harbor_scan_list(project_id, kwargs))
