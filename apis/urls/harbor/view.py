import nexus
import util
from flask_apispec import doc, marshal_with, use_kwargs
from flask_apispec.views import MethodResource
from flask_jwt_extended import jwt_required
from flask_restful import Resource, reqparse
from resources import role
from resources.harbor import (hb_copy_artifact_and_retage,
                              hb_create_artifact_tag, hb_create_registries,
                              hb_create_replication_policy,
                              hb_delete_artifact_tag, hb_delete_registries,
                              hb_delete_replication_policy,
                              hb_delete_repository,
                              hb_execute_replication_policy,
                              hb_get_project_summary, hb_get_registries,
                              hb_get_replication_execution_task,
                              hb_get_replication_executions,
                              hb_get_replication_executions_tasks_log,
                              hb_get_replication_policies,
                              hb_get_replication_policy, hb_list_artifacts,
                              hb_list_repositories, hb_ping_registries,
                              hb_put_registries, hb_put_replication_policy,
                              hb_update_repository, harbor_scan)

from . import router_model


def extract_names():
    parser = reqparse.RequestParser()
    parser.add_argument('repository_fullname', type=str)
    args = parser.parse_args()
    name = args['repository_fullname']
    names = name.split('/')
    return names[0], '/'.join(names[1:])


class HarborRepository(Resource):
    @jwt_required
    def get(self, nexus_project_id):
        role.require_in_project(nexus_project_id)
        project_name = nexus.nx_get_project(id=nexus_project_id).name
        return util.success(hb_list_repositories(project_name))

    @jwt_required
    def put(self):
        project_name, repository_name = extract_names()
        role.require_in_project(project_name=project_name)
        parser = reqparse.RequestParser()
        parser.add_argument('description', type=str)
        args = parser.parse_args()
        hb_update_repository(project_name, repository_name, args)
        return util.success()

    @jwt_required
    def delete(self):
        project_name, repository_name = extract_names()
        role.require_in_project(project_name=project_name)
        hb_delete_repository(project_name, repository_name)
        return util.success()


def check_tag_name(artifacts, tag_name):
    output = []
    if artifacts is None:
        return artifacts
    for artifact in artifacts:
        if artifact.get('name') == tag_name:
            output.append(artifact)
    return output


class HarborArtifact(Resource):
    @jwt_required
    def get(self):
        project_name, repository_name = extract_names()
        role.require_in_project(project_name=project_name)
        parser = reqparse.RequestParser()
        parser.add_argument('repository_fullname', type=str)
        parser.add_argument('tag_name', type=str)
        args = parser.parse_args()
        artifacts = hb_list_artifacts(project_name, repository_name)
        if args.get('tag_name', None) is not None:
            return util.success(check_tag_name(artifacts, args.get('tag_name')))
        else:
            return util.success(artifacts)

    @jwt_required
    def delete(self):
        project_name, repository_name = extract_names()
        role.require_in_project(project_name=project_name)
        parser = reqparse.RequestParser()
        parser.add_argument('digest', type=str)
        parser.add_argument('tag_name', type=str)
        args = parser.parse_args()
        hb_delete_artifact_tag(project_name, repository_name,
                               args['digest'], args['tag_name'])
        return util.success()


class HarborProject(Resource):
    @jwt_required
    def get(self, nexus_project_id):
        role.require_in_project(nexus_project_id)
        project_id = nexus.nx_get_project_plugin_relation(
            nexus_project_id=nexus_project_id).harbor_project_id
        return util.success(hb_get_project_summary(project_id))


class HarborRegistry(Resource):
    @jwt_required
    def get(self, registry_id):
        role.require_admin()
        return util.success(hb_get_registries(registry_id))

    @jwt_required
    def put(self, registry_id):
        role.require_admin()
        parser = reqparse.RequestParser()
        parser.add_argument('name', type=str, required=True)
        parser.add_argument('type', type=str, required=True)
        parser.add_argument('access_key', type=str, required=True)
        parser.add_argument('access_secret', type=str, required=True)
        parser.add_argument('location', type=str, required=False)
        parser.add_argument('login_server', type=str, required=False)
        parser.add_argument('description', type=str)
        parser.add_argument('insecure', type=bool)
        parser.add_argument('disabled', type=bool)
        args = parser.parse_args()
        return util.success({'registry_id': hb_put_registries(registry_id, args)})

    @jwt_required
    def delete(self, registry_id):
        role.require_admin()
        hb_delete_registries(registry_id)
        return util.success()


class HarborRegistries(Resource):
    @jwt_required
    def get(self):
        return util.success(hb_get_registries())

    @jwt_required
    def post(self):
        role.require_admin()
        parser = reqparse.RequestParser()
        parser.add_argument('name', type=str, required=True)
        parser.add_argument('type', type=str, required=True)
        parser.add_argument('access_key', type=str, required=True)
        parser.add_argument('access_secret', type=str, required=True)
        parser.add_argument('location', type=str, required=False)
        parser.add_argument('login_server', type=str, required=False)
        parser.add_argument('description', type=str)
        parser.add_argument('insecure', type=bool)
        args = parser.parse_args()
        return util.success({'registry_id': hb_create_registries(args)})


class HarborRegistriesPing(Resource):
    @jwt_required
    def post(self):
        parser = reqparse.RequestParser()
        parser.add_argument('registries_id', type=str, required=True)
        args = parser.parse_args()
        hb_ping_registries(args)
        return util.success()


class HarborReplicationPolicy(Resource):
    @jwt_required
    def get(self, replication_policy_id):
        policies = hb_get_replication_policy(replication_policy_id)
        return util.success(policies)

    @jwt_required
    def put(self, replication_policy_id):
        parser = reqparse.RequestParser()
        parser.add_argument('policy_name', type=str, required=True)
        parser.add_argument('repo_name', type=str, required=True)
        parser.add_argument('image_name', type=str, required=True)
        parser.add_argument('tag_name', type=str, required=True)
        parser.add_argument('registry_id', type=int, required=True)
        parser.add_argument('description', type=str, required=True)
        parser.add_argument('dest_repo_name', type=str, required=True)
        args = parser.parse_args()
        return util.success({'replication_policy_id': hb_put_replication_policy(args, replication_policy_id)})

    @jwt_required
    def delete(self, replication_policy_id):
        return util.success({'replication_policy_id': hb_delete_replication_policy(replication_policy_id)})


class HarborReplicationPolices(Resource):
    @jwt_required
    def get(self):
        parser = reqparse.RequestParser()
        parser.add_argument('name', type=str)
        args = parser.parse_args()
        policies = hb_get_replication_policies(args)
        return util.success(policies)

    @jwt_required
    def post(self):
        parser = reqparse.RequestParser()
        parser.add_argument('policy_name', type=str, required=True)
        parser.add_argument('repo_name', type=str, required=True)
        parser.add_argument('image_name', type=str, required=True)
        parser.add_argument('tag_name', type=str, required=True)
        parser.add_argument('registry_id', type=int, required=True)
        parser.add_argument('description', type=str, required=True)
        parser.add_argument('dest_repo_name', type=str, required=True)
        args = parser.parse_args()
        return util.success({'policy_id': hb_create_replication_policy(args)})


class HarborReplicationExecution(Resource):
    @jwt_required
    def post(self):
        parser = reqparse.RequestParser()
        parser.add_argument('policy_id', type=int)
        args = parser.parse_args()
        output = hb_execute_replication_policy(args.get('policy_id'))
        return util.success({'image_uri': output})

    @jwt_required
    def get(self):
        parser = reqparse.RequestParser()
        parser.add_argument('policy_id', type=int)
        args = parser.parse_args()
        output = hb_get_replication_executions(args.get('policy_id'))
        return util.success({'executions': output})


class HarborReplicationExecutionTasks(Resource):
    @jwt_required
    def get(self, execution_id):
        print(execution_id)
        output = hb_get_replication_execution_task(execution_id)
        return util.success({'task': output})


class HarborReplicationExecutionTaskLog(Resource):
    @jwt_required
    def get(self, execution_id, task_id):
        output = hb_get_replication_executions_tasks_log(execution_id, task_id)
        return util.success({'logs': output.text.splitlines()})


class HarborCopyImageRetage(Resource):
    @jwt_required
    def post(self):
        parser = reqparse.RequestParser()
        parser.add_argument('project_name', type=str, required=True)
        parser.add_argument('from_repo_name', type=str, required=True)
        parser.add_argument('dest_repo_name', type=str, required=True)
        parser.add_argument('from_tag', type=str, required=True)
        parser.add_argument('dest_tag', type=str, required=True)
        args = parser.parse_args()

        return util.success(
            hb_copy_artifact_and_retage(
                args["project_name"], args["from_repo_name"], args["dest_repo_name"], args["from_tag"], args["dest_tag"]))


@doc(tags=['Harbor Scan'], description='Create a harbor image scan record when pipeline execute')
class HarborScan(MethodResource):

    @use_kwargs(router_model.CreateTemplateFormProjectScheme, location=('form'))
    def post(self, project_name, **kwargs):
        harbor_scan.create_harbor_scan(project_name, kwargs.get("branch"), kwargs.get("commit_id"))
        return util.success()


@doc(tags=['Harbor Scan'], description='List harbor image scan by project')
class HarborScanList(MethodResource):
    @jwt_required
    def get(self, project_id):
        return util.success(harbor_scan.harbor_scan_list(project_id))
