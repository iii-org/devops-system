import nexus
import util
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
                              hb_update_repository)


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


class HarborRelease():

    @jwt_required
    def get_list_artifacts(self, project_name, repository_name):
        return hb_list_artifacts(project_name, repository_name)

    def check_harbor_status(self, image, tag_name):
        output = 2
        if image is True and tag_name is True:
            output = 1
        elif image is True:
            output = 0
        return output

    def check_harbor_release(self, artifacts, tag_name, commit):
        output = {'check': False, 'tag': False, 'image': False,
                  "info": "", "target": {}, "errors": {}, "type": 2}

        for art in artifacts:
            #  Tag duplicate
            if art['name'] == tag_name:
                output['tag'] = True
                output['info'] = '{0} is exists in harbor'.format(tag_name)
                output['target']['duplicate'] = art
            #  Image Find
            if art['name'] == commit:
                output['image'] = True
                output['info'] = '{0} is exists in harbor'.format(commit)
                output['target']['release'] = art
        output['type'] = self.check_harbor_status(
            output['image'], output['tag'])
        if output['type'] == 0:
            output['check'] = True
        elif output['type'] == 2:
            output['info'] = '{0} image is not exists in harbor'.format(commit)
        return output

    def create(self, project_name, repository_name, reference, tag_name):
        return hb_create_artifact_tag(project_name, repository_name, reference, tag_name)

    def delete_harbor_tag(self, project_name, repository_name, hb_info):
        return hb_delete_artifact_tag(project_name, repository_name, hb_info['digest'], hb_info['name'])


hb_release = HarborRelease()
