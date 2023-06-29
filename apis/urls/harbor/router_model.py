from marshmallow import Schema, fields
from util import CommonBasicResponse


class CreateHarborScan(Schema):
    branch = fields.Str(required=True, description="Branch name", example="master")
    commit_id = fields.Str(required=True, description="Commit short id", example="d45736e4")


class HarborScanList(Schema):
    per_page = fields.Int(required=False, description="Show how many items at one page", example="10")
    page = fields.Int(required=False, description="Page number", example="1")
    search = fields.Str(required=False, description="params", example="master")


class HarborRepositoryResponse(CommonBasicResponse):
    data = fields.Raw(
        example=[
            {
                "artifact_count": 0,
                "creation_time": "2023-05-04T03:23:57.848Z",
                "id": 2,
                "name": "dockerhub/library/alpine",
                "project_id": 2,
                "pull_count": 3,
                "update_time": "2023-05-04T03:27:25.298Z"
            }
        ]
    )


class HarborRepositoryPut(Schema):
    repository_fullname = fields.Str(required=False, description="Repository name", example="dockerhub/library/alpine")
    description = fields.Str(required=False, description="Repository description", example="Repository description")


class HarborRepositoryDel(Schema):
    repository_fullname = fields.Str(required=True, description="Repository name", example="dockerhub/library/alpine")


class HarborArtifactGet(Schema):
    repository_fullname = fields.Str(required=True, description="Repository name", example="dockerhub/library/alpine")
    tag_name = fields.Str(required=False, description="Image tag name", example="latest")


class HarborArtifactResponse(CommonBasicResponse):
    data = fields.Raw(
        example=[
            {
                "artifact_id": 1,
                "tag_id": 1,
                "name": "latest",
                "size": 3548,
                "vulnerabilities": "",
                "digest": "sha256:29f11cf76554d36c15f564e85a7982906fa81443fb197d02ecd5c50eabe9601a",
                "labels": "labels",
                "push_time": "2023-05-05T10:20:47.802Z",
            }
        ]
    )


class HarborArtifactDel(Schema):
    repository_fullname = fields.Str(required=True, description="Repository name", example="dockerhub/library/alpine")
    tag_name = fields.Str(required=True, description="Image tag name", example="latest")
    digest = fields.Str(required=True, description="Image tag name", example="latest")


class HarborProjectResponse(CommonBasicResponse):
    data = fields.Raw(
        example={
            "registry": {
                "creation_time": "2023-05-03T07:38:00.281Z",
                "description": "Default Harbor Project Proxy Cache",
                "id": 1,
                "name": "dockerhub",
                "status": "healthy",
                "type": "docker-hub",
                "update_time": "2023-05-05T10:08:20.162Z",
                "url": "https://hub.docker.com"
            },
            "repo_count": 4
        }
    )


class HarborRegistryGetResponse(CommonBasicResponse):
    data = fields.Raw(
        example=[
            {
                "creation_time": "2023-05-04T07:19:48.321Z",
                "credential": {},
                "description": "Default Harbor Project Proxy Cache",
                "id": 8,
                "name": "dockerhub-test",
                "status": "healthy",
                "type": "docker-hub",
                "update_time": "2023-05-04T07:19:48.321Z",
                "url": "https://hub.docker.com"
            }
        ]
    )


class HarborRegistryPut(Schema):
    name = fields.Str(required=True, description="Project name", example="dockerhub")
    type = fields.Str(required=True, description="Project type", example="harbor")
    access_key = fields.Str(required=True, description="Registry Access Key", example="access102938c")
    access_secret = fields.Str(required=True, description="Registry Access Secret", example="access$dsfhj8938")
    location = fields.Str(required=False, description="When Registry Type is aws-ecr, Project Location",
                          example="project_path")
    login_server = fields.Str(required=False, description="Repository Server", example="https://hub/docker.com")
    description = fields.Str(required=False, description="Registry Description",
                             example="Default Harbor Project Proxy Cache")
    insecure = fields.Bool(required=False, description="Repository have secure", example=True)
    disabled = fields.Bool(required=False, description="Repository Disabled", example=False)


class HarborRegistryPutResponse(CommonBasicResponse):
    data = fields.Dict(example={"registry_id": 1})


class HarborRegistriesGetResponse(CommonBasicResponse):
    data = fields.Dict(
        example={
            "creation_time": "2023-05-04T07:19:48.321Z",
            "credential": {},
            "description": "Default Harbor Project Proxy Cache",
            "id": 8,
            "name": "dockerhub-test",
            "status": "healthy",
            "type": "docker-hub",
            "update_time": "2023-05-04T07:19:48.321Z",
            "url": "https://hub.docker.com"
        }
    )


class HarborRegistryAdd(Schema):
    name = fields.Str(required=True, description="Project name", example="dockerhub")
    type = fields.Str(required=True, description="Project type", example="harbor")
    access_key = fields.Str(required=True, description="Registry Access Key", example="access102938c")
    access_secret = fields.Str(required=True, description="Registry Access Secret", example="access$dsfhj8938")
    location = fields.Str(required=False, description="When Registry Type is aws-ecr, Project Location",
                          example="project_path")
    login_server = fields.Str(required=False, description="Repository Server", example="https://hub/docker.com")
    description = fields.Str(required=False, description="Registry Description",
                             example="Default Harbor Project Proxy Cache")
    insecure = fields.Bool(required=False, description="Repository have secure", example=True)


class HarborRegistryAddResponse(CommonBasicResponse):
    data = fields.Dict(example={"registry_id": 1})


class HarborReplicationPolicyResponse(CommonBasicResponse):
    data = fields.Dict(
        example={
            "copy_by_chunk": False,
            "creation_time": "2023-05-08T09:23:12.084Z",
            "description": "policy test",
            "dest_namespace": "dest_repo_name",
            "dest_namespace_replace_count": -1,
            "dest_registry": {
                "creation_time": "2023-05-04T07:19:48.321Z",
                "credential": {},
                "description": "Default Harbor Project Proxy Cache",
                "id": 8,
                "name": "dockerhub-test",
                "status": "healthy",
                "type": "docker-hub",
                "update_time": "2023-05-04T07:19:48.321Z",
                "url": "https://hub.docker.com"
            },
            "enabled": True,
            "filters": None,
            "id": 2,
            "name": "policy_test",
            "override": True,
            "speed": 0,
            "src_registry": {
                "creation_time": "0001-01-01T00:00:00.000Z",
                "credential": {
                    "access_secret": "*****",
                    "type": "secret"
                },
                "id": 0,
                "insecure": True,
                "name": "Local",
                "status": "healthy",
                "type": "harbor",
                "update_time": "0001-01-01T00:00:00.000Z",
                "url": "http://harbor-core:80"
            },
            "trigger": {
                "trigger_settings": {},
                "type": "manual"
            },
            "update_time": "2023-05-08T09:23:12.084Z"
        }
    )


class HarborReplicationPolicyPut(Schema):
    policy_name = fields.Str(required=True, description="Policy name", example="policy_test")
    repo_name = fields.Str(required=True, description="Project name", example="dockerhub")
    image_name = fields.Str(required=True, description="Image name", example="alpine")
    tag_name = fields.Str(required=True, description="Tag name", example="latest")
    registry_id = fields.Int(required=True, description="Registry id", example=1)
    description = fields.Str(required=True, description="Project name", example="policy test")
    dest_repo_name = fields.Str(required=True, description="Project name", example="dest_repo_name")


class HarborReplicationPolicyPutResponse(CommonBasicResponse):
    data = fields.Dict(example={"replication_policy_id": 1})


class HarborReplicationPolicyDelResponse(CommonBasicResponse):
    data = fields.Dict(example={"replication_policy_id": 1})


class HarborReplicationPolicesGet(Schema):
    name = fields.Str(required=False, description="Policy name", example="policy_test")


class HarborReplicationPolicesResponse(CommonBasicResponse):
    data = fields.Raw(
        example=[
            {
                "copy_by_chunk": False,
                "creation_time": "2023-05-08T09:23:12.084Z",
                "description": "policy test",
                "dest_namespace": "dest_repo_name",
                "dest_namespace_replace_count": -1,
                "dest_registry": {
                    "creation_time": "2023-05-04T07:19:48.321Z",
                    "credential": {},
                    "description": "Default Harbor Project Proxy Cache",
                    "id": 8,
                    "name": "dockerhub-test",
                    "status": "healthy",
                    "type": "docker-hub",
                    "update_time": "2023-05-04T07:19:48.321Z",
                    "url": "https://hub.docker.com"
                },
                "enabled": True,
                "filters": None,
                "id": 2,
                "name": "policy_test",
                "override": True,
                "speed": 0,
                "src_registry": {
                    "creation_time": "0001-01-01T00:00:00.000Z",
                    "credential": {
                        "access_secret": "*****",
                        "type": "secret"
                    },
                    "id": 0,
                    "insecure": True,
                    "name": "Local",
                    "status": "healthy",
                    "type": "harbor",
                    "update_time": "0001-01-01T00:00:00.000Z",
                    "url": "http://harbor-core:80"
                },
                "trigger": {
                    "trigger_settings": {},
                    "type": "manual"
                },
                "update_time": "2023-05-08T09:23:12.084Z"
            }
        ]
    )


class HarborReplicationPolicyAdd(Schema):
    policy_name = fields.Str(required=True, description="Policy name", example="policy_test")
    repo_name = fields.Str(required=True, description="Project name", example="dockerhub")
    image_name = fields.Str(required=True, description="Image name", example="alpine")
    tag_name = fields.Str(required=True, description="Tag name", example="latest")
    registry_id = fields.Int(required=True, description="Registry id", example=1)
    description = fields.Str(required=True, description="Project name", example="policy test")
    dest_repo_name = fields.Str(required=True, description="Project name", example="dest_repo_name")


class HarborReplicationPolicyAddResponse(CommonBasicResponse):
    data = fields.Dict(example={"policy_id": 1})


class HarborReplicationExecution(Schema):
    policy_name = fields.Str(required=True, description="Policy name", example="policy_test")


class HarborReplicationExecutionResponse(CommonBasicResponse):
    data = fields.Dict(example={"image_url": "https://hub.docker.com/dest_repo_name/dockerhub:master"})


class HarborReplicationExecutionGetResponse(CommonBasicResponse):
    data = fields.Dict(
        example={
            "executions": [
                {
                    "end_time": "2023-05-09T02:16:35.219Z",
                    "failed": 0,
                    "id": 347,
                    "in_progress": 0,
                    "policy_id": 2,
                    "start_time": "2023-05-09T02:16:32.765Z",
                    "status": "Failed",
                    "status_text": "failed to do the prepare work for pushing/uploading resources: create namespace 'dest_repo_name' in DockerHub error: 401 -- {\"message\":\"unauthorized\",\"errinfo\":{}}\n",
                    "stopped": 0,
                    "succeed": 0,
                    "total": 0,
                    "trigger": "manual"
                }
            ]
        }
    )


class HarborReplicationExecutionTasksResponse(CommonBasicResponse):
    data = fields.Dict(example={"task": []})


class HarborReplicationExecutionTaskLogResponse(CommonBasicResponse):
    data = fields.Dict(example={"logs": [""]})


class HarborCopyImageReTag(Schema):
    project_name = fields.Str(required=True, description="Project name", example="dockerhub")
    from_repo_name = fields.Str(required=True, description="Source repo name", example="source")
    dest_repo_name = fields.Str(required=True, description="Destination repo name", example="destination")
    from_tag = fields.Str(required=True, description="Policy name", example="master")
    dest_tag = fields.Str(required=True, description="Policy name", example="master")


class HarborCopyImageReTagResponse(CommonBasicResponse):
    data = None


class HarborImageAutoDel(Schema):
    project_name = fields.Str(required=False, description="project_name", example="project-name")
    keep_image_count = fields.Int(required=False, description="keep_image_count", example="3")
