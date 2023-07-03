from . import view


def harbor_url(api, add_resource):
    api.add_resource(view.HarborRepositoriesV2, "/harbor/projects/<int:nexus_project_id>")
    add_resource(view.HarborRepositoriesV2, "public")
    api.add_resource(view.HarborRepositoryV2, "/harbor/repositories")
    add_resource(view.HarborRepositoryV2, "public")
    api.add_resource(view.HarborArtifactV2, "/harbor/artifacts")
    add_resource(view.HarborArtifactV2, "public")
    api.add_resource(view.HarborProjectV2, "/harbor/projects/<int:nexus_project_id>/summary")
    add_resource(view.HarborProjectV2, "public")
    api.add_resource(view.HarborRegistriesV2, "/harbor/registries")
    add_resource(view.HarborRegistriesV2, "public")
    api.add_resource(view.HarborRegistryV2, "/harbor/registries/<sint:registry_id>")
    add_resource(view.HarborRegistryV2, "public")
    api.add_resource(view.HarborReplicationPolicesV2, "/harbor/replication/policies")
    add_resource(view.HarborReplicationPolicesV2, "public")
    api.add_resource(
        view.HarborReplicationPolicyV2,
        "/harbor/replication/policies/<sint:replication_policy_id>",
    )
    add_resource(view.HarborReplicationPolicyV2, "public")
    api.add_resource(view.HarborReplicationExecutionV2, "/harbor/replication/executions")
    add_resource(view.HarborReplicationExecutionV2, "public")
    api.add_resource(
        view.HarborReplicationExecutionTasksV2,
        "/harbor/replication/executions/<sint:execution_id>/tasks",
    )
    add_resource(view.HarborReplicationExecutionTasksV2, "public")
    api.add_resource(
        view.HarborReplicationExecutionTaskLogV2,
        "/harbor/replication/executions/<sint:execution_id>/tasks/<sint:task_id>/log",
    )
    add_resource(view.HarborReplicationExecutionTaskLogV2, "public")
    api.add_resource(view.HarborCopyImageReTagV2, "/harbor/handle_image")
    add_resource(view.HarborCopyImageReTagV2, "public")

    api.add_resource(view.HarborScanV2, "/v2/harbor/<project_name>/scan")
    add_resource(view.HarborScanV2, "private")
    api.add_resource(view.HarborScanListV2, "/v2/harbor/<sint:project_id>/list")
    add_resource(view.HarborScanListV2, "private")
    api.add_resource(view.HarborScanReportV2, "/v2/harbor/<project_name>/scan/report")
    add_resource(view.HarborScanReportV2, "private")

    api.add_resource(view.HarborImageAutoDel, "/v2/harbor/image/auto/del")
    add_resource(view.HarborImageAutoDel, "private")
