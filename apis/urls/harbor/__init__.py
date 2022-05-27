from . import view


def harbor_url(api, add_resource):
    api.add_resource(view.HarborRepository,
                     '/harbor/projects/<int:nexus_project_id>',
                     '/harbor/repositories')
    api.add_resource(view.HarborArtifact,
                     '/harbor/artifacts')
    api.add_resource(view.HarborProject,
                     '/harbor/projects/<int:nexus_project_id>/summary')
    api.add_resource(view.HarborRegistries, '/harbor/registries')
    api.add_resource(view.HarborRegistry,
                     '/harbor/registries/<sint:registry_id>')
    api.add_resource(view.HarborReplicationPolices,
                     '/harbor/replication/policies')
    api.add_resource(view.HarborReplicationPolicy,
                     '/harbor/replication/policies/<sint:replication_policy_id>')
    api.add_resource(view.HarborReplicationExecution,
                     '/harbor/replication/executions')
    api.add_resource(view.HarborReplicationExecutionTasks,
                     '/harbor/replication/executions/<sint:execution_id>/tasks')
    api.add_resource(view.HarborReplicationExecutionTaskLog,
                     '/harbor/replication/executions/<sint:execution_id>/tasks/<sint:task_id>/log')
    api.add_resource(view.HarborCopyImageRetage, '/harbor/handle_image')

    api.add_resource(view.HarborScan, '/v2/harbor/<project_name>/scan')
    add_resource(view.HarborScan, "private")
    api.add_resource(view.HarborScanList, '/v2/harbor/<sint:project_id>/list')
    add_resource(view.HarborScanList, "private")
    api.add_resource(view.HarborScanReport, '/v2/harbor/<project_name>/scan/report')
    add_resource(view.HarborScanReport, "private")
