from . import view


def project_url(api, add_resource):
    # Project son relation
    api.add_resource(view.CheckhasSonProject, '/project/<sint:project_id>/has_son')
    api.add_resource(view.CheckhasSonProjectV2, '/v2/project/<sint:project_id>/has_son')
    add_resource(view.CheckhasSonProjectV2, "public")

    api.add_resource(view.GetProjectRootID, '/project/<sint:project_id>/root_project')
    api.add_resource(view.GetProjectRootIDV2, '/v2/project/<sint:project_id>/root_project')
    add_resource(view.GetProjectRootIDV2, "public")

    api.add_resource(view.SyncProjectRelation, '/project/sync_project_relation')
    api.add_resource(view.SyncProjectRelationV2, '/v2/project/sync_project_relation')
    add_resource(view.SyncProjectRelationV2, "public")

    api.add_resource(view.GetProjectFamilymembersByUser, '/project/<sint:project_id>/members')
    api.add_resource(view.GetProjectFamilymembersByUserV2, '/v2/project/<sint:project_id>/members')
    add_resource(view.GetProjectFamilymembersByUserV2, "public")

    