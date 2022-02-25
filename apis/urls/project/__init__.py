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

    # Issues by Project
    api.add_resource(view.IssueByProject, '/project/<sint:project_id>/issues')
    api.add_resource(view.IssueByProjectV2, '/v2/project/<sint:project_id>/issues')
    add_resource(view.IssueByProjectV2, 'public')

    api.add_resource(view.IssueByTreeByProject, '/project/<sint:project_id>/issues_by_tree')
    api.add_resource(view.IssueByTreeByProjectV2, '/v2/project/<sint:project_id>/issues_by_tree')
    add_resource(view.IssueByTreeByProjectV2, "public")

    api.add_resource(view.IssueByStatusByProject, '/project/<sint:project_id>/issues_by_status')
    api.add_resource(view.IssueByStatusByProjectV2, '/v2/project/<sint:project_id>/issues_by_status')
    add_resource(view.IssueByStatusByProjectV2, "public")

    api.add_resource(view.IssuesProgressByProject, '/project/<sint:project_id>/issues_progress')
    api.add_resource(view.IssuesProgressByProjectV2, '/v2/project/<sint:project_id>/issues_progress')
    add_resource(view.IssuesProgressByProjectV2, "public")

    api.add_resource(view.IssuesStatisticsByProject, '/project/<sint:project_id>/issues_statistics')
    api.add_resource(view.IssuesStatisticsByProjectV2, '/v2/project/<sint:project_id>/issues_statistics')
    add_resource(view.IssuesStatisticsByProjectV2, "public")

    api.add_resource(view.IssueByDateByProject, '/project/<sint:project_id>/issues_by_date')
    api.add_resource(view.IssueByDateByProjectV2, '/v2/project/<sint:project_id>/issues_by_date')
    add_resource(view.IssueByDateByProjectV2, 'public')