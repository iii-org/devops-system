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

    # Issue filter by project
    api.add_resource(view.IssueFilterByProject, '/project/<sint:project_id>/issue_filter',
                 '/project/<sint:project_id>/issue_filter/<custom_filter_id>')
    api.add_resource(view.IssueFilterByProjectV2, '/v2/project/<sint:project_id>/issue_filter')
    add_resource(view.IssueFilterByProjectV2, 'public')
    api.add_resource(
        view.IssueFilterByProjectWithFilterIDV2, '/v2/project/<sint:project_id>/issue_filter/<custom_filter_id>')
    add_resource(view.IssueFilterByProjectWithFilterIDV2, 'public')

    # Download project's issue as excel
    api.add_resource(view.DownloadProject,
                 '/project/<sint:project_id>/download/execute',
                 '/project/<sint:project_id>/download/is_exist',
                 '/project/<sint:project_id>/download')
    api.add_resource(view.DownloadProjectExecuteV2, '/v2/project/<sint:project_id>/download/execute')
    add_resource(view.DownloadProjectExecuteV2, "public")
    api.add_resource(view.DownloadProjectIsExistV2, '/v2/project/<sint:project_id>/download/is_exist')
    add_resource(view.DownloadProjectIsExistV2, "public")          
    api.add_resource(view.DownloadProjectV2, '/v2/project/<sint:project_id>/download')
    add_resource(view.DownloadProjectV2, "public")         

    # List project
    api.add_resource(view.ListMyProjects, '/project/list')
    api.add_resource(view.ListMyProjectsV2, '/v2/project/list')
    add_resource(view.ListMyProjectsV2, 'public')

    api.add_resource(view.CalculateProjectIssues, '/project/list/caculate')
    api.add_resource(view.CalculateProjectIssuesV2, '/v2/project/list/caculate')
    add_resource(view.CalculateProjectIssuesV2, 'public')

    api.add_resource(view.ListProjectsByUser, '/projects_by_user/<int:user_id>')
    api.add_resource(view.ListProjectsByUserV2, '/v2/projects_by_user/<int:user_id>')
    add_resource(view.ListProjectsByUserV2, 'public')

    # Single project
    api.add_resource(view.SingleProject, '/project', '/project/<sint:project_id>')
    api.add_resource(view.SingleProjectV2, '/v2/project/<sint:project_id>')
    add_resource(view.SingleProjectV2, 'public')
    api.add_resource(view.SingleProjectCreateV2, '/v2/project')
    add_resource(view.SingleProjectCreateV2, 'public')
    
    api.add_resource(view.SingleProjectByName, '/project_by_name/<project_name>')
    api.add_resource(view.SingleProjectByNameV2, '/v2/project_by_name/<project_name>')
    add_resource(view.SingleProjectByNameV2, 'public')

    # Project member
    api.add_resource(view.ProjectMember, '/project/<sint:project_id>/member',
                 '/project/<sint:project_id>/member/<int:user_id>')
    api.add_resource(view.ProjectMemberV2, '/v2/project/<sint:project_id>/member')
    add_resource(view.ProjectMemberV2, 'public')
    api.add_resource(view.ProjectMemberDeleteV2, '/v2/project/<sint:project_id>/member/<int:user_id>')
    add_resource(view.ProjectMemberDeleteV2, 'public')

    api.add_resource(view.ProjectUserList, '/project/<sint:project_id>/user/list')
    api.add_resource(view.ProjectUserListV2, '/v2/project/<sint:project_id>/user/list')
    add_resource(view.ProjectUserListV2, 'public')

    # Project test results, reports, files
    api.add_resource(view.TestSummary, '/project/<sint:project_id>/test_summary')
    api.add_resource(view.TestSummaryV2, '/v2/project/<sint:project_id>/test_summary')
    add_resource(view.TestSummaryV2, 'public')
    
    api.add_resource(view.AllReports, '/project/<sint:project_id>/test_reports')
    api.add_resource(view.AllReportsV2, '/v2/project/<sint:project_id>/test_reports')
    add_resource(view.AllReportsV2, 'public')

    api.add_resource(view.ProjectFile, '/project/<sint:project_id>/file')
    api.add_resource(view.ProjectFileV2, '/v2/project/<sint:project_id>/file')
    add_resource(view.ProjectFileV2, 'public')

    # Project pulgin(k8s)
    api.add_resource(view.ProjectPluginUsage, '/project/<sint:project_id>/plugin/resource')
    api.add_resource(view.ProjectPluginUsageV2, '/v2/project/<sint:project_id>/plugin/resource')
    add_resource(view.ProjectPluginUsageV2, 'public')

    api.add_resource(view.ProjectUserResource, '/project/<sint:project_id>/resource')
    api.add_resource(view.ProjectUserResourceV2, '/v2/project/<sint:project_id>/resource')
    add_resource(view.ProjectUserResourceV2, 'public')

    api.add_resource(view.ProjectPluginPod, '/project/<sint:project_id>/plugin')
    api.add_resource(view.ProjectPluginPodV2, '/v2/project/<sint:project_id>/plugin')
    add_resource(view.ProjectPluginPodV2, 'public')

    api.add_resource(view.ProjectUserResourcePods, '/project/<sint:project_id>/resource/pods')
    api.add_resource(view.ProjectUserResourcePodsV2, '/v2/project/<sint:project_id>/resource/pods')
    add_resource(view.ProjectUserResourcePodsV2, 'public')

    api.add_resource(view.ProjectUserResourcePod, '/project/<sint:project_id>/resource/pods/<pod_name>')
    api.add_resource(view.ProjectUserResourcePodV2, '/v2/project/<sint:project_id>/resource/pods/<pod_name>')
    add_resource(view.ProjectUserResourcePodV2, 'public')

    api.add_resource(view.ProjectUserResourcePodLog, '/project/<sint:project_id>/resource/pods/<pod_name>/log')
    api.add_resource(view.ProjectUserResourcePodLogV2, '/v2/project/<sint:project_id>/resource/pods/<pod_name>/log')
    add_resource(view.ProjectUserResourcePodLogV2, 'public')

    api.add_resource(view.ProjectEnvironment, '/project/<sint:project_id>/environments',
                 '/project/<sint:project_id>/environments/branch/<branch_name>')
    api.add_resource(view.ProjectEnvironmentGetV2, '/v2/project/<sint:project_id>/environments')
    add_resource(view.ProjectEnvironmentGetV2, 'public')
    api.add_resource(view.ProjectEnvironmentV2,  '/v2/project/<sint:project_id>/environments/branch/<branch_name>')
    add_resource(view.ProjectEnvironmentV2, 'public')