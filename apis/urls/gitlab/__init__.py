from . import view


def gitlab_url(api, add_resource):
    api.add_resource(view.GitProjectBranches, "/repositories/<repository_id>/branches")
    api.add_resource(view.GitProjectBranchesV2, "/v2/repositories/<repository_id>/branches")
    add_resource(view.GitProjectBranchesV2, "public")

    api.add_resource(
        view.GitProjectFile,
        "/repositories/<repository_id>/branch/files",
        "/repositories/<repository_id>/branch/<branch_name>/files/<file_path>",
    )

    api.add_resource(
        view.GitProjectRepositories,
        "/repositories/<repository_id>/branch/<branch_name>/tree",
    )
    api.add_resource(
        view.GitProjectRepositoriesV2,
        "/v2/repositories/<repository_id>/branch/<branch_name>/tree",
    )
    add_resource(view.GitProjectRepositoriesV2, "public")
