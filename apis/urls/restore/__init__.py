from . import view


def restore_url(api, add_resource):
    api.add_resource(view.UserRestoreFromJsonV2, "/v2/user/restore/json")
    add_resource(view.UserRestoreFromJsonV2, "public")

    api.add_resource(view.ProjectRestoreFromJsonV2, "/v2/project/restore/json")
    add_resource(view.ProjectRestoreFromJsonV2, "public")
