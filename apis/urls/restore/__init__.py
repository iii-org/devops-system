from . import view


def restore_url(api, add_resource):
    api.add_resource(view.UserRestoreFromJsonV2, "/v2/user/restore/json")
    add_resource(view.UserRestoreFromJsonV2, "public")
