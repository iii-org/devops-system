from . import view


def backup_url(api, add_resource):
    api.add_resource(view.UserBackupToJsonV2, "/v2/user/backup/json")
    add_resource(view.UserBackupToJsonV2, "public")

    api.add_resource(view.ProjectBackupToJsonV2, "/v2/project/backup/json")
    add_resource(view.ProjectBackupToJsonV2, "public")
