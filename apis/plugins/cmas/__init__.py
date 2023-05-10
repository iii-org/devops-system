from . import cmas_main

ui_route = ["Cmas"]

# --------------------- API router ---------------------


def router(api, add_resource):
    api.add_resource(cmas_main.CMASTasksV2, "/v2/repo_project/<sint:repository_id>/cmas")
    add_resource(cmas_main.CMASTasksV2, "public")
    api.add_resource(cmas_main.CMASTaskV2, "/v2/cmas")
    add_resource(cmas_main.CMASTaskV2, "public")
    api.add_resource(cmas_main.CMASRemoteV2, "/v2/cmas/<string:task_id>")
    add_resource(cmas_main.CMASRemoteV2, "public")
    api.add_resource(cmas_main.CMASDonwloadV2, "/v2/cmas/<string:task_id>/<string:file_type>")
    add_resource(cmas_main.CMASDonwloadV2, "public")
    api.add_resource(cmas_main.CMASSecretV2, "/v2/cmas/secret")
    add_resource(cmas_main.CMASSecretV2, "public")
    api.add_resource(cmas_main.CMASAPKREmoveV2, "/v2/cmas/apk_remove")
    add_resource(cmas_main.CMASAPKREmoveV2, "public")
