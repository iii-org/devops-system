from . import cmas_main

ui_route = ["Cmas"]

# --------------------- API router ---------------------


def router(api, add_resource):
    api.add_resource(cmas_main.CMASTask, '/cmas', '/repo_project/<sint:repository_id>/cmas')
    api.add_resource(cmas_main.CMASRemote, '/cmas/<string:task_id>')
    api.add_resource(cmas_main.CMASDonwload, '/cmas/<string:task_id>/<string:file_type>')
    api.add_resource(cmas_main.CMASSecret, '/cmas/secret')
    api.add_resource(cmas_main.CMASAPKREmove, '/cmas/apk_remove')

