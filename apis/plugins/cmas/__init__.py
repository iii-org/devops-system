from . import cmas_main

ui_route = ["Cmas"]

# --------------------- API router ---------------------


def router(api):
    api.add_resource(cmas_main.CMASTask, '/cmas', '/repo_project/<sint:repository_id>/cmas')
    api.add_resource(cmas_main.CMASRemote, '/cmas/<string:task_id>')
    api.add_resource(cmas_main.CMASDonwload, '/cmas/<string:task_id>/<string:file_type>')
    api.add_resource(cmas_main.CMASSecret, '/cmas/secret')
