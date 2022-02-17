from . import zap_main

ui_route = ["Zap"]
# --------------------- API router ---------------------


def router(api):
    api.add_resource(zap_main.Zap, '/zap', '/project/<sint:project_id>/zap')
