from . import zap_main

# --------------------- API router ---------------------


def router(api):
    api.add_resource(zap_main.Zap, '/zap', '/project/<sint:project_id>/zap')
