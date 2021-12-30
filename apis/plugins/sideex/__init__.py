from . import sideex_main

# --------------------- API router ---------------------


def router(api):
    api.add_resource(sideex_main.Sideex, '/sideex', '/project/<sint:project_id>/sideex')
    api.add_resource(sideex_main.SideexReport, '/sideex_report/<int:test_id>')
