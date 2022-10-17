from . import sideex_main

ui_route = ["Sideex"]

# --------------------- API router ---------------------


def router(api, add_resource):
    api.add_resource(sideex_main.Sideex, '/sideex', '/project/<sint:project_id>/sideex')
    api.add_resource(sideex_main.SideexReport, '/sideex_report/<int:test_id>')
    api.add_resource(sideex_main.SideexJsonfileVariable, '/sideex/<sint:project_id>/jsonfile/varable')
    api.add_resource(sideex_main.SideexGenerateJsonfile, '/sideex/<sint:project_id>/jsonfile/generate')
    api.add_resource(sideex_main.SideexDeleteAllfile, '/sideex/<sint:project_id>/jsonfile/delete')
    api.add_resource(sideex_main.DownloadPictResult, '/sideex/<sint:project_id>/download/result')