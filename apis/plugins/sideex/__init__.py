from . import sideex_main

ui_route = ["Sideex"]

# --------------------- API router ---------------------


def router(api, add_resource):
    api.add_resource(sideex_main.Sideex, '/sideex', '/project/<sint:project_id>/sideex')
    api.add_resource(sideex_main.SideexReport, '/sideex_report/<int:test_id>')
    api.add_resource(sideex_main.SideexJsonfileVariable, '/sideex/<sint:project_id>/jsonfile/varable')
    api.add_resource(sideex_main.SideexGenerateJsonfile, '/sideex/<sint:project_id>/jsonfile/generate')
    api.add_resource(sideex_main.SideexDeleteAllfile, '/sideex/<sint:project_id>/jsonfile/delete')
    api.add_resource(sideex_main.HistoryPictResult, '/sideex/<sint:project_id>/history/result')
    api.add_resource(sideex_main.GenerateResult, '/sideex/<sint:project_id>/generate_result')
    api.add_resource(sideex_main.PictStatus, '/sideex/<sint:project_id>/pict/status')
    api.add_resource(sideex_main.CheckResultFileExist, '/sideex/<sint:project_id>/result/exist')