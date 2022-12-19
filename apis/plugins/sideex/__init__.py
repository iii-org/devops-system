from . import sideex_main

ui_route = ["Sideex"]

# --------------------- API router ---------------------


def router(api, add_resource):
    api.add_resource(sideex_main.Sideex, '/sideex', '/project/<sint:project_id>/sideex')
    api.add_resource(sideex_main.SideexReport, '/sideex_report/<int:test_id>')
    api.add_resource(sideex_main.SideexV2, '/v2/project/<sint:project_id>/sideex')
    add_resource(sideex_main.SideexV2, "public")
    api.add_resource(sideex_main.SideexReportV2, '/v2/sideex_report/<int:test_id>')
    add_resource(sideex_main.SideexReportV2, "public")
    api.add_resource(sideex_main.SideexJsonfileVariable, '/sideex/<sint:project_id>/jsonfile/varable')
    api.add_resource(sideex_main.SideexJsonfileVariableV2, '/v2/sideex/<sint:project_id>/jsonfile/varable')
    add_resource(sideex_main.SideexJsonfileVariableV2, "public")
    api.add_resource(sideex_main.SideexGenerateJsonfile, '/sideex/<sint:project_id>/jsonfile/generate')
    api.add_resource(sideex_main.SideexGenerateJsonfileV2, '/v2/sideex/<sint:project_id>/jsonfile/generate')
    add_resource(sideex_main.SideexGenerateJsonfileV2, "public")
    api.add_resource(sideex_main.SideexDeleteAllfile, '/sideex/<sint:project_id>/jsonfile/delete')
    api.add_resource(sideex_main.SideexDeleteAllfileV2, '/v2/sideex/<sint:project_id>/jsonfile/delete')
    add_resource(sideex_main.SideexDeleteAllfileV2, "public")
    api.add_resource(sideex_main.HistoryPictResult, '/sideex/<sint:project_id>/history/result')
    api.add_resource(sideex_main.GenerateResult, '/sideex/<sint:project_id>/generate_result')
    api.add_resource(sideex_main.GenerateResultV2, '/v2/sideex/<sint:project_id>/generate_result')
    add_resource(sideex_main.GenerateResultV2, "public")
    api.add_resource(sideex_main.PictStatus, '/sideex/<sint:project_id>/pict/status')
    api.add_resource(sideex_main.PictStatusV2, '/v2/sideex/<sint:project_id>/pict/status')
    add_resource(sideex_main.PictStatusV2, "public")
    api.add_resource(sideex_main.CheckResultFileExist, '/sideex/<sint:project_id>/result/exist')
    api.add_resource(sideex_main.CheckResultFileExistV2, '/v2/sideex/<sint:project_id>/result/exist')
    add_resource(sideex_main.CheckResultFileExistV2, "public")