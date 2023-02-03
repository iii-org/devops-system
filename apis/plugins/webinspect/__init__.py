from . import webinspect_main

ui_route = ["Webinspect", "WebInspectReport"]
# --------------------- API router ---------------------


def router(api, add_resource):
    # WebInspect
    api.add_resource(
        webinspect_main.WebInspectScan,
        "/webinspect/create_scan",
        "/webinspect/list_scan/<project_name>",
    )
    api.add_resource(webinspect_main.WebInspectScanStatus, "/webinspect/status/<scan_id>")
    api.add_resource(webinspect_main.WebInspectScanStatistics, "/webinspect/stats/<scan_id>")
    api.add_resource(webinspect_main.WebInspectReport, "/webinspect/report/<scan_id>")
