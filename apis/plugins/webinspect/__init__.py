from . import webinspect_main

ui_route = ["WebInspect"]

# --------------------- API router ---------------------


def router(api, add_resource):
    # WebInspect
    api.add_resource(webinspect_main.WebInspectPostScan, "/webinspect/scan")
    # add_resource(webinspect_main.WebInspectPostScan, "public")
    api.add_resource(webinspect_main.WebInspectListScan, "/project/<sint:project_id>/webinspect/scan")
    # add_resource(webinspect_main.WebInspectListScan, "public")
    api.add_resource(webinspect_main.WebInspectScan, "/webinspect/scan/<s_id>")
    # add_resource(webinspect_main.WebInspectScan, "public")
