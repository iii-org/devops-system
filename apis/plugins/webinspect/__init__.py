from . import webinspect_main_real

ui_route = ["WebInspect"]

# --------------------- API router ---------------------


def router(api, add_resource):
    # WebInspect
    api.add_resource(webinspect_main_real.WebInspectPostScan, "/webinspect/scan")
    add_resource(webinspect_main_real.WebInspectPostScan, "private")
    api.add_resource(webinspect_main_real.WebInspectListScan, "/project/<sint:project_id>/webinspect/scan")
    add_resource(webinspect_main_real.WebInspectListScan, "private")
    api.add_resource(webinspect_main_real.WebInspectScan, "/webinspect/scan/<s_id>")
    add_resource(webinspect_main_real.WebInspectScan, "private")
