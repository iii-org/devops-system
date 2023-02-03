from . import checkmarx_main

ui_route = ["Checkmarx"]
# --------------------- API router ---------------------


def router(api, add_resource):
    # runner API
    api.add_resource(checkmarx_main.CreateCheckmarxScan, "/checkmarx/create_scan")
    api.add_resource(
        checkmarx_main.GetCheckmarxProject,
        "/checkmarx/get_cm_project_id/<sint:project_id>",
    )

    #
    api.add_resource(checkmarx_main.GetCheckmarxScans, "/checkmarx/scans/<sint:project_id>")
    api.add_resource(
        checkmarx_main.GetCheckmarxLatestScan,
        "/checkmarx/latest_scan/<sint:project_id>",
    )
    api.add_resource(
        checkmarx_main.GetCheckmarxLatestScanStats,
        "/checkmarx/latest_scan_stats/<sint:project_id>",
    )
    api.add_resource(
        checkmarx_main.GetCheckmarxLatestReport,
        "/checkmarx/latest_report/<sint:project_id>",
    )
    api.add_resource(checkmarx_main.GetCheckmarxReport, "/checkmarx/report/<report_id>")
    api.add_resource(checkmarx_main.GetCheckmarxScanStatus, "/checkmarx/scan_status/<scan_id>")
    api.add_resource(checkmarx_main.GetCheckmarxScanStatistics, "/checkmarx/scan_stats/<scan_id>")
    api.add_resource(checkmarx_main.RegisterCheckmarxReport, "/checkmarx/report/<scan_id>")
    api.add_resource(checkmarx_main.GetCheckmarxReportStatus, "/checkmarx/report_status/<scan_id>")
    api.add_resource(checkmarx_main.CancelCheckmarxScan, "/checkmarx/scan/<scan_id>/cancel")
    api.add_resource(checkmarx_main.CronjobScan, "/checkmarx/cronjob_scan")
