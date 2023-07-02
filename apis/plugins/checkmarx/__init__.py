from . import checkmarx_main

ui_route = ["Checkmarx"]
# --------------------- API router ---------------------


def router(api, add_resource):
    # runner API
    api.add_resource(checkmarx_main.CreateCheckmarxScanV2, "/v2/checkmarx/create_scan")
    add_resource(checkmarx_main.CreateCheckmarxScanV2, "public")
    api.add_resource(
        checkmarx_main.GetCheckmarxProjectV2,
        "/v2/checkmarx/get_cm_project_id/<sint:project_id>",
    )
    add_resource(checkmarx_main.GetCheckmarxProjectV2, "public")
    #
    api.add_resource(checkmarx_main.GetCheckmarxScansV2, "/checkmarx/scans/<sint:project_id>")
    add_resource(checkmarx_main.GetCheckmarxScansV2, "public")
    api.add_resource(
        checkmarx_main.GetCheckmarxLatestScanV2,
        "/checkmarx/latest_scan/<sint:project_id>",
    )
    add_resource(checkmarx_main.GetCheckmarxLatestScanV2, "public")
    api.add_resource(
        checkmarx_main.GetCheckmarxLatestScanStatsV2,
        "/checkmarx/latest_scan_stats/<sint:project_id>",
    )
    add_resource(checkmarx_main.GetCheckmarxLatestScanStatsV2, "public")
    api.add_resource(
        checkmarx_main.GetCheckmarxLatestReportV2,
        "/checkmarx/latest_report/<sint:project_id>",
    )
    add_resource(checkmarx_main.GetCheckmarxLatestReportV2, "public")
    api.add_resource(checkmarx_main.GetCheckmarxReportV2, "/checkmarx/report/<report_id>")
    add_resource(checkmarx_main.GetCheckmarxReportV2, "public")
    api.add_resource(checkmarx_main.GetCheckmarxScanStatusV2, "/checkmarx/scan_status/<scan_id>")
    add_resource(checkmarx_main.GetCheckmarxScanStatusV2, "public")
    api.add_resource(checkmarx_main.GetCheckmarxScanStatisticsV2, "/checkmarx/scan_stats/<scan_id>")
    add_resource(checkmarx_main.GetCheckmarxScanStatisticsV2, "public")
    api.add_resource(checkmarx_main.RegisterCheckmarxReportV2, "/checkmarx/report/<scan_id>")
    add_resource(checkmarx_main.RegisterCheckmarxReportV2, "public")
    api.add_resource(checkmarx_main.GetCheckmarxReportStatusV2, "/checkmarx/report_status/<report_id>")
    add_resource(checkmarx_main.GetCheckmarxReportStatusV2, "public")
    api.add_resource(checkmarx_main.CancelCheckmarxScanV2, "/checkmarx/scan/<scan_id>/cancel")
    add_resource(checkmarx_main.CancelCheckmarxScanV2, "public")
    api.add_resource(checkmarx_main.CronjobScan, "/checkmarx/cronjob_scan")
