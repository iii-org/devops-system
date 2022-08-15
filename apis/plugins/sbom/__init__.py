from . import sbom_main

ui_route = ["Sbom"]
# --------------------- API router ---------------------


def router(api, add_resource):
    api.add_resource(sbom_main.SbomGetV2, '/v2/<sint:project_id>/sboms')
    api.add_resource(sbom_main.SbomParseV2, '/v2/sbom/<int:sbom_id>/parse')
    api.add_resource(sbom_main.SbomListV2, '/v2/sbom/<int:project_id>/list')
    api.add_resource(sbom_main.SbomGetRiskOverviewV2, '/v2/sbom/<int:sbom_id>/riskoverview')
    add_resource(sbom_main.SbomGetRiskOverviewV2, "public")
    api.add_resource(sbom_main.SbomRiskDetailV2, '/v2/sbom/<int:sbom_id>/riskdetail')
    add_resource(sbom_main.SbomRiskDetailV2, "public")
    api.add_resource(sbom_main.SbomGetScanFileListV2, '/v2/sbom/<int:sbom_id>/files')
    add_resource(sbom_main.SbomGetScanFileListV2, "public")
    api.add_resource(sbom_main.SbomDownloadReportV2, '/v2/sbom/<int:sbom_id>/downloadreport')
    add_resource(sbom_main.SbomDownloadReportV2, "public")
    
    # runner API
    api.add_resource(sbom_main.SbomPostV2, '/v2/sbom')
    api.add_resource(sbom_main.SbomPatchV2, '/v2/sbom/<int:sbom_id>')

    # Cronjob
    api.add_resource(sbom_main.SbomRemoveExtra, '/v2/sbom/remove')
