from . import postman_main


ui_route = ["Postman", "PostmanTestCase"]

# --------------------- API router ---------------------


def router(api, add_resource):
    # Postman tests
    api.add_resource(postman_main.ExportToPostmanV2, "/export_to_postman/<sint:project_id>")
    add_resource(postman_main.ExportToPostmanV2, "public")
    api.add_resource(postman_main.PostmanResultsV2, "/postman_results/<sint:project_id>")
    add_resource(postman_main.PostmanResultsV2, "public")
    api.add_resource(postman_main.PostmanScanReportV2, "/postman_report/<int:id>")
    add_resource(postman_main.PostmanScanReportV2, "public")
    api.add_resource(postman_main.PostmanReportV2, "/testResults")
    add_resource(postman_main.PostmanReportV2, "public")
