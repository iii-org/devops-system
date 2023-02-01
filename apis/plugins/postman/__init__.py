from . import postman_main


ui_route = ["Postman", "PostmanTestCase"]

# --------------------- API router ---------------------


def router(api, add_resource):
    # Postman tests
    api.add_resource(postman_main.ExportToPostman, "/export_to_postman/<sint:project_id>")
    api.add_resource(postman_main.PostmanResults, "/postman_results/<sint:project_id>")
    api.add_resource(postman_main.PostmanReport, "/testResults", "/postman_report/<int:id>")
