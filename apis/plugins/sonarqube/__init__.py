from . import sonarqube_main

ui_route = ["Sonarqube"]

# --------------------- API router ---------------------


def router(api, add_resource):
    api.add_resource(sonarqube_main.SonarqubeHistoryV2, "/sonarqube/<project_name>")
    add_resource(sonarqube_main.SonarqubeHistoryV2, "public")
    api.add_resource(sonarqube_main.SonarqubeCodelenV2, "/sonarqube/<project_name>/codelen")
    add_resource(sonarqube_main.SonarqubeCodelenV2, "public")
