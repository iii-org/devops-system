from . import sonarqube_main

ui_route = ["Sonarqube"]

# --------------------- API router ---------------------


def router(api):
    api.add_resource(sonarqube_main.SonarqubeHistory, '/sonarqube/<project_name>')
