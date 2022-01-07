from . import sonarqube_main

# --------------------- API router ---------------------


def router(api):
    api.add_resource(sonarqube_main.SonarqubeHistory, '/sonarqube/<project_name>')
