from . import sbom_main

ui_route = ["Sbom"]
# --------------------- API router ---------------------


def router(api, add_resource):
    # runner API
    api.add_resource(sbom_main.SbomPostV2, '/v2/sbom')
    api.add_resource(sbom_main.SbomGetV2, '/v2/<sint:project_id>/sboms')
    api.add_resource(sbom_main.SbomPatchV2, '/v2/sbom/<int:sbom_id>')