from . import view


def rancher_url(api, add_resource):
    # Router
    api.add_resource(view.CheckPipeline, "/v2/rancher/check_pipeline")
