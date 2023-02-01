from flask_apispec.views import MethodResource
from flask_apispec import marshal_with, doc, use_kwargs
from resources.rancher import check_pipeline_need_remove
import util
from nexus import nx_get_project_plugin_relation
from . import router_model


class CheckPipeline(MethodResource):
    @doc(tags=["Rancher"], description="Check rancher need run or not.")
    @use_kwargs(router_model.CheckPipelineSchema, location="form")
    def post(self, **kwargs):
        check_pipeline_need_remove(kwargs["repo_name"], kwargs["branch"], kwargs["commit_id"])
        return util.success()
