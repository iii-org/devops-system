from resources.handler.jwt import jwt_required_cronjob
from flask_apispec import marshal_with, doc, use_kwargs
from flask_apispec.views import MethodResource
from .control import restore_user_from_json, restore_project_from_json
import util


# @doc(tags=["Restore"], description="User's data restore from json file")
class UserRestoreFromJsonV2(MethodResource):
    # @marshal_with(util.CommonResponse)
    @jwt_required_cronjob
    def post(self):
        restore_user_from_json()
        return util.success()


# @doc(tags=["Restore"], description="Project's data restore from json file")
class ProjectRestoreFromJsonV2(MethodResource):
    # @marshal_with(util.CommonResponse)
    @jwt_required_cronjob
    def post(self):
        restore_project_from_json()
        return util.success()
