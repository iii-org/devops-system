from resources.handler.jwt import jwt_required
from flask_apispec import marshal_with, doc, use_kwargs
from flask_apispec.views import MethodResource
from .control import backup_user_to_json, backup_project_to_json
import util


@doc(tags=["Backup"], description="User's data backup to json file")
class UserBackupToJsonV2(MethodResource):
    @marshal_with(util.CommonResponse)
    # @jwt_required
    def post(self, **kwargs):
        backup_user_to_json()
        return util.success()


@doc(tags=["Backup"], description="Project's data backup to json file")
class ProjectBackupToJsonV2(MethodResource):
    @marshal_with(util.CommonResponse)
    # @jwt_required
    def post(self):
        backup_project_to_json()
        return util.success()
