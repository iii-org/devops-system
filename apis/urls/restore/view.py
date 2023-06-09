from resources.handler.jwt import jwt_required
from flask_apispec import marshal_with, doc, use_kwargs
from flask_apispec.views import MethodResource
from .control import restore_user_from_json
import util


@doc(tags=["User"], description="User's data restore from json file")
class UserRestoreFromJsonV2(MethodResource):
    @marshal_with(util.CommonResponse)
    @jwt_required
    def post(self):
        restore_user_from_json()
        return util.success()