import util
from flask_apispec import doc, marshal_with
from flask_apispec.views import MethodResource
from flask_jwt_extended import jwt_required
from flask_restful import Resource
from resources import router
from resources.apiError import DevOpsError

from . import route_model

get_router_error = "Without Router Definition"


class Router(Resource):
    @ jwt_required
    def get(self):
        try:
            return util.success(router.get_plugin_software())
        except DevOpsError:
            return util.respond(404, get_router_error
                                )


@ doc(tags=['Router'], description="Get UI route name")
@ marshal_with(route_model.UIRouteListResponse)
class RouterNameV2(MethodResource):

    @ jwt_required
    def get(self):
        util.require_admin()
        return util.success(router.get_ui_route_list())


@ doc(tags=['Router'], description="Get the user route")
@ marshal_with(route_model.UIRouteListResponse)
class UserRouteV2(MethodResource):
    @ jwt_required
    def get(self):
        return util.success(router.get_user_route())
