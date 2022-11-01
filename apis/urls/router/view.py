from flask_jwt_extended import jwt_required
from flask_restful import Resource

import util
from resources import router
from resources.apiError import DevOpsError

get_router_error = "Without Router Definition"


class Router(Resource):
    @jwt_required()
    def get(self):
        try:
            return util.success(router.get_plugin_software())
        except DevOpsError:
            return util.respond(404, get_router_error)


class UI_Router(Resource):
    @jwt_required()
    def get(self):
        try:
            return util.success(router.display_by_permission())
        except DevOpsError:
            return util.respond(404, get_router_error)
