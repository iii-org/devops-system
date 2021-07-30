from flask_jwt_extended import jwt_required
from flask_restful import Resource, reqparse
from sqlalchemy.orm.exc import NoResultFound

import plugins
import resources.apiError as apiError
import util as util
from resources import role


invalid_plugin_name = 'Unable get plugin software'



class Plugins(Resource):
    @jwt_required
    def get(self):
        return util.success(plugins.list_plugins())


class Plugin(Resource):
    @jwt_required
    def get(self, plugin_name):
        role.require_admin('Only admins can get plugin software.')
        return util.success(plugins.get_plugin_config(plugin_name))

    @jwt_required
    def patch(self, plugin_name):
        role.require_admin('Only admins can modify plugin software.')
        parser = reqparse.RequestParser()
        parser.add_argument('arguments', type=dict)
        parser.add_argument('disabled', type=bool)
        args = parser.parse_args()
        plugins.update_plugin_config(plugin_name, args)
        return util.respond(204)

    @jwt_required
    def delete(self, plugin_name):
        role.require_admin('Only admins can delete plugin software.')
        plugins.delete_plugin_row(plugin_name)
        return util.respond(204)

    @jwt_required
    def post(self, plugin_name):
        role.require_admin('Only admins can create plugin software.')
        parser = reqparse.RequestParser()
        parser.add_argument('arguments', type=dict)
        parser.add_argument('disabled', type=bool)
        args = parser.parse_args()
        plugins.insert_plugin_row(plugin_name, args)
        return util.success()


class APIPlugin():
    def get_plugin(self, plugin_name):
        try:
            return plugins.get_plugin_config(plugin_name)
        except NoResultFound:
            return util.respond(404, invalid_plugin_name,
                                error=apiError.invalid_plugin_name(plugin_name))


api_plugin = APIPlugin()
