from flask_jwt_extended import jwt_required
from flask_restful import Resource

import model
import util as util
from resources.apiError import DevOpsError

get_router_error = "Without Router Definition"
key_return_json = ['parameter']


def row_to_dict(row):
    ret = {}
    if row is None:
        return row
    ret['id'] = getattr(row,  'id')
    ret['name'] = getattr(row,  'name')
    ret['disabled'] = getattr(row,  'disabled')
    return ret


def get_plugin_software():
    plugins = model.PluginSoftware.query.with_entities(
        model.PluginSoftware.id, model.PluginSoftware.name, model.PluginSoftware.disabled).all()
    output = []
    for plugin in plugins:
        if plugin is not None:
            output.append(row_to_dict(plugin))
    return output


class Router(Resource):
    @jwt_required
    def get(self):
        try:
            return util.success(get_plugin_software())
        except DevOpsError:
            return util.respond(404, get_router_error
                                )
