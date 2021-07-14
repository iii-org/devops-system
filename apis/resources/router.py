import json
import requests
import util as util
import model

from flask_jwt_extended import jwt_required, get_jwt_identity
from flask_restful import Resource, reqparse
from resources import apiError
from resources.apiError import DevOpsError
from resources.logger import logger
from datetime import datetime, date

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
