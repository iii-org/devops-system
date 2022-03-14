import json

import model
import plugins
from flask_jwt_extended import get_jwt_identity
from model import db
from sqlalchemy.sql import and_


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
