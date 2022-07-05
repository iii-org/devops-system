import datetime
import json
from flask_jwt_extended import  get_jwt_identity
import model
import plugins
import util
from flask_jwt_extended import get_jwt_identity
from model import UIRouteJson, db
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

def display_by_permission():
    ui_route_list = []
    user_doc = get_jwt_identity()
    row = UIRouteJson.query.filter_by(name='ui_route').first()
    for temp in row.ui_route:
        if temp.get("redirect") == "/404":
            ui_route_list.append(temp)
            continue
        if user_doc.get("role_name") not in temp.get("meta").get("roles"):
                continue
        if temp.get("children") is not None:
            children_list = []
            for children in temp.get("children"):
                if user_doc.get("role_name") in temp.get("meta").get("roles"):
                    children_list.append(children)
            temp["children"] = children_list
        ui_route_list.append(temp)
    return ui_route_list
