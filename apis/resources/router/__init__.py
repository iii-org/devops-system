import datetime
import json
from flask_jwt_extended import get_jwt_identity
import model
import plugins
import util
from flask_jwt_extended import get_jwt_identity
from model import UIRouteData, db
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
    role_name = get_jwt_identity()['role_name']
    ui_routes = UIRouteData.query.filter_by(parent=0, role=role_name).all()
    for ui_route in ui_routes:
        ui_route_list.append(get_ui_route(ui_route, role_name))
    # get error page
    error_route = UIRouteData.query.filter_by(role="").first()
    ui_route_list.append(error_route.ui_route)
    return ui_route_list


def get_ui_route(ui_route, role_name):
    child_routes = UIRouteData.query.filter_by(parent=ui_route.id, role=role_name).all()
    children = []
    for child_route in child_routes:
        children.append(get_ui_route(child_route, role_name))
    ui_route_dict = ui_route.ui_route
    if len(children) > 0:
        ui_route_dict['children'] = children
    return ui_route_dict
