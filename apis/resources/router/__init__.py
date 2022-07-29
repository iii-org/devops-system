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
    i = 0
    times = 0
    while True:
        ui_route = UIRouteData.query.filter_by(parent=0, role=role_name, old_brother=i).first()
        if ui_route is None or times > 50:
            break
        ui_route_list.append(get_ui_route(ui_route, role_name))
        i = ui_route.id
        times += 1
    # get error page
    error_route = UIRouteData.query.filter_by(role="").first()
    ui_route_list.append(error_route.ui_route)
    return ui_route_list


def get_ui_route(ui_route, role_name):
    children = []
    i = 0
    times = 0
    while True:
        child_route = UIRouteData.query.filter_by(parent=ui_route.id, role=role_name, old_brother=i).first()
        if child_route is None or times > 50:
            break
        children.append(get_ui_route(child_route, role_name))
        i = child_route.id
        times += 1
    ui_route_dict = ui_route.ui_route
    if len(children) > 0:
        ui_route_dict['children'] = children
    return ui_route_dict
