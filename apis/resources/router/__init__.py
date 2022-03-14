import json

import model
import plugins
from flask_jwt_extended import get_jwt_identity
from model import UIRoute, UIRouteUserRoleRelation, db
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


def get_ui_route_list():
    return json.loads(str(UIRoute.query.all()))


def get_user_route():
    # Get route_name and filter by user role
    rows = db.session.query(UIRoute).join(UIRouteUserRoleRelation, and_(
        UIRouteUserRoleRelation.user_role == get_jwt_identity()["role_id"],
        UIRoute.id == UIRouteUserRoleRelation.ui_route_id)).all()

    # filter if plugins is not enable
    disable_plugin_list = []
    db_pluging_list = get_plugin_software()
    i = 0
    while i < len(db_pluging_list):
        if db_pluging_list[i]["disabled"] is False:
            del db_pluging_list[i]
        else:
            i += 1
    for db_pluging_dict in db_pluging_list:
        if db_pluging_dict['name'] in plugins.list_plugin_modules() and \
                hasattr(getattr(plugins, db_pluging_dict['name']), "ui_route") is True:
            disable_plugin_list.extend(getattr(plugins, db_pluging_dict['name']).ui_route)
    j = 0
    while j < len(rows):
        if rows[j].route_name in disable_plugin_list:
            del rows[j]
        else:
            j += 1
    return json.loads(str(rows))
