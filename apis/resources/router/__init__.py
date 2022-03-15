import datetime
import json

import model
import plugins
import util
from flask_jwt_extended import get_jwt_identity
from model import UIRouteJson, db
from sqlalchemy.sql import and_

key_return_json = ['parameter']


def load_ui_route():
    ui_route_json = util.read_json_file("apis/ui_route.json")
    row = UIRouteJson.query.filter_by(name='ui_route').first()
    if row is None:
        new_row = UIRouteJson(
            name='ui_route',
            ui_route=ui_route_json,
            created_at=datetime.datetime.utcnow(),
            updated_at=datetime.datetime.utcnow()
        )
        db.session.add(new_row)
        db.session.commit()
    elif str(ui_route_json) != str(row.ui_route):
        row.ui_route = ui_route_json
        row.updated_at = datetime.datetime.utcnow()
        db.session.commit()
    else:
        print("Noting change")


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
