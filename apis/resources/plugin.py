import json
import numbers
from datetime import datetime, date
import util as util
import config
import model
from model import db
import base64
from resources import role

from flask_jwt_extended import jwt_required, get_jwt_identity
from flask_restful import Resource, reqparse
from sqlalchemy.orm.exc import NoResultFound
import resources.apiError as apiError
from resources.logger import logger

invalid_plugin_id = 'Unable get plugin'
invalid_plugin_softwares = 'Unable get plugin softwares'


def row_to_dict(row):
    ret = {}
    if row is None:
        return row
    for key in type(row).__table__.columns.keys():
        value = getattr(row, key)
        if type(value) is datetime or type(value) is date:
            ret[key] = str(value)
        elif key == "parameter" and value is not None:
            parmameters = base64.b64decode(value).decode('utf-8')
            ret[key] = json.loads(parmameters)
        else:
            ret[key] = value
    return ret


def get_plugin_softwares():
    plugins = model.PluginSoftware.query.all()
    output = []
    for plugin in plugins:
        if plugin is not None:
            output.append(row_to_dict(plugin))
    return output


def get_plugin_software_by_id(plugin_id):
    plugin = model.PluginSoftware.query.\
        filter(model.PluginSoftware.id == plugin_id).\
        first()
    return row_to_dict(plugin)


def get_plugin_software_by_name(plugin_name):
    plugin = model.PluginSoftware.query.\
        filter(model.PluginSoftware.name.like(plugin_name)).\
        first()
    return row_to_dict(plugin)


def update_plugin_software(plugin_id, args):
    r = model.PluginSoftware.query.filter_by(id=plugin_id).first()
    if r is None:
        return {}
    r.name = args['name']

    if args.get('type_id') == 2:

        r.parameter = None
    else:
        r.parameter = get_plugin_parameters(args)
    disabled = False
    if args.get('disabled') is True:
        disabled = True
    r.disabled = disabled
    r.type_id = args.get('type_id', 1)
    r.update_at = str(datetime.now())
    db.session.commit()
    return row_to_dict(r)


def create_plugin_software(args):
    type_id = args.get('type_id')
    if type_id == 2:
        rancher.rc_add_secrets_into_rc_all(args)

    parameter = get_plugin_parameters(args)
    new = model.PluginSoftware(
        name=args['name'],
        parameter=parameter,
        disabled=args.get('disabled'),
        create_at=str(datetime.now()),
        type_id=args.get('type_id', 1)
    )
    db.session.add(new)
    db.session.commit()
    return {'plugin_id': new.id}


def delete_plugin_software(plugin_id):
    plugin_software = model.PluginSoftware.query.filter_by(
        id=plugin_id).first()
    db.session.delete(plugin_software)
    db.session.commit()
    return {'plugin_id': plugin_id}


class Plugins(Resource):
    @jwt_required
    def get(self):
        try:
            role.require_admin('Only admins can get plugin software.')
            return util.success({'plugin_list': get_plugin_softwares()})
        except NoResultFound:
            return util.respond(404, invalid_plugin_softwares)

    @jwt_required
    def post(self):
        role.require_admin('Only admins can create plugin software.')
        parser = reqparse.RequestParser()
        parser.add_argument('name', type=str)
        parser.add_argument('parameter', type=dict)
        parser.add_argument('disabled', type=bool)
        parser.add_argument('type_id', type=int)
        args = parser.parse_args()
        output = create_plugin_software(args)
        return util.success(output)


class Plugin(Resource):
    @jwt_required
    def get(self, plugin_id):
        try:
            role.require_admin('Only admins can get plugin software.')
            return util.success(get_plugin_software_by_id(plugin_id))
        except NoResultFound:
            return util.respond(404, invalid_plugin_id,
                                error=apiError.invalid_plugin_id(plugin_id))

    @jwt_required
    def put(self, plugin_id):
        role.require_admin('Only admins can modify plugin software.')
        parser = reqparse.RequestParser()
        parser.add_argument('name', type=str)
        parser.add_argument('parameter', type=dict)
        parser.add_argument('disabled', type=bool)
        parser.add_argument('type_id', type=int)
        args = parser.parse_args()
        print(type(args.get('disabled')))
        print(args.get('disabled'))
        output = update_plugin_software(plugin_id, args)
        return util.success(output)

    @jwt_required
    def delete(self, plugin_id):
        role.require_admin('Only admins can delete plugin software.')
        output = delete_plugin_software(plugin_id)
        return util.success(output)


class APIPlugin():
    def get_plugin(self, plugin_name):
        try:
            return get_plugin_software_by_name(plugin_name)
        except NoResultFound:
            return util.respond(404, invalid_plugin_id,
                                error=apiError.invalid_plugin_id(plugin_name))


api_plugin = APIPlugin()
