import base64
import json
from datetime import datetime, date

from flask_jwt_extended import jwt_required
from flask_restful import Resource, reqparse
from sqlalchemy.orm.exc import NoResultFound

import model
import plugins
import resources.apiError as apiError
import util as util
from model import db
from resources import role
from .rancher import rancher

invalid_plugin_id = 'Unable get plugin'
invalid_plugin_softwares = 'Unable get plugin softwares'


class Rancher(object):
    def __init__(self, args):
        self.name = args.get('name')
        self.parameter = {            
            'data' : args.get('parameter'),
            'type' : 'secret'
        }
    def get_secret_into_rc_all(self):
        output = {}
        data = rancher.rc_get_secrets_all_list()

        return data
    def add_secrets_into_rc_all(self):
        self.parameter['name'] = self.name
        rancher.rc_add_secrets_into_rc_all(self.parameter)
        return "Success"
    def put_secrets_into_rc_all(self):
        rancher.rc_put_secrets_into_rc_all(self.name, self.parameter)
        return "Success"
        
    def delete_secrets_into_rc_all(self):
        rancher.rc_delete_secrets_into_rc_all(self.name)
        return "Success"


def get_plugin_parameters(args):
    parameters = args.get('parameter')
    if args.get('type_id',1) ==1 and parameters is not None :
        parameters = base64.b64encode(
            bytes(json.dumps(parameters), encoding='utf-8')).decode('utf-8')
    else:
        parameters = None
    return parameters

     
def k8s_secrest_decode(data):
    output = {}
    if data is None:
        return output
    for k,v  in data.items():        
        output[k] = base64.b64decode(v).decode('utf-8')
    return output 

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


@DeprecationWarning
def list_plugin_software():
    plugins = model.PluginSoftware.query.all()
    output = []
    for plugin in plugins:
        if plugin is not None:
            output.append(row_to_dict(plugin))
    return output


@DeprecationWarning
def get_plugin_software_by_id(plugin_id):
    output = {}
    plugin = model.PluginSoftware.query.\
        filter(model.PluginSoftware.id == plugin_id).\
        first()
    output = row_to_dict(plugin)
    if plugin.type_id == 2:
        args = {
            'name' :plugin.name
        }
        k8s = Rancher(args)
        secrets = k8s.get_secret_into_rc_all()
        for secret in secrets:
            if secret['name'] == plugin.name :
                output['parameter'] = k8s_secrest_decode(secret['data'])
                break                    
    return output


def get_plugin_software_by_name(plugin_name):
    plugin = model.PluginSoftware.query.\
        filter(model.PluginSoftware.name.like(plugin_name)).\
        first()
    return row_to_dict(plugin)


def update_plugin_software(plugin_id, args):
    r = model.PluginSoftware.query.filter_by(id=plugin_id).first()
    if r is None:
        return {}
    if args.get('type_id') == 2:
        k8s = Rancher(args)
        k8s.put_secrets_into_rc_all()          
        r.parameter = None
    else:
        r.parameter = get_plugin_parameters(args)
    disabled = False
    if args.get('disabled') is True:
        disabled = True
    r.name = args['name']
    r.disabled = disabled
    r.type_id = args.get('type_id', 1)
    r.update_at = str(datetime.now())
    db.session.commit()
    return row_to_dict(r)


def create_plugin_software(args):
    type_id = args.get('type_id')
    if type_id == 2:
        k8s = Rancher(args)
        k8s.add_secrets_into_rc_all()                            
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
    r = model.PluginSoftware.query.filter_by(
        id=plugin_id).first()        
    if r.type_id == 2:
        k8s = Rancher({'name' : r.name})
        k8s.delete_secrets_into_rc_all()               
    db.session.delete(r)
    db.session.commit()
    return {'plugin_id': plugin_id}


class Plugins(Resource):
    @jwt_required
    def get(self):
        role.require_admin('Only admins can get plugin software.')
        return util.success(plugins.list_plugins())


class Plugin(Resource):
    @jwt_required
    def get(self, plugin_name):
        role.require_admin('Only admins can get plugin software.')
        return util.success(plugins.get_plugin_config(plugin_name))

    @jwt_required
    def put(self, plugin_name):
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
            return util.respond(404, invalid_plugin_id,
                                error=apiError.invalid_plugin_id(plugin_name))


api_plugin = APIPlugin()
