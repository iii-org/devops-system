# For a plugin, make a directory named as its name, then put it under this directory.
# A plugin must have a plugin_config.json in it, and the name key must be as same as the
# plugin directory name.
# If the plugin only contains one module, make it __init__.py.

import json
import os
from datetime import datetime
from enum import Enum
from os.path import dirname, join, exists

from kubernetes.client import ApiException

import threading
import model
from resources import apiError
from resources import role
from resources import template
from resources.apiError import DevOpsError
from resources.kubernetesClient import read_namespace_secret, SYSTEM_SECRET_NAMESPACE, DEFAULT_NAMESPACE, \
    create_namespace_secret, patch_namespace_secret, delete_namespace_secret
from resources.rancher import rancher

import plugins

SYSTEM_SECRET_PREFIX = 'system-secret-'


class PluginKeyStore(Enum):
    DB = 'db'  # Store in db
    SECRET_SYSTEM = 'secret_system'  # Store in secret only for system admin
    SECRET_ALL = 'secret_all'  # Store in secret in all namespaces


def root():
    return dirname(__file__)


def list_plugin_modules():
    ret = []
    for plugin_name in filter(lambda x: not x.startswith('__'), next(os.walk(root()))[1]):
        config_file = join(root(), plugin_name, 'plugin_config.json')
        if not exists(config_file):
            continue
        ret.append(plugin_name)
    return ret


def list_plugins():
    ret = []
    rows = model.PluginSoftware.query.all()
    for row in rows:
        ret.append({
            'name': row.name,
            'create_at': str(row.create_at),
            'update_at': str(row.update_at),
            'disabled': row.disabled
        })
    return ret


def get_plugin_config_file(plugin_name):
    config_file = join(root(), plugin_name, 'plugin_config.json')
    f = open(config_file)
    config = json.load(f)
    f.close()
    return config


def system_secret_name(plugin_name):
    return f'{SYSTEM_SECRET_PREFIX}{plugin_name}'


def get_plugin_config(plugin_name):
    config = get_plugin_config_file(plugin_name)
    db_row = model.PluginSoftware.query.filter_by(name=plugin_name).one()
    db_arguments = json.loads(db_row.parameter)
    system_secrets = read_namespace_secret(SYSTEM_SECRET_NAMESPACE, system_secret_name(plugin_name))
    global_secrets = read_namespace_secret(DEFAULT_NAMESPACE, plugin_name)
    ret = {
        'name': plugin_name,
        'arguments': [],
        'disabled': db_row.disabled
    }
    if db_arguments is None:
        db_arguments = {}
    if system_secrets is None:
        system_secrets = {}
    if global_secrets is None:
        global_secrets = {}
    for item in config['keys']:
        key = item['key']
        item_value = item.get('value')
        store = PluginKeyStore(item['store'])
        value = None
        if store == PluginKeyStore.DB:
            value = db_arguments.get(key, None)
        elif store == PluginKeyStore.SECRET_SYSTEM:
            value = system_secrets.get(key, None)
        elif store == PluginKeyStore.SECRET_ALL:
            value = global_secrets.get(key, None)
        else:
            value = f'Wrong store location: {item["store"]}'
        # if value is not assign, assign default value
        if value is None and item_value is not None:
            value = item_value

        o = {
            'key': key,
            'title': item['key'].replace('-', '_'),
            'type': item['type'],
            'value': value
        }

        # Add Select Option
        if item['type'] == 'select':
            o['options'] = item['options']
            #  If Plugin is AD , get system role list
            if plugin_name == 'ad' and item['key'] == 'default_role_id':
                o['options'] = role.get_user_roles(True)
        ret['arguments'].append(o)
    return ret


def update_plugin_config(plugin_name, args):
    config = get_plugin_config_file(plugin_name)
    db_row = model.PluginSoftware.query.filter_by(name=plugin_name).one()
    db_arguments = json.loads(db_row.parameter)
    if db_arguments is None:
        db_arguments = {}
    system_secrets = read_namespace_secret(SYSTEM_SECRET_NAMESPACE, system_secret_name(plugin_name))
    global_secrets = read_namespace_secret(DEFAULT_NAMESPACE, plugin_name)
    key_map = {}
    for item in config['keys']:
        key_map[item['key']] = {
            'store': item['store'],
            'type': item['type']
        }
    if args.get('disabled', None) is not None:
        db_row.disabled = bool(args['disabled'])
        #  Update Project Plugin Status
        if bool(config.get('is_pipeline', True)):
            threading.Thread(target=template.update_pj_plugin_status, args=(plugin_name, args["disabled"],)).start()

    if args.get('arguments', None) is not None:
        for argument in args['arguments']:
            if argument not in key_map:
                raise DevOpsError(400, f'Argument {argument} is not in the argument list of plugin {plugin_name}.',
                                  error=apiError.argument_error(argument))
            store = PluginKeyStore(key_map[argument]['store'])
            if store == PluginKeyStore.DB:
                db_arguments[argument] = str(args['arguments'][argument])
            elif store == PluginKeyStore.SECRET_SYSTEM:
                if system_secrets is None:
                    create_namespace_secret(SYSTEM_SECRET_NAMESPACE, system_secret_name(plugin_name), {})
                    system_secrets = {}
                system_secrets[argument] = str(args['arguments'][argument])
            elif store == PluginKeyStore.SECRET_ALL:
                if global_secrets is None:
                    global_secrets = {}
                global_secrets[argument] = str(args['arguments'][argument])
    if system_secrets is not None:
        patch_namespace_secret(SYSTEM_SECRET_NAMESPACE, system_secret_name(plugin_name), system_secrets)
    if global_secrets is not None:
        rancher.rc_add_secrets_to_all_namespaces(plugin_name, global_secrets)
    db_row.parameter = json.dumps(db_arguments)
    db_row.update_at = datetime.now()
    model.db.session.commit()


def delete_plugin_row(plugin_name):
    row = model.PluginSoftware.query.filter_by(name=plugin_name).one()
    model.db.session.delete(row)
    model.db.session.commit()
    try:
        rancher.rc_delete_secrets_into_rc_all(plugin_name)
    except apiError.DevOpsError as e:
        if e.status_code != 404:
            raise e
    try:
        delete_namespace_secret(SYSTEM_SECRET_NAMESPACE, system_secret_name(plugin_name))
    except ApiException as e:
        if e.status != 404:
            raise e


def insert_plugin_row(plugin_name, args):
    check = model.PluginSoftware.query.filter_by(name=plugin_name).first()
    if check is not None:
        raise DevOpsError(400, 'Plugin is already in the db.',
                          error=apiError.argument_error(plugin_name))
    new = model.PluginSoftware(
        name=plugin_name,
        disabled=args.get('disabled', False),
        create_at=datetime.now(),
        update_at=datetime.now(),
        parameter='{}'
    )
    model.db.session.add(new)
    model.db.session.commit()
    update_plugin_config(plugin_name, args)
    return new


def sync_plugins_in_db_and_code():
    # Insert plugins db row
    existed_plugins = list_plugins()
    plugin_modules = list_plugin_modules()
    for plugin_name in plugin_modules:
        existed = False
        for ep in existed_plugins:
            if ep['name'] == plugin_name:
                existed = True
                break
        if not existed:
            config = get_plugin_config_file(plugin_name)
            insert_plugin_row(plugin_name, {
                'arguments': {},
                'disabled': config.get('default_disabled', True)
            })
    for plugin in existed_plugins:
        existed = False
        for plugin_name in plugin_modules:
            if plugin['name'] == plugin_name:
                existed = True
                break
        if not existed:
            delete_plugin_row(plugin['name'])


def create_plugins_api_router(api):
    plugin_names = list_plugin_modules()
    for plugin_name in plugin_names:
        third_part_plugin = getattr(plugins, plugin_name)
        if hasattr(third_part_plugin, "router"):
            third_part_plugin.router(api)
