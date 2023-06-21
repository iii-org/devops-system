# For a plugin, make a directory named as its name, then put it under this directory.
# A plugin must have a plugin_config.json in it, and the name key must be as same as the
# plugin directory name.
# If the plugin only contains one module, make it __init__.py.

import util
import config
import json
import os
from datetime import datetime
from enum import Enum
from os.path import dirname, join, exists

from kubernetes.client import ApiException

from subprocess import PIPE
import threading
import model
from resources import apiError
from resources import role
from resources import template
from resources.gitlab import gitlab
from enums.action_type import ActionType
from resources.activity import record_activity
from resources.apiError import DevOpsError
from resources.kubernetesClient import (
    read_namespace_secret,
    SYSTEM_SECRET_NAMESPACE,
    DEFAULT_NAMESPACE,
    delete_namespace_secret,
)
from resources.notification_message import (
    close_notification_message,
    get_unclose_notification_message,
    create_notification_message,
)
from resources.kubernetesClient import ApiK8sClient
from resources.router import update_plugin_hidden
from resources.redis import update_plugins_software_switch_all, get_plugins_software_switch_all
from typing import Any

SYSTEM_SECRET_PREFIX = "system-secret-"


## enterprise plugin validation
def validate_license_key(plugin):
    plugin_secret = read_namespace_secret(DEFAULT_NAMESPACE, plugin)
    if plugin_secret is not None:
        deployment_uuid = model.NexusVersion.query.first().deployment_uuid
        output_str, error_output = util.ssh_to_node_by_key(
            f"~/deploy-devops/sbom/sbom_license {deployment_uuid}",
            config.get("DEPLOYER_NODE_IP"),
        )
        if error_output == "":
            return output_str.replace("\n", "").strip() == plugin_secret.get("license_key")
    return False


def sbom_validation():
    def check_element_in_service(element, service_elements):
        for service_element in service_elements:
            if element == service_element:
                return True
        return False

    api_k8s_client = ApiK8sClient()
    if not check_element_in_service(
        "anchore-grypedb-update-job-by-day",
        [pod.metadata.name for pod in api_k8s_client.list_namespaced_cron_job("default").items],
    ) or not check_element_in_service(
        "anchore-init-pod",
        [pod.metadata.name for pod in api_k8s_client.list_namespaced_job("default").items],
    ):
        raise apiError.DevOpsError(
            400,
            "Service has not been deployed.",
            error=apiError.not_deployment_error("sbom"),
        )

    if not validate_license_key("sbom"):
        raise apiError.DevOpsError(
            400,
            "Sbom deployment failed, please contact DevOps for assistance.",
            error=apiError.license_key_error("sbom"),
        )


ENTERPRISE_PLUGINS = {"sbom": {"func": sbom_validation}}


class PluginKeyStore(Enum):
    DB = "db"  # Store in db
    SECRET_ALL = "secret_all"  # Store in secret in all namespaces


def root():
    return dirname(__file__)


def list_plugin_modules():
    ret = []
    for plugin_name in filter(lambda x: not x.startswith("__"), next(os.walk(root()))[1]):
        config_file = join(root(), plugin_name, "plugin_config.json")
        if not exists(config_file):
            continue
        ret.append(plugin_name)
    return ret


def list_plugins():
    ret = []
    rows = model.PluginSoftware.query.all()
    for row in rows:
        ret.append(
            {
                "name": row.name,
                "create_at": str(row.create_at),
                "update_at": str(row.update_at),
                "disabled": row.disabled,
            }
        )
    return ret


def get_plugin_config_file(plugin_name):
    config_file = join(root(), plugin_name, "plugin_config.json")
    f = open(config_file)
    config = json.load(f)
    f.close()
    return config


def system_secret_name(plugin_name):
    return f"{SYSTEM_SECRET_PREFIX}{plugin_name}"


def get_plugin_global_variable_from_gitlab(plugin_name: str):
    plugin_keys_info = get_plugin_config_file(plugin_name)["keys"]
    env_key_value_mapping = {
        plugin_key_info["key"]: "" for plugin_key_info in plugin_keys_info if plugin_key_info["store"] == "secret_all"
    }
    if not env_key_value_mapping:
        return {}

    all_gitlab_global_variables = gitlab.gl_get_all_global_variable()

    for all_gitlab_global_variable in all_gitlab_global_variables:
        if all_gitlab_global_variable["key"] in env_key_value_mapping:
            env_key_value_mapping[all_gitlab_global_variable["key"]] = all_gitlab_global_variable["value"]

    return env_key_value_mapping


def update_plugin_global_variable_to_gitlab(plugin_name: str, arguments: dict[str, Any]):
    plugin_keys_infos = get_plugin_config_file(plugin_name)["keys"]
    env_info_mapping = {plugin_keys_info["key"]: plugin_keys_info["type"] for plugin_keys_info in plugin_keys_infos}

    all_gitlab_global_variables = gitlab.gl_get_all_global_variable()
    all_gitlab_global_variables_keys = [
        all_gitlab_global_variable["key"] for all_gitlab_global_variable in all_gitlab_global_variables
    ]

    for key, value in arguments.items():
        if key in env_info_mapping:
            masked = env_info_mapping[key] == "password" and value != ""

            value_detail = {
                "value": value,
                "variable_type": "env_var",
                "protected": False,
                "masked": masked,
                "raw": True,
            }
            if key not in all_gitlab_global_variables_keys:
                value_detail["key"] = key
                gitlab.gl_create_global_variable(value_detail)
            else:
                gitlab.gl_update_global_variable(key, value_detail)


def get_plugin_config(plugin_name):
    config = get_plugin_config_file(plugin_name)
    db_row = model.PluginSoftware.query.filter_by(name=plugin_name).one()
    db_arguments = json.loads(db_row.parameter) or {}
    system_variables = get_plugin_global_variable_from_gitlab(plugin_name)

    value_store_mapping = {
        PluginKeyStore.DB: db_arguments,
        PluginKeyStore.SECRET_ALL: system_variables,
    }
    ret = {"name": plugin_name, "arguments": [], "disabled": db_row.disabled}

    for item in config["keys"]:
        key, item_value, store = item["key"], item.get("value"), PluginKeyStore(item["store"])
        value = value_store_mapping[store].get(key) if store in value_store_mapping else item_value

        o = {
            "key": key,
            "title": item["key"].replace("-", "_"),
            "type": item["type"],
            "value": value,
        }

        # Add Select Option
        if item["type"] == "select":
            o["options"] = item["options"]
            #  If Plugin is AD , get system role list
            if plugin_name == "ad" and item["key"] == "default_role_id":
                o["options"] = role.get_user_roles(True)
        ret["arguments"].append(o)
    return ret


def update_plugin_config(plugin_name, args):
    patch_secret = False
    config = get_plugin_config_file(plugin_name)
    system_variables = get_plugin_global_variable_from_gitlab(plugin_name)

    key_map = {}
    for item in config["keys"]:
        key_map[item["key"]] = {"store": item["store"], "type": item["type"]}

    if args.get("disabled") is not None:
        update_plugin_disable_argument(plugin_name, args, not system_variables)

    if args.get("arguments") is not None:
        update_plugin_argument(plugin_name, args, key_map, system_variables)


def update_plugin_argument(
    plugin_name: str, args: dict[str, Any], key_map: dict[str, Any], system_variables: dict[str, Any]
):
    db_row = model.PluginSoftware.query.filter_by(name=plugin_name).one()
    db_arguments = json.loads(db_row.parameter) or {}

    for argument in args["arguments"]:
        if argument not in key_map:
            raise DevOpsError(
                400,
                f"Argument {argument} is not in the argument list of plugin {plugin_name}.",
                error=apiError.argument_error(argument),
            )
        store = PluginKeyStore(key_map[argument]["store"])
        if store == PluginKeyStore.DB:
            db_arguments[argument] = str(args["arguments"][argument])

        elif store == PluginKeyStore.SECRET_ALL:
            system_variables[argument] = str(args["arguments"][argument])

    if db_arguments:
        update_plugin_config_in_db(plugin_name, db_arguments)
    elif system_variables:
        update_plugin_global_variable_to_gitlab(plugin_name, system_variables)


def update_plugin_disable_argument(plugin_name: str, args: dict[str, Any], is_first_import: bool = False):
    from resources.excalidraw import check_excalidraw_alive
    from plugins.ad.ad_main import check_ad_alive

    plugin_alive_mapping = {
        "excalidraw": {
            "func": check_excalidraw_alive,
            "alert_monitring_id": 1001,
            "parameters": {
                "excalidraw_url": args.get("arguments").get("EXCLD_URL") if args.get("arguments") is not None else None,
                "excalidraw_socket_url": args.get("arguments").get("EXCLD_SOCKET_URL")
                if args.get("arguments") is not None
                else None,
            },
        },
        "ad": {
            "func": check_ad_alive,
            "alert_monitring_id": 1002,
            "parameters": {"ldap_parameter": args.get("arguments", {})},
        },
    }
    disabled = args["disabled"]
    if not disabled:
        check_plugin_alive(plugin_name, plugin_alive_mapping, is_first_import)
        if plugin_name in ENTERPRISE_PLUGINS:
            ENTERPRISE_PLUGINS[plugin_name]["func"]()
        enable_plugin_config(plugin_name)
    else:
        plugin_alive_id = plugin_alive_mapping.get(plugin_name, {}).get("alert_monitring_id")
        read_plugin_alert_msg(plugin_name, plugin_alive_id)
        disable_plugin_config(plugin_name)

    update_plugin_hidden(plugin_name, disabled)


def check_plugin_alive(plugin_name: str, plugin_alive_mapping: dict[str, Any], is_first_import: bool):
    # First time import excalidraw (It can move to @use_kwargs)
    if plugin_name == "excalidraw" and is_first_import:
        excalidraw_url = plugin_alive_mapping["excalidraw"]["parameters"]["excalidraw_url"]
        excalidraw_socket_url = plugin_alive_mapping["excalidraw"]["parameters"]["excalidraw_socket_url"]

        if excalidraw_url is None or excalidraw_socket_url is None:
            raise DevOpsError(
                400,
                "Argument: EXCLD_URL or EXCLD_SOCKET_URL can not be blank in first create.",
                error=apiError.argument_error("disabled"),
            )

    # check plugin server alive before set disabled to false.
    plugin_alive_func = plugin_alive_mapping.get(plugin_name, {}).get("func")
    if plugin_alive_func is not None:
        kwargs = plugin_alive_mapping.get(plugin_name, {}).get("parameters", {})
        alive = plugin_alive_func(**kwargs)["alive"]
        if not alive:
            raise DevOpsError(
                400,
                "Plugin is not alive",
                error=apiError.plugin_server_not_alive(plugin_name),
            )


def read_plugin_alert_msg(plugin_name: str, plugin_alive_id: int):
    # Read alert_message of plugin server is not alive then send notification.
    if plugin_alive_id is not None:
        not_alive_messages = get_unclose_notification_message(plugin_alive_id)
        if not_alive_messages is not None and len(not_alive_messages) > 0:
            for not_alive_message in not_alive_messages:
                close_notification_message(not_alive_message["id"])
            create_notification_message(
                {
                    "alert_level": 1,
                    "title": f"Close {plugin_name} alert",
                    "message": f"Close {plugin_name} not alive alert, because plugin has been disabled.",
                    "type_ids": [4],
                    "type_parameters": {"role_ids": [5]},
                },
                user_id=1,
            )


def delete_plugin_row(plugin_name):
    row = model.PluginSoftware.query.filter_by(name=plugin_name).one()
    model.db.session.delete(row)
    model.db.session.commit()

    # try:
    #     rancher.rc_delete_secrets_into_rc_all(plugin_name)
    # except apiError.DevOpsError as e:
    #     if e.status_code != 404:
    #         raise e
    # try:
    #     delete_namespace_secret(SYSTEM_SECRET_NAMESPACE, system_secret_name(plugin_name))
    # except ApiException as e:
    #     if e.status != 404:
    #         raise e


def insert_plugin_row(plugin_name, args):
    check = model.PluginSoftware.query.filter_by(name=plugin_name).first()
    if check is not None:
        raise DevOpsError(
            400,
            "Plugin is already in the db.",
            error=apiError.argument_error(plugin_name),
        )
    new = model.PluginSoftware(
        name=plugin_name,
        disabled=args.get("disabled", False),
        create_at=datetime.utcnow(),
        update_at=datetime.utcnow(),
        parameter="{}",
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
            if ep["name"] == plugin_name:
                existed = True
                break
        if not existed:
            config = get_plugin_config_file(plugin_name)
            insert_plugin_row(
                plugin_name,
                {"arguments": {}, "disabled": config.get("default_disabled", True)},
            )
    for plugin in existed_plugins:
        existed = False
        for plugin_name in plugin_modules:
            if plugin["name"] == plugin_name:
                existed = True
                break
        if not existed:
            delete_plugin_row(plugin["name"])


def create_plugins_api_router(api, add_resource):
    plugin_names = list_plugin_modules()
    plugins = __import__("plugins", fromlist=plugin_names)
    for plugin_name in plugin_names:
        third_part_plugin = getattr(plugins, plugin_name)
        if hasattr(third_part_plugin, "router"):
            third_part_plugin.router(api, add_resource)


def handle_plugin(plugin):
    def decorator(func):
        def wrap(*args, **kwargs):
            plugin_software = model.PluginSoftware.query.filter_by(name=plugin).first()
            if plugin_software is None:
                raise apiError.DevOpsError(404, plugin, error=apiError.invalid_plugin_name(plugin))
            elif plugin_software.disabled:
                raise apiError.DevOpsError(404, plugin, error=apiError.plugin_is_disabled(plugin))

            return func(*args, **kwargs)

        return wrap

    return decorator


#  Update Project Plugin Status
def update_project_plugin_status():
    switches = get_plugins_software_switch_all()
    plugins = model.PluginSoftware.query.all()
    plugin_json: dict = {}
    for plugin in plugins:
        config = get_plugin_config_file(plugin.name)
        if bool(config.get("is_pipeline", True)):
            plugin_json[plugin.name] = plugin.disabled
            if str(plugin.disabled).lower() != switches.get(plugin.name):
                threading.Thread(
                    target=template.update_pj_plugin_status,
                    args=(
                        (plugin.name if plugin.name != "sbom" else "anchore"),
                        plugin.disabled,
                    ),
                ).start()
    update_plugins_software_switch_all(plugin_json)


@record_activity(ActionType.ENABLE_PLUGIN)
def enable_plugin_config(plugin_name):
    db_row = model.PluginSoftware.query.filter_by(name=plugin_name).one()
    db_row.disabled = False
    db_row.update_at = datetime.utcnow()
    model.db.session.commit()


@record_activity(ActionType.DISABLE_PLUGIN)
def disable_plugin_config(plugin_name):
    db_row = model.PluginSoftware.query.filter_by(name=plugin_name).one()
    db_row.disabled = True
    db_row.update_at = datetime.utcnow()
    model.db.session.commit()


def update_plugin_config_in_db(plugin_name: str, db_arguments: dict[str, Any]):
    db_row = model.PluginSoftware.query.filter_by(name=plugin_name).one()
    db_row.parameter = json.dumps(db_arguments)
    db_row.update_at = datetime.utcnow()
    model.db.session.commit()
