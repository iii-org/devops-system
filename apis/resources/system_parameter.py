from flask_restful import Resource, reqparse
from github import Github

import config
import json
import model
import util as util
from model import db, SystemParameter
from resources import apiError, kubernetesClient
from resources.monitoring import verify_github_info


def row_to_dict(row):
    if row is None:
        return row
    return {key: getattr(row, key) for key in type(row).__table__.columns.keys()}


def execute_modify_cron(args):
    deployer_node_ip = config.get('DEPLOYER_NODE_IP')
    if deployer_node_ip is None:
        # get the k8s cluster the oldest node ip
        deployer_node_ip = kubernetesClient.get_the_oldest_node()[0]

    cmd = f"perl /home/rkeuser/deploy-devops/bin/modify-cron.pl {args}"
    output_str, error_str = util.ssh_to_node_by_key(cmd, deployer_node_ip) 
    output_str = output_str.replace("\n", "")
    if output_str.startswith("Error:"):
        raise Exception(output_str)
    return output_str


def execute_pre_func(obj, args):
    if obj is None:
        return
    if args is None:
        obj()
    else:
        obj(args)


def get_system_parameter():
    return [
        row_to_dict(system_parameter) for system_parameter in SystemParameter.query.all()]


def update_system_parameter(id, args):
    system_parameter = SystemParameter.query.get(id)
    system_param_name = system_parameter.name
    value, active = args.get("value"), args.get("active") 
    id_mapping = {
        "github_verify_info": {
            "execute_func": verify_github_info,
            "func_args": value,
            "cron_name": "sync_tmpl",
            "time": '"* 16 * * *"',
            "cron_args": f'{value.get("account")}:{value.get("token")}' if value is not None else ""
        },
    }
    if system_param_name in id_mapping:
        id_info = id_mapping[system_param_name]
        if active is not None and not active:
            args = f'{id_info["cron_name"]} off' 
        else:
            if value is not None:
                execute_pre_func(id_info.get("execute_func"), id_info.get("func_args"))
                args = f'{id_info["cron_name"]} on {id_info["time"]} {id_info.get("cron_args", "")}'
            else:
                args = f'{id_info["cron_name"]} on {id_info["time"]} {system_parameter.value["account"]}:{system_parameter.value["token"]}'
        execute_modify_cron(args)

    if active is not None:
        system_parameter.active = active
    if value is not None:
        system_parameter.value = value
    db.session.commit()


# --------------------- Resources ---------------------


class SystemParameters(Resource):
    def get(self):
        return util.success(get_system_parameter())

    def put(self, param_id):
        parser = reqparse.RequestParser()
        parser.add_argument('value', type=str, location='json')
        parser.add_argument('active', type=bool)
        args = parser.parse_args()
        if args.get("value") is not None:
            args["value"] = json.loads(args["value"].replace("\'", "\""))
            if not args["value"].get("token", "").startswith("ghp_"):
                raise apiError.DevOpsError(400, "Token should begin with 'ghp_'.",
                                           error=apiError.github_token_error("Token"))
        return util.success(update_system_parameter(param_id, args))
