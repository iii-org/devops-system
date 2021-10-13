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


def get_system_parameter():
    return [
        row_to_dict(system_parameter) for system_parameter in SystemParameter.query.all()]


def update_system_parameter(id, args):
    id_mapping = {
        2: {
            "execute_func": verify_github_info,
            "cron_name": "sync_tmpl",
            "time": '"* 16 * * *"',
            "args": f'{args["value"].get("account")}:{args["value"].get("token")}'
        },
    }
    value = args["value"]
    active = args.get("active") 
    if id in id_mapping:
        id_mapping[id]["execute_func"](value)
        if args.get("active") is not None:
            if args["active"]:
                args = f'{id_mapping[id]["cron_name"]} on {id_mapping[id]["time"]} {id_mapping[id].get("args", "")}'  
            else:
                args = f'{id_mapping[id]["cron_name"]} off' 
            execute_modify_cron(args)
    system_parameter = SystemParameter.query.get(id)
    if args.get("active") is not None:
        system_parameter.active = args["active"]
    system_parameter.value = value
    db.session.commit()


# --------------------- Resources ---------------------


class SystemParameters(Resource):
    def get(self):
        return util.success(get_system_parameter())

    def put(self, param_id):
        parser = reqparse.RequestParser()
        parser.add_argument('value', type=str, location='json', required=True)
        parser.add_argument('active', type=bool)
        args = parser.parse_args()
        args["value"] = json.loads(args["value"].replace("\'", "\""))
        return util.success(update_system_parameter(param_id, args))
