from flask_restful import Resource, reqparse
from github import Github
from flask_jwt_extended import jwt_required
import config
import json
import time
import model
import threading
import util as util
from model import db, SystemParameter
from resources import apiError, kubernetesClient
from resources.monitoring import verify_github_info
from resources.lock import get_lock_status, update_lock_status
from datetime import datetime, timedelta
from flask_socketio import Namespace, emit, disconnect
import os

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


def execute_pre_func(obj, args=None):
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
            "time": '"15 0 * * *"',
            "cron_args": 
                f'{value.get("account")}:{value.get("token")}' if value is not None else f'{system_parameter.value["account"]}:{system_parameter.value["token"]}'
        },
    }
    if system_param_name in id_mapping:
        id_info = id_mapping[system_param_name]
        if value is not None:
            execute_pre_func(id_info.get("execute_func"), id_info.get("func_args"))

        if active is not None and not active:
            args = f'{id_info["cron_name"]} off' 
        else:
            args = f'{id_info["cron_name"]} on {id_info["time"]} {id_info.get("cron_args", "")}'
        execute_modify_cron(args)
    if active is not None:
        system_parameter.active = active
    if value is not None:
        system_parameter.value = value
    db.session.commit()


def get_github_verify_execute_status():
    ret = get_lock_status("execute_sync_templ")

    sync_date = ret["sync_date"] if ret["sync_date"] is None else ret["sync_date"] + timedelta(hours=8)

    # Get log info
    output = get_github_verify_log()
    if output is None:
        ret["sync_date"] = str(ret["sync_date"])
        return ret

    output_list = output.split("----------------------------------------")

    run_time = output_list[1].split("\n")[1]
    if run_time is not None:
        run_time = datetime.strptime(run_time[:-4], '%a %d %b %Y %I:%M:%S %p')
        delta = run_time - sync_date

        # Check the log is previous run
        if delta.total_seconds() < 90:
            ret["status"] = {"first_stage": False, "second_stage": False}
        
            # Check the first stage is done
            ret["status"]["first_stage"] = output_list[-2].replace("\n", "").endswith("SUCCESS")

            # Check the second stage is done
            ret["status"]["second_stage"] = output_list[-1].replace("\n", "").endswith("SUCCESS")

    ret["sync_date"] = str(ret["sync_date"])
    return ret


def execute_sync_template_by_perl(cmd, name):
    update_lock_status("execute_sync_templ", is_lock=True, sync_date=datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"))
    deployer_node_ip = config.get('DEPLOYER_NODE_IP')
    if deployer_node_ip is None:
        # get the k8s cluster the oldest node ip
        deployer_node_ip = kubernetesClient.get_the_oldest_node()[0]

    value = SystemParameter.query.filter_by(name=name).first().value
    args = f'{value["account"]}:{value["token"]}'
    cmd = f"perl {cmd} {args} > /iiidevopsNFS/api-logs/sync-github-templ-api.log 2>&1"
    util.ssh_to_node_by_key(cmd, deployer_node_ip)
    update_lock_status("execute_sync_templ", is_lock=False, sync_date=datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"))


def execute_system_parameter_by_perl(name):
    name_perl_mapping = {"github_verify_info": "/home/rkeuser/deploy-devops/bin/sync-github-templ.pl"}
    if name not in name_perl_mapping:
        return
    if name == "github_verify_info":
        cmd = name_perl_mapping[name]
        thread = threading.Thread(target=execute_sync_template_by_perl, args=(cmd, name, ))
        thread.start()


def get_github_verify_log():
    file_path = "logs/sync-github-templ-api.log"
    if not os.path.isfile(file_path):
        return None
    with open(file_path, "r") as f:
        output = f.read()
    return output

def get_github_verify_log_websocket(data):
    if data == "get":
        ws_start_time = time.time()
        current_num = 0
        while (time.time() - ws_start_time) <= 900:
            if get_github_verify_log() is None:
                output = "Log is unavailable."
                emit("sync_templ_log", output)
                break
            
            # Call twice to prevent time lag.
            status = get_github_verify_execute_status()
            if status.get("status", {}).get("second_stage", False):    
                outputs = get_github_verify_log().split("\n") 
                output = "\n".join(outputs[current_num:])
                emit("sync_templ_log", output)
                break

            outputs = get_github_verify_log().split("\n")
            max_index = len(outputs)
            output = "\n".join(outputs[current_num:max_index])            
            emit("sync_templ_log", output)
            current_num = max_index

# --------------------- Resources ---------------------


class SystemParameters(Resource):
    @jwt_required
    def get(self):
        return util.success(get_system_parameter())

    @jwt_required
    def post(self):
        parser = reqparse.RequestParser()
        parser.add_argument('name', type=str)
        args = parser.parse_args()
        return util.success(execute_system_parameter_by_perl(args["name"]))

    @jwt_required
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

class ParameterGithubVerifyExecuteStatus(Resource):
    @jwt_required
    def get(self):
        return util.success(get_github_verify_execute_status())

class SyncTemplateWebsocketLog(Namespace):
    def on_connect(self):
        print('Connect')

    def on_disconnect(self):
        print('Disconnect')

    def on_get_perl_log(self, data):
        print('get_perl_log')
        get_github_verify_log_websocket(data)
        
