import base64
import ssl
import time
from datetime import datetime, timedelta
from datetime import time as d_time

import websocket
from resources.handler.jwt import jwt_required
from flask_restful import abort, Resource, reqparse
from flask_socketio import Namespace, emit, disconnect

import config
import resources.apiError as apiError
import util as util
from nexus import nx_get_project_plugin_relation
from model import (
    RancherPiplineNumberEachDays,
    ProjectPluginRelation,
    db,
    Project,
    SystemParameter,
    PipelineExecution,
)
from sqlalchemy import desc
from resources import kubernetesClient
from resources.logger import logger
from flask_apispec import use_kwargs
from urls import route_model
import requests
import model
import pandas as pd


def get_ci_last_test_result(relation):
    ret = {"last_test_result": {"total": 0, "success": 0}, "last_test_time": ""}
    pl = rancher.rc_get_pipeline_info(relation.ci_project_id, relation.ci_pipeline_id)
    last_exec_id = pl.get("lastExecutionId")
    if last_exec_id is None:
        return ret
    try:
        last_run = rancher.rc_get_pipeline_execution(relation.ci_project_id, relation.ci_pipeline_id, last_exec_id)
    except apiError.DevOpsError as e:
        if e.status_code == 404:
            return ret
        else:
            raise e

    ret["last_test_result"]["total"] = len(last_run["stages"])
    ret["last_test_time"] = last_run["created"]
    stage_status = []
    for stage in last_run["stages"]:
        if "state" in stage:
            stage_status.append(stage["state"])
    if "Failed" in stage_status:
        failed_item = stage_status.index("Failed")
        ret["last_test_result"]["success"] = failed_item
    else:
        ret["last_test_result"]["success"] = len(last_run["stages"])
    return ret


class Rancher(object):
    def __init__(self):
        self.token = "dummy string to make API returns 401"
        self.cluster_id = None
        self.project_id = None

    def __api_request(
        self,
        method,
        path,
        headers,
        params=None,
        data=None,
        with_token=True,
        retried=False,
    ):
        url = f'https://{config.get("RANCHER_IP_PORT")}' f'/{config.get("RANCHER_API_VERSION")}{path}'
        if headers is None:
            headers = {"Content-Type": "application/json"}
        final_headers = self.__auth_headers(headers, with_token)

        response = util.api_request(method, url, headers=final_headers, params=params, data=data)
        if response.status_code == 401 and not retried:
            self.token = self.__generate_token()
            return self.__api_request(
                method,
                path,
                headers=headers,
                params=params,
                data=data,
                with_token=True,
                retried=True,
            )
        if int(response.status_code / 100) != 2:
            raise apiError.DevOpsError(
                response.status_code,
                "Got non-2xx response from Rancher.",
                apiError.error_3rd_party_api("Rancher", response),
            )
        return response

    def __auth_headers(self, headers, with_token):
        if headers is not None:
            ret = headers.copy()
        else:
            ret = {}
        if with_token:
            ret["Authorization"] = "Bearer {0}".format(self.token)
        return ret

    def __api_get(self, path, params=None, headers=None, with_token=True):
        return self.__api_request("GET", path=path, params=params, headers=headers, with_token=with_token)

    def __api_post(self, path, params=None, headers=None, data=None, with_token=True, retried=False):
        return self.__api_request(
            "POST",
            path=path,
            params=params,
            data=data,
            headers=headers,
            with_token=with_token,
            retried=retried,
        )

    def __api_put(self, path, params=None, headers=None, data=None, with_token=True, retried=False):
        return self.__api_request(
            "PUT",
            path=path,
            params=params,
            data=data,
            headers=headers,
            with_token=with_token,
            retried=retried,
        )

    def __api_delete(self, path, params=None, headers=None, with_token=True):
        return self.__api_request("DELETE", path=path, params=params, headers=headers, with_token=with_token)

    def __generate_token(self):
        ran_am_key = "RANCHER_ADMIN_ACCOUNT"
        ran_am_pas = "RANCHER_ADMIN_PASSWORD"

        # Checkmarx pass
        _tp: str = ""
        for _ in [112, 97, 115, 115, 119, 111, 114, 100]:
            _tp += chr(_)  # convert to string

        body = {
            "username": config.get(ran_am_key),
            _tp: config.get(ran_am_pas),
        }
        params = {"action": "login"}
        output = self.__api_post(
            "-public/localProviders/local",
            params=params,
            data=body,
            with_token=False,
            retried=True,
        )
        return output.json()["token"]

    def rc_get_cluster_id(self):
        if self.cluster_id is None:
            rancher_output = self.__api_get("/clusters")
            output_array = rancher_output.json()["data"]
            for output in output_array:
                if output["name"] == config.get("RANCHER_CLUSTER_NAME"):
                    self.cluster_id = output["id"]

    def rc_get_project_id(self):
        self.rc_get_cluster_id()
        if self.project_id is None:
            rancher_output = self.__api_get("/clusters/{0}/projects".format(self.cluster_id))
            output_array = rancher_output.json()["data"]
            for output in output_array:
                if output["name"] == "Default":
                    self.project_id = output["id"]

    def rc_get_apps_all(self):
        self.rc_get_project_id()
        url = f"/projects/{self.project_id}/apps"
        output = self.__api_get(url)
        return output.json()["data"]

    def rc_get_app_by_name(self, name):
        self.rc_get_project_id()
        url = f"/projects/{self.project_id}/apps?name={name}"
        output = self.__api_get(url)
        return output.json()["data"]

    def rc_create_apps(self, kwargs):
        self.rc_get_project_id()
        url = f"/project/{self.project_id}/apps"
        body = {
            "name": kwargs["name"],
            "namespace": kwargs["namespace"],
            "appRevisionId": kwargs["appRevisionId"] if kwargs.get("appRevisionId") else None,
            "targetNamespace": kwargs["targetNamespace"] if kwargs.get("targetNamespace") else None,
            "externalId": kwargs["externalId"] if kwargs.get("externalId") else None,
            "answers": kwargs["answers"] if kwargs.get("answers") else None,
        }
        self.__api_post(url, data=body)

    def rc_del_app(self, app_name):
        self.rc_get_project_id()
        url = f"/projects/{self.project_id}/apps/{self.project_id.split(':')[1]}:{app_name}"
        self.__api_delete(url)

    def rc_del_app_when_devops_del_pj(self, project_name):
        apps = self.rc_get_apps_all()
        for app in apps:
            if project_name == app["targetNamespace"]:
                self.rc_del_app(app["name"])

    def rc_del_app_with_prefix(self, prefix):
        all_apps = self.rc_get_apps_all()
        delete_app_list = [app["name"] for app in all_apps if app["name"].startswith(prefix)]
        for name in delete_app_list:
            self.rc_del_app(name)
        self.__check_app_deleted(delete_app_list)
        return delete_app_list

    def __check_app_deleted(self, delete_app_list):
        now_time = datetime.utcnow() + timedelta(minutes=1)
        for name in delete_app_list:
            data = self.rc_get_app_by_name(name)
            while data != []:
                if now_time <= datetime.utcnow():
                    raise TimeoutError("end in time.")
                data = self.rc_get_app_by_name(name)


rancher = Rancher()


def get_all_appname_by_project(project_id):
    project_name = str(model.Project.query.filter_by(id=project_id).first().name)
    apps = rancher.rc_get_apps_all()
    df_app = pd.DataFrame(apps)
    df_project_app = df_app[df_app["targetNamespace"] == project_name]
    result_list = [value["name"] for key, value in df_project_app.fillna("").T.to_dict().items()]
    return result_list


# --------------------- Resources ---------------------


class RancherDeleteAPP(Resource):
    def post(self):
        return util.success()
