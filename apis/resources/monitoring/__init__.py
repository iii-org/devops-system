from flask_restful import Resource, reqparse
from nexus import nx_get_project_plugin_relation
import util
from model import Project, db, ServerDataCollection, SystemParameter, AlertMessage, Project
from github import Github
from flask_jwt_extended import jwt_required
from resources import role

from plugins.sonarqube.sonarqube_main import sq_get_current_measures, sq_list_project
from resources.harbor import hb_get_project_summary, hb_get_registries
from resources.redmine import redmine
from resources.gitlab import gitlab
from resources.rancher import rancher, remove_extra_executions
from resources import logger
from resources.kubernetesClient import ApiK8sClient as k8s_client
from resources.kubernetesClient import list_namespace_services, list_namespace_pods_info
from datetime import datetime, timedelta
from datetime import time as d_time
from sqlalchemy import desc
from resources import apiError
import subprocess
import os
import config
import pandas as pd
import re
from flask_apispec import marshal_with, doc, use_kwargs
from flask_apispec.views import MethodResource
from . import route_model

class Monitoring:
    def __init__(self, project_id=None):
        self.pj_id = project_id
        self.all_alive = True
        self.__init_ids()
        self.error_message = None

    def __init_ids(self):
        self.plan_pj_id = None
        self.gl_pj_id = None
        self.hr_pj_id = None
        self.ci_pj_id = None
        self.ci_pipeline_id = None

        if self.pj_id is not None:
            relation = nx_get_project_plugin_relation(nexus_project_id=self.pj_id)
            self.plan_pj_id = relation.plan_project_id
            self.gl_pj_id = relation.git_repository_id
            self.hr_pj_id = relation.harbor_project_id
            self.ci_pj_id = relation.ci_project_id
            self.ci_pipeline_id = relation.ci_pipeline_id

    def __is_server_alive(self, func, *args, **kwargs):
        try:
            func(*args, **kwargs)
            return True
        except Exception as e:
            logger.logger.info(f'{func.__name__} : {str(e)}')
            self.error_message = str(e)
            return False

    def __get_project_name(self):
        pj = Project.query.get(self.pj_id)
        return pj.name if pj is not None else None

    def __has_pj_id(self):
        return self.pj_id is not None

    def __update_all_alive(self, alive):
        if not alive:
            self.all_alive = alive

    def __check_server_alive(self, func_with_pj, func, *args, **kwargs):
        if self.__has_pj_id():
            alive = self.__is_server_alive(func_with_pj, *args)
        else:
            alive = self.__is_server_alive(func, **kwargs)
        self.__update_all_alive(alive)
        return alive

    def redmine_alive(self):
        return self.__check_server_alive(
            redmine.rm_get_project, redmine.rm_list_projects, self.plan_pj_id)

    def gitlab_alive(self):
        return self.__check_server_alive(
            gitlab.gl_get_project, gitlab.gl_get_user_list, self.gl_pj_id, args={})

    # Harbor
    def harbor_alive(self):
        server_alive = self.__check_server_alive(
            hb_get_project_summary, hb_get_registries, self.hr_pj_id)
        if not server_alive:
            return server_alive
        # Storage alive
        harbour_storage = harbor_nfs_storage_remain_limit()
        storage_alive = harbour_storage["status"]
        if not storage_alive:
            self.error_message = str(harbour_storage["message"])
            self.__update_all_alive(storage_alive)    
        return storage_alive

    def k8s_alive(self):
        return self.__check_server_alive(
            list_namespace_services, k8s_client().get_api_resources, self.__get_project_name())

    def sonarqube_alive(self):
        return self.__check_server_alive(
            sq_get_current_measures, sq_list_project, self.__get_project_name(), params={'p': 1, 'ps': 1})

    def rancher_alive(self):
        return self.__check_server_alive(
            rancher.rc_get_pipeline_info, rancher.rc_get_project_pipeline, self.ci_pj_id, self.ci_pipeline_id)

    def check_project_alive(self):
        return {
            "alive": {
                "redmine": self.redmine_alive(),
                "gitlab": self.gitlab_alive(),
                "harbor": self.harbor_alive(),
                "k8s": self.k8s_alive(),
                "sonarqube": self.sonarqube_alive(),
                "rancher": self.rancher_alive(),
            },
            "all_alive": self.all_alive
        }


def generate_alive_response(name):
    monitoring = Monitoring()
    alive_mapping = {
        "redmine": monitoring.redmine_alive,
        "gitlab": monitoring.gitlab_alive,
        "harbor": monitoring.harbor_alive,
        "kubernetes": monitoring.k8s_alive,
        "sonarQube": monitoring.sonarqube_alive,
        "rancher": monitoring.rancher_alive,
    }
    return {
        "name": name.capitalize(),
        "status": alive_mapping[name](),
        "message": monitoring.error_message,
        "datetime": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
    }


def row_to_dict(row):
    if row is None:
        return row
    return {key: getattr(row, key) for key in type(row).__table__.columns.keys()}


def verify_github_info(value):
    account = value["account"]
    token = value["token"]
    g = Github(login_or_token=token)
    try:
        login = g.get_user().login
    except:
        raise apiError.DevOpsError(
            400,
            'Token is invalid.',
            apiError.error_with_alert_code("github", 20001, 'Token is invalid.', value))

    if login != account:
        raise apiError.DevOpsError(
            400,
            'Token is not belong to this account.',
            apiError.error_with_alert_code("github", 20002, 'Token is not belong to this account.', value))

    if len([repo for repo in g.search_repositories(query='iiidevops in:name')]) == 0:
        raise apiError.DevOpsError(
            400,
            'Token is not belong to this project(iiidevops).',
            apiError.error_with_alert_code("github", 20003, 'Token is not belong to this project(iiidevops).', value))


def docker_image_pull_limit_alert():
    limit = ""
    os.chmod('./apis/resources/monitoring/docker_hub_remain_limit.sh', 0o777)
    results = subprocess.run(
        './apis/resources/monitoring/docker_hub_remain_limit.sh', stdout=subprocess.PIPE).stdout.decode('utf-8')
    for result in results.split("\n"):
        if result.startswith("ratelimit-remaining:"):
            regex = re.compile(r'ratelimit-remaining:(.\d+)')
            limit = regex.search(result).group(1).strip()
            break

    if limit == "":
        status, message = False, "Can not get number of ratelimit-remaining!"
    else:
        limit = int(limit)
        status = limit > 30
        message = None if status else "Pull remain time close to the limit(30 times)."

    return {
        "name": "Harbor proxy remain limit",
        "status": status,
        "remain_limit": limit,
        "message": message,
        "datetime": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
    }


def harbor_nfs_storage_remain_limit():
    try:
        output_str, _ = util.ssh_to_node_by_key(
            'cd /iiidevopsNFS/ ; df -h' ,config.get("DEPLOYER_NODE_IP"))
        
        contents = output_str.split("\n")
        data_frame_contents = [
            list(filter(lambda a: a != "", content.split(" "))) for content in contents]
        df = pd.DataFrame(data_frame_contents[1:], columns = data_frame_contents[0][:-1])
        out_df = df[df.loc[:,"Mounted"] == "/"]
        ret = out_df.to_dict("records")[0]
        
        status = int(ret["Use%"].replace("%", "")) < 75
        return {
            "name": "Harbor nfs folder storage remain.",
            "status": status,
            "total_size": ret["Size"],
            "used": ret["Used"],
            "avail": ret["Avail"],
            "message": "Nfs Folder Used percentage exceeded 75%!" if not status else None,
            "datetime": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
        }
    except Exception as e:
        return {
            "name": "Harbor nfs folder storage remain.",
            "status": False,
            "total_size": None,
            "used": None,
            "avail": None,
            "message": str(e),
            "datetime": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
        }
    

# --------------------- Resources ---------------------
@doc(tags=['Monitoring'], description="Get All plugin servers' status")
@use_kwargs(route_model.ServersAliveSchema, location="query")
@marshal_with(route_model.ServersAliveResponse)
class ServersAlive(MethodResource):
    @jwt_required
    def get(self, **kwargs):
        pj_id = kwargs.get("project_id")
        monitoring = Monitoring(pj_id) if pj_id is not None else Monitoring()
        return util.success(monitoring.check_project_alive())


# redmine
@doc(tags=['Monitoring'], description="Get Redmine server's status")
@marshal_with(route_model.ServerAliveResponse)
class RedmineAlive(MethodResource):
    @jwt_required
    def get(self):
        return generate_alive_response("redmine")


# gitlab
@doc(tags=['Monitoring'], description="Get Gitlab server's status")
@marshal_with(route_model.ServerAliveResponse)
class GitlabAlive(MethodResource):
    @jwt_required
    def get(self):
        return generate_alive_response("gitlab")


# harbor
@doc(tags=['Monitoring'], description="Get Harbor server's status")
@marshal_with(route_model.ServerAliveResponse)
class HarborAlive(MethodResource):
    @jwt_required
    def get(self):
        return generate_alive_response("harbor")

@doc(tags=['Monitoring'], description="Get Harbor remain time of pull image from docker hub")
@marshal_with(route_model.HarborProxyResponse)
class HarborProxy(MethodResource):
    @jwt_required
    def get(self):
        return docker_image_pull_limit_alert()

@doc(tags=['Monitoring'], description="Get Harbor server's status")
@marshal_with(route_model.HarborStorageResponse)
class HarborStorage(MethodResource):
    @jwt_required
    def get(self):
        return harbor_nfs_storage_remain_limit()

# sonarQube
@doc(tags=['Monitoring'], description="Get SonarQube server's status")
@marshal_with(route_model.ServerAliveResponse)
class SonarQubeAlive(MethodResource):
    @jwt_required
    def get(self):
        return generate_alive_response("sonarQube")


# rancher
@doc(tags=['Monitoring'], description="Get Rancher server's status")
@marshal_with(route_model.ServerAliveResponse)
class RancherAlive(MethodResource):
    @jwt_required
    def get(self):
        return generate_alive_response("rancher")


@doc(tags=['Monitoring'], description="Check Rancher name is changed to default or not")
@marshal_with(route_model.RancherDefaultNameResponse)
class RancherDefaultName(MethodResource):
    @jwt_required
    def get(self):
        rancher.rc_get_cluster_id()
        return {"default_cluster_name": rancher.cluster_id is not None}


# k8s
@doc(tags=['Monitoring'], description="Get Kubernetes server's status")
@marshal_with(route_model.ServerAliveResponse)
class K8sAlive(MethodResource):
    @jwt_required
    def get(self):
        return generate_alive_response("kubernetes")


class CollectPodRestartTime(MethodResource):
    @doc(tags=['Monitoring'], description="Collect K8s pods' restart time.")
    def post(self):
        collect_at = datetime.utcnow().strftime("%Y-%m-%d %H:00:00")
        for pj in Project.query.all():
            project_pods = list_namespace_pods_info(pj.name)
            if project_pods == []:
                continue
            for project_pod in project_pods:
                for container in project_pod["containers"]:
                    row = ServerDataCollection(
                        type_id=1,
                        project_id=pj.id,
                        detail={
                            "pod_name": project_pod["name"],
                            "containers_name": container["name"],
                        },
                        value={"value": container["restart"]},
                        create_at=datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
                        collect_at=collect_at
                    )
                    db.session.add(row)
                    db.session.commit()

    @doc(tags=['Monitoring'], description="Delete out of time limit pods.")
    def delete(self):
        expired_date = datetime.utcnow() - timedelta(days=30)
        ServerDataCollection.query.filter_by(type_id=1).filter(ServerDataCollection.create_at <= expired_date).delete()
        db.session.commit()


class PodAlert(MethodResource):
    @doc(tags=['Monitoring'], description="Send alrt message to pod which out of restart times limit.")
    def post(self):
        condition = SystemParameter.query.filter_by(name="k8s_pod_restart_times_limit").one()
        if not condition.active or condition.active is None:
            return
        limit_times = condition.value["limit_times"]
        datetime_now = datetime.utcnow().strftime("%Y-%m-%d %H:%M")

        limit_hour = datetime.utcnow() - timedelta(hours=1)
        limit_hour = limit_hour.strftime("%Y-%m-%d %H:00:00")
        data_collections = ServerDataCollection.query.filter_by(
            type_id=1).filter(ServerDataCollection.collect_at >= limit_hour)

        mapping = {}
        for data_collection in data_collections:
            detail = data_collection.detail
            restart_times = data_collection.value["value"]
            mapping.setdefault(
                f'{data_collection.project_id}=={detail["pod_name"]}=={detail["containers_name"]}', []).append(restart_times)

        for detail, times in mapping.items():
            if len(times) >= 2 and (max(times) - min(times)) > limit_times:
                total_restart_times = max(times) - min(times)
                details = detail.split("==")
                row = AlertMessage(
                    resource_type="k8s",
                    detail={"project_name": Project.query.filter_by(id=details[0]).one().name},
                    alert_code=10001,
                    message=f"Restart times of pod({details[1]}) belong in container({details[2]}) has surpassed 20 times({total_restart_times}) in 1 hour.",
                    create_at=datetime_now
                )
                db.session.add(row)
                db.session.commit()

    @doc(tags=['Monitoring'], description="Delete out of time limit pod alert message.")
    def delete(self):
        expired_date = datetime.utcnow() - timedelta(days=30)
        AlertMessage.query.filter_by(
            resource_type="k8s", alert_code=10001).filter(AlertMessage.create_at <= expired_date).delete()
        db.session.commit()

@doc(tags=['Monitoring'], description="Remove extra k8s executions.")
class RemoveExtraExecutions(MethodResource):
    def post(self):
        remove_extra_executions()


# GitHub
@doc(tags=['Monitoring'], description="Validate Github token.")
@marshal_with(route_model.GithubTokenVerifyResponse)
class GithubTokenVerify(MethodResource):
    @jwt_required
    def post(self):
        role.require_admin()
        value = row_to_dict(SystemParameter.query.filter_by(name="github_verify_info").one())["value"]
        return util.success(verify_github_info(value))
