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
import re

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
        return self.__check_server_alive(
            hb_get_project_summary, hb_get_registries, self.hr_pj_id)

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
    os.chmod('/home/john/devops-api/apis/resources/monitoring/docker_hub_remain_limit.sh', 0o777)
    results = subprocess.run(
        '/home/john/devops-api/apis/resources/monitoring/docker_hub_remain_limit.sh', stdout=subprocess.PIPE).stdout.decode('utf-8')
    for result in results.split("\n"):
        if result.startswith("ratelimit-remaining:"):
            regex = re.compile(r'ratelimit-remaining:(.\d+)')
            limit = regex.search(result).group(1).strip()
    
    if not limit.isdigit():
        status, message = False, "Can not get number of ratelimit-remaining!"
    elif int(limit) <= 30:
        limit = int(limit)
        status, message = False, "Pull remain time close to the limit(30 times)."
    else:
        limit = int(limit)
        status, message = True, None

    return {
        "name": "Harbor proxy remain limit",
        "status": status,
        "remain_limit": limit,
        "message": message,
        "datetime": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
    }



# --------------------- Resources ---------------------
class ServersAlive(Resource):
    @jwt_required
    def get(self):
        parser = reqparse.RequestParser()
        parser.add_argument('project_id', type=int)
        args = parser.parse_args()
        pj_id = args.get("project_id")

        monitoring = Monitoring(pj_id) if pj_id is not None else Monitoring()
        return util.success(monitoring.check_project_alive())


# redmine
class RedmineAlive(Resource):
    @jwt_required
    def get(self):
        return generate_alive_response("redmine")


# gitlab
class GitlabAlive(Resource):
    @jwt_required
    def get(self):
        return generate_alive_response("gitlab")


# harbor
class HarborAlive(Resource):
    @jwt_required
    def get(self):
        return generate_alive_response("harbor")

class HarborProxy(Resource):
    @jwt_required
    def get(self):
        return docker_image_pull_limit_alert()

# sonarQube
class SonarQubeAlive(Resource):
    @jwt_required
    def get(self):
        return generate_alive_response("sonarQube")


# rancher
class RancherAlive(Resource):
    @jwt_required
    def get(self):
        return generate_alive_response("rancher")


class RancherDefaultName(Resource):
    @jwt_required
    def get(self):
        rancher.rc_get_cluster_id()
        return {"default_cluster_name": rancher.cluster_id is not None}


# k8s
class K8sAlive(Resource):
    @jwt_required
    def get(self):
        return generate_alive_response("kubernetes")


class CollectPodRestartTime(Resource):
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

    def delete(self):
        expired_date = datetime.utcnow() - timedelta(days=30)
        ServerDataCollection.query.filter_by(type_id=1).filter(ServerDataCollection.create_at <= expired_date).delete()
        db.session.commit()


class PodAlert(Resource):
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

    def delete(self):
        expired_date = datetime.utcnow() - timedelta(days=30)
        AlertMessage.query.filter_by(
            resource_type="k8s", alert_code=10001).filter(AlertMessage.create_at <= expired_date).delete()
        db.session.commit()


class RemoveExtraExecutions(Resource):
    def post(self):
        remove_extra_executions()


# GitHub
class GithubTokenVerify(Resource):
    @jwt_required
    def post(self):
        role.require_admin()
        value = row_to_dict(SystemParameter.query.filter_by(name="github_verify_info").one())["value"]
        return util.success(verify_github_info(value))
