from nexus import nx_get_project_plugin_relation
import util
from model import MonitoringRecord, Project, db, NotificationMessage
from github import Github
from resources.redis import update_server_alive
from sqlalchemy import desc

from plugins.sonarqube.sonarqube_main import sq_get_current_measures, sq_list_project
from resources.harbor import hb_get_project_summary, hb_get_registries
from resources.redmine import redmine
from resources.gitlab import gitlab
from resources.rancher import rancher
from resources import logger
from resources.notification_message import create_notification_message, get_not_alive_notification_message_list, close_notification_message
from resources.kubernetesClient import ApiK8sClient as k8s_client
from resources.kubernetesClient import list_namespace_services, list_namespace_pods_info
from datetime import datetime
from resources import apiError
import subprocess
import os
import config
import pandas as pd
import re


DATETIMEFORMAT = "%Y-%m-%d %H:%M:%S"
AlertServiceIDMapping = {
    "Redmine not alive": 101,
    "GitLab not alive": 201,
    "Harbor not alive": 301,
    "Harbor pull limit exceed": 302,
    "Harbor NFS out of storage": 303,
    "K8s not alive": 401,
    "Sonarqube not alive": 501,
    "Rancher not alive": 601,
}


class Monitoring:

    def __init__(self, project_id=None):
        self.server = None
        self.pj_id = project_id
        self.all_alive = True
        self.__init_ids()
        self.error_message = None
        self.error_title = None
        self.alert_service_id = None
        self.detail = {}

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
            self.send_notification()
            self.store_in_monitoring_record()
        else:
            not_alive_messages = get_not_alive_notification_message_list(self.alert_service_id)
            if not_alive_messages != []:
                for not_alive_message in not_alive_messages:
                    close_notification_message(not_alive_message["id"])
                    self.send_server_back_notification(not_alive_message["title"])

        self.error_title = None

    def __check_server_alive(self, func_with_pj, func, *args, **kwargs):
        if self.__has_pj_id():
            alive = self.__is_server_alive(func_with_pj, *args)
        else:
            alive = self.__is_server_alive(func, **kwargs)
        self.__update_all_alive(alive)
        return alive

    def send_notification(self):
        title = f"{self.server} not alive" if self.error_title is None else self.error_title
        previous_server_notification = NotificationMessage.query.filter_by(title=title) \
            .order_by(desc(NotificationMessage.created_at)).all()
        if previous_server_notification == [] or \
                get_not_alive_notification_message_list(self.alert_service_id) == []:
            args = {
                "alert_level": 102,
                "title": title,
                "alert_service_id": self.alert_service_id,
                "message": str(self.error_message),
                "type_ids": [4],
                "type_parameters": {"role_ids": [5]}
            }
            create_notification_message(args, user_id=1)

    def store_in_monitoring_record(self):
        args = {
            "server": self.server,
            "message": self.error_message,
            "detail": self.detail
        }
        create_monitoring_record(args)

    def send_server_back_notification(self, title):
        if title.endswith("not alive"):
            title = f"{self.server} is back"
        else:
            title = f"{title} is solved"
        args = {
            "alert_level": 1,
            "title": title,
            "message": title,
            "type_ids": [4],
            "type_parameters": {"role_ids": [5]}
        }
        create_notification_message(args, user_id=1)

    def redmine_alive(self):
        self.server = "Redmine"
        self.alert_service_id = 101
        return self.__check_server_alive(
            redmine.rm_get_project, redmine.rm_list_projects, self.plan_pj_id)

    def gitlab_alive(self):
        self.server = "GitLab"
        self.alert_service_id = 201
        return self.__check_server_alive(
            gitlab.gl_get_project, gitlab.gl_get_user_list, self.gl_pj_id, args={})

    # Harbor
    def harbor_alive(self):
        self.server = "Harbor"
        self.alert_service_id = 301
        server_alive = self.__check_server_alive(
            hb_get_project_summary, hb_get_registries, self.hr_pj_id)
        if not server_alive:
            return server_alive

        harbor_alive = True
        for check_element in [harbor_nfs_storage_remain_limit, docker_image_pull_limit_alert]:
            check_element = check_element()
            element_alive = check_element["status"]
            self.error_title = str(check_element["error_title"])
            self.alert_service_id = AlertServiceIDMapping[self.error_title]
            if not element_alive:
                harbor_alive = element_alive
                self.error_message = str(check_element["message"])
                self.detail = check_element
            self.__update_all_alive(element_alive)
            if not element_alive:
                self.detail = {}
        return harbor_alive

    def k8s_alive(self):
        self.server = "K8s"
        self.alert_service_id = 401
        return self.__check_server_alive(
            list_namespace_services, k8s_client().get_api_resources, self.__get_project_name())

    def sonarqube_alive(self):
        self.server = "Sonarqube"
        self.alert_service_id = 501
        return self.__check_server_alive(
            sq_get_current_measures, sq_list_project, self.__get_project_name(), params={'p': 1, 'ps': 1})

    def rancher_alive(self):
        self.server = "Rancher"
        self.alert_service_id = 601
        return self.__check_server_alive(
            rancher.rc_get_pipeline_info, rancher.rc_get_project_pipeline, self.ci_pj_id, self.ci_pipeline_id)

    # all alive
    def check_project_alive(self):
        all_alive = {
            "alive": {
                "Redmine": self.redmine_alive(),
                "GitLab": self.gitlab_alive(),
                "Harbor": self.harbor_alive(),
                "K8s": self.k8s_alive(),
                "Sonarqube": self.sonarqube_alive(),
                "Rancher": self.rancher_alive(),
            },
            "all_alive": self.all_alive
        }
        return all_alive


def generate_alive_response(name):
    monitoring = Monitoring()
    alive_mapping = {
        "Redmine": monitoring.redmine_alive,
        "GitLab": monitoring.gitlab_alive,
        "Harbor": monitoring.harbor_alive,
        "K8s": monitoring.k8s_alive,
        "Sonarqube": monitoring.sonarqube_alive,
        "Rancher": monitoring.rancher_alive,
    }
    return {
        "name": name.capitalize(),
        "status": alive_mapping[name](),
        "message": monitoring.error_message,
        "datetime": datetime.utcnow().strftime(DATETIMEFORMAT),
    }


def server_alive(name):
    alive = generate_alive_response(name)
    status = alive["status"]
    update_server_alive(str(status))
    return alive


def row_to_dict(row):
    if row is None:
        return row
    return {key: getattr(row, key) for key in type(row).__table__.columns.keys()}


def create_monitoring_record(args):
    row = MonitoringRecord(
        server=args["server"],
        message=args["message"],
        detail=args.get("detail", {}),
        created_at=datetime.utcnow()
    )
    db.session.add(row)
    db.session.commit()


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
        "error_title": "Harbor pull limit exceed",
        "status": status,
        "remain_limit": limit,
        "message": message,
        "datetime": datetime.utcnow().strftime(DATETIMEFORMAT),
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
            "error_title": "Harbor NFS out of storage",
            "status": status,
            "total_size": ret["Size"],
            "used": ret["Used"],
            "avail": ret["Avail"],
            "message": "Nfs Folder Used percentage exceeded 75%!" if not status else None,
            "datetime": datetime.utcnow().strftime(DATETIMEFORMAT),
        }
    except Exception as e:
        return {
            "name": "Harbor nfs folder storage remain.",
            "error_title": "Harbor NFS out of storage",
            "status": False,
            "total_size": None,
            "used": None,
            "avail": None,
            "message": str(e),
            "datetime": datetime.utcnow().strftime(DATETIMEFORMAT),
        }
