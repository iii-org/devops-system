import os
import re
import subprocess
import json
from datetime import datetime
from time import sleep

import config
import pandas as pd
import util
from github import Github
from model import MonitoringRecord, NotificationMessage, Project, ProjectPluginRelation, db, PluginSoftware, SystemParameter
from nexus import nx_get_project_plugin_relation
from plugins.sonarqube.sonarqube_main import (sq_get_current_measures,
                                              sq_list_project)
from resources import apiError, logger
from resources.gitlab import gitlab
from resources.harbor import hb_get_project_summary, hb_get_registries
from resources.kubernetesClient import ApiK8sClient as k8s_client
from resources.kubernetesClient import (list_namespace_pods_info,
                                        list_namespace_services)
from resources.notification_message import (
    close_notification_message, create_notification_message,
    get_unclose_notification_message,
    get_unread_notification_message_list)
from resources.rancher import rancher
from resources.redis import update_server_alive
from resources.redmine import redmine
from resources.mail import Mail, mail_server_is_open
from sqlalchemy import desc
from resources.resource_storage import get_project_resource_storage_level, compare_operator

DATETIMEFORMAT = "%Y-%m-%d %H:%M:%S"
AlertServiceIDMapping = {
    "Redmine not alive": 101,
    "GitLab not alive": 201,
    "Gitlab projects are exceeded its storage limit": 202,
    "Harbor not alive": 301,
    "Harbor pull limit exceed": 302,
    "Harbor NFS out of storage": 303,
    "K8s not alive": 401,
    "Sonarqube not alive": 501,
    "Rancher not alive": 601,
    "Rancher AppRevision counts out of limit": 602
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
        self.invalid_project_id_mapping = {}

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
            send_back_notifcation_titles = []
            not_alive_messages = get_unclose_notification_message(self.alert_service_id)
            if not_alive_messages is not None and len(not_alive_messages) > 0:
                for not_alive_message in not_alive_messages:
                    close_notification_message(not_alive_message["id"])
                    not_alive_mes_title = not_alive_message["title"]
                    
                    # Do not need to send same recover notification and notification which not 
                    # in AlertServiceIDMapping's keys
                    if not_alive_mes_title in AlertServiceIDMapping and \
                        not_alive_mes_title not in send_back_notifcation_titles:
                        send_back_notifcation_titles.append(not_alive_mes_title)
                
                for send_back_notifcation_title in send_back_notifcation_titles:
                    self.send_server_back_notification(send_back_notifcation_title)

        self.error_title = None

    def __check_server_alive(self, func_with_pj, func, *args, **kwargs):
        if self.__has_pj_id():
            alive = self.__is_server_alive(func_with_pj, *args)
        else:
            alive = self.__is_server_alive(func, **kwargs)
        self.__update_all_alive(alive)
        return alive

    def __check_plugin_server_alive(self, func):
        server_alive = func()
        if not server_alive["alive"]:
            if server_alive.get("message") is not None:
                self.error_message = server_alive["message"]
            else:
                self.error_message = f"{self.server} not alive"
        self.__update_all_alive(server_alive["alive"])
        return server_alive["alive"]

    def __check_server_element_alive(self, func):
        element_ret = func()
        element_alive = element_ret["status"]
        self.error_title = str(element_ret["error_title"])
        self.alert_service_id = AlertServiceIDMapping[self.error_title]
        if not element_alive:
            self.error_message = str(element_ret["message"])
            self.detail = element_ret
            self.invalid_project_id_mapping = element_ret.get("invalid_project_id_mapping", {})
        self.__update_all_alive(element_alive)
        return element_alive

    def send_notification(self):
        title = f"{self.server} not alive" if self.error_title is None else self.error_title
        previous_server_notification = NotificationMessage.query.filter_by(title=title) \
            .order_by(desc(NotificationMessage.created_at)).all()
        if previous_server_notification == [] or \
                get_unread_notification_message_list(alert_service_id=self.alert_service_id) == []:
            args = {
                "alert_level": 102,
                "title": title,
                "alert_service_id": self.alert_service_id,
                "message": str(self.error_message),
                "type_ids": [4],
                "type_parameters": {"role_ids": [5]}
            }
            create_notification_message(args, user_id=1)

            # Send notification to type 2 (project)
            if self.invalid_project_id_mapping != {}:
                for pj_id, mes in self.invalid_project_id_mapping.items():
                    args = {
                        "alert_level": 102,
                        "title": str(mes),
                        "alert_service_id": self.alert_service_id,
                        "message": str(mes),
                        "type_ids": [2],
                        "type_parameters": {"project_ids": [int(pj_id)]}
                    }
                    create_notification_message(args, user_id=1)
                    sleep(0.5)
                self.invalid_project_id_mapping = {} 


    def store_in_monitoring_record(self):
        args = {
            "server": self.server,
            "message": self.error_message,
            "detail": self.detail
        }
        create_monitoring_record(args)
        self.detail = {}

    def send_server_back_notification(self, title):
        recover_message_mapping = {
            "Harbor NFS out of storage": "All nodes' nfs folder used percentage back to health level.",
            "Harbor pull limit exceed": "All nodes' pull remain rate back to health level.",
            "Gitlab projects are exceeded its storage limit": "All projects' storage are in health level."
        }

        if title.endswith("not alive"):
            recover_title = f"{self.server} is back"
        else:
            recover_title = f"{title} is solved"
        args = {
            "alert_level": 1,
            "title": recover_title,
            "message": recover_message_mapping.get(title, recover_title),
            "type_ids": [4],
            "type_parameters": {"role_ids": [5]}
        }
        create_notification_message(args, user_id=1)

    def redmine_alive(self):
        self.server = "Redmine"
        self.alert_service_id = 101
        return self.__check_server_alive(
            redmine.rm_get_project, redmine.rm_list_projects, self.plan_pj_id)

    # Gitlab
    def gitlab_alive(self, is_project=False):
        self.server = "GitLab"
        self.alert_service_id = 201
        gitlab_alive = self.__check_server_alive(
            gitlab.gl_get_project, gitlab.gl_get_user_list, self.gl_pj_id, args={})
        if not gitlab_alive or is_project:
            return gitlab_alive

        for check_element in [gitlab_projects_storage_limit]:
            if not self.__check_server_element_alive(check_element):
                gitlab_alive = False
        return gitlab_alive
        

    # Harbor
    def harbor_alive(self, is_project=False):
        self.server = "Harbor"
        self.alert_service_id = 301
        harbor_alive = self.__check_server_alive(
            hb_get_project_summary, hb_get_registries, self.hr_pj_id)
        if not harbor_alive or is_project:
            return harbor_alive    
        harbor_alive = True

        # offline env doesn't need to check pull limit
        check_elements = [harbor_nfs_storage_remain_limit]
        if (config.get("deploy_env") or "online") == "online":
            check_elements.append(docker_image_pull_limit_alert)
        for check_element in check_elements:
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
        rancher_alive = self.__check_server_alive(
            rancher.rc_get_pipeline_info, rancher.rc_get_project_pipeline, self.ci_pj_id, self.ci_pipeline_id)
        if not rancher_alive:
            return rancher_alive

        for check_element in [rancher_projects_limit_num]:
            if not self.__check_server_element_alive(check_element):
                rancher_alive = False
        return rancher_alive

    # Plugins
    def excalidraw_alive(self):
        from resources.excalidraw import check_excalidraw_alive
        self.server = "Excalidraw"
        self.alert_service_id = 1001
        return self.__check_plugin_server_alive(check_excalidraw_alive)

    def ad_alive(self):
        from plugins.ad.ad_main import check_ad_alive
        self.server = "ad"
        self.alert_service_id = 1002
        return self.__check_plugin_server_alive(check_ad_alive) 

    def smtp_alive(self):
        self.server = "SMTP"
        self.alert_service_id = 1101
        return self.__check_plugin_server_alive(check_mail_server)

    def check_plugin_is_open(self, plugin):
        try:
            plugin_software = PluginSoftware.query.filter_by(name=plugin).first()
            plugin_disabled = plugin_software is not None and not plugin_software.disabled
        except:
            plugin_disabled = False
        return plugin_disabled

    def check_plugin_alive(self):
        ret = {}
        plugin_mapping = {
            "excalidraw": {
                "alive": self.excalidraw_alive,
            },
            "mail": {
                "alive": self.smtp_alive, 
                "is_open": mail_server_is_open
            },
            "ad": {
                "alive": self.ad_alive,
            }
        }
        for plugin, plugin_info in plugin_mapping.items():
            in_plugin_db = plugin_info.get("is_open") is None
            if (in_plugin_db and self.check_plugin_is_open(plugin)) or \
                (not in_plugin_db and plugin_info["is_open"]()):
                alive = plugin_info["alive"]()
                ret[plugin] = alive
        return ret

    # all alive
    def check_project_alive(self, is_project=False):
        '''
        when 'is_project' is True, only check servers are working.
        '''
        plugin_alive_dict = self.check_plugin_alive()
        all_alive = {
            "alive": {
                "Redmine": self.redmine_alive(),
                "GitLab": self.gitlab_alive(is_project),
                "Harbor": self.harbor_alive(is_project),
                "K8s": self.k8s_alive(),
                "Sonarqube": self.sonarqube_alive(),
                "Rancher": self.rancher_alive(),
            },
            "all_alive": self.all_alive
        }
        all_alive["alive"] |= plugin_alive_dict
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
        not_alive_messages = get_unread_notification_message_list(title="GitHub token is unavailable")
        if not_alive_messages is not None and len(not_alive_messages) > 0:
            for not_alive_message in not_alive_messages:
                close_notification_message(not_alive_message["id"])
            back_to_alive_title = "GitHub token is back to available."
            create_notification_message({
                "alert_level": 1,
                "title": back_to_alive_title,
                "message": back_to_alive_title,
                "type_ids": [4],
                "type_parameters": {"role_ids": [5]}
            })
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
    output_str, _ = util.ssh_to_node_by_key(
            'perl deploy-devops/bin/get-cluster-pull-ratelimit.pl', config.get("DEPLOYER_NODE_IP")) 
    outputs = output_str.split("\n")
    if "---" in outputs:
        nodes_info = outputs[outputs.index("---") + 1]
    else:
        nodes_info = max(output_str.split("\n"))
    
    try:
        nodes_info = json.loads(nodes_info)
    except:
        return {
            "name": "Harbor proxy remain limit",
            "error_title": "Harbor pull limit exceed",
            "status": False,
            "remain_limit": 0,
            "message": "Can not get all nodes' pull limit info.",
            "datetime": datetime.utcnow().strftime(DATETIMEFORMAT),
        }
    error_nodes_message = []
    for node_info in nodes_info:
        limit = node_info.get("ratelimit-remaining")
        if limit is None:
            error_nodes_message.append(f"Can not get node {node_info.get('node')} pull remain times.")
        elif limit < 30:
            error_nodes_message.append(f"Node {node_info.get('node')} pull remain times({limit}) below limit(30 times).")

    return {
        "name": "Harbor proxy remain limit",
        "error_title": "Harbor pull limit exceed",
        "status": error_nodes_message == [],
        "message": "\n".join(error_nodes_message),
        "datetime": datetime.utcnow().strftime(DATETIMEFORMAT),
    }


def harbor_nfs_storage_remain_limit():
    output_str, _ = util.ssh_to_node_by_key(
        'perl deploy-devops/bin/get-cluster-df.pl', config.get("DEPLOYER_NODE_IP"))
    nodes_storage_info = max(output_str.split('\n'))
    try:
        nodes_storage_info = json.loads(nodes_storage_info)
    except:
        return {
            "name": "Harbor nfs folder storage remain.",
            "error_title": "Harbor NFS out of storage",
            "status": False,
            "total_size": None,
            "used": None,
            "avail": None,
            "message": "Can not get all nodes' nft storage.",
            "datetime": datetime.utcnow().strftime(DATETIMEFORMAT),
        }
    error_nodes_message = []
    for node_storage_info in nodes_storage_info:
        usage = node_storage_info.get("Usage")
        if usage is None:
            error_nodes_message.append(f"Can not get node {node_storage_info.get('node')} nfs usage.")
        elif int(usage.replace("%", "")) > 75:
            error_nodes_message.append(f"Node {node_storage_info.get('node')} nfs Folder Used percentage({usage}) exceeded 75%!")
    
    return {
        "name": "Harbor nfs folder storage remain.",
        "error_title": "Harbor NFS out of storage",
        "status": error_nodes_message == [],
        "message": "\n".join(error_nodes_message),
        "datetime": datetime.utcnow().strftime(DATETIMEFORMAT),
    }


def check_mail_server():
    ret = {"alive": True, "message": ""}
    try:
        Mail.check_mail_server()
    except Exception as e:
        ret["alive"], ret["message"] = False, str(e)
    return ret


def gitlab_projects_storage_limit():
    invalid_project_id_mapping = {}
    project_rows = db.session.query(Project, ProjectPluginRelation).join(
        ProjectPluginRelation, Project.id==ProjectPluginRelation.project_id)
    for project_row in project_rows:
        project_obj, repo_id = project_row.Project, project_row.ProjectPluginRelation.git_repository_id
        pj_resource_storage = get_project_resource_storage_level(project_obj.id)
        gitlab_resource_info = pj_resource_storage.get("gitlab")
        if gitlab_resource_info is not None:
            pj_gl_storage_usage_dict = gitlab.gl_get_storage_usage(repo_id)
            used = int(pj_gl_storage_usage_dict.get("used", {}).get("value", 0)) / 1024 / 1024 / 1024
            max_used = int(pj_gl_storage_usage_dict.get("quota", {}).get("value", 0)) / 1024 / 1024 / 1024   
            limit = gitlab_resource_info["limit"]
            if compare_operator(
                gitlab_resource_info["comparison"],
                used,
                limit,
                max_used,
                percentage=gitlab_resource_info["percentage"]
            ):
                invalid_project_id_mapping[project_obj.id] = f"Project: {project_obj.name} 在gitlab上的使用量({round(used, 5)}) 超過限制({limit})"
    message = "\n".join(invalid_project_id_mapping.values())
    return {
        "status": message == "", 
        "message": message,
        "error_title": "Gitlab projects are exceeded its storage limit",
        # "invalid_project_id_mapping": invalid_project_id_mapping
    }


def rancher_projects_limit_num():
    command = "kubectl get apprevisions -n $(kubectl get project -n local -o jsonpath=\"{.items[?(@.spec.displayName=='Default')].metadata.name}\") | grep -v NAME | wc -l"
    output_str, _ = util.ssh_to_node_by_key(command, config.get("DEPLOYER_NODE_IP"))
    parameter = SystemParameter.query.filter_by(name="rancher_app_revision_limit").first()
    if int(output_str) >= int(parameter.value["limit_nums"]):
        return {
            "error_title": "Rancher AppRevision counts out of limit",
            "status": False,
            "message": f"Rancher AppRevision counts surpass {parameter.value['limit_nums']}."
        }
    else:
        return {
            "error_title": "Rancher AppRevision counts out of limit",
            "status": True
        }
