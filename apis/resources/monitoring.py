from flask_restful import Resource, reqparse
from nexus import nx_get_project_plugin_relation
import util
from model import Project, db, ServerDataCollection

from plugins.sonarqube import sq_get_current_measures, sq_list_project
from resources.harbor import hb_get_project_summary, hb_get_registries
from resources.redmine import redmine
from resources.gitlab import gitlab
from resources.rancher import rancher
from resources import logger
from resources.kubernetesClient import ApiK8sClient as k8s_client
from resources.kubernetesClient import list_namespace_services, list_namespace_pods_info
from datetime import datetime, timedelta


class Monitoring:
    def __init__(self, project_id=None):
        self.pj_id = project_id
        self.all_alive = True
        self.__init_ids()

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
            gitlab.gl_get_project, gitlab.gl_get_all_project, self.gl_pj_id)

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

# --------------------- Resources ---------------------
class ServersAlive(Resource):
    def get(self):
        parser = reqparse.RequestParser()
        parser.add_argument('project_id', type=int)
        args = parser.parse_args()
        pj_id = args.get("project_id")

        monitoring = Monitoring(pj_id) if pj_id is not None else Monitoring()
        return util.success(monitoring.check_project_alive())


class RancherDefaultName(Resource):
    def get(self):
        rancher.rc_get_cluster_id()
        return {"default_cluster_name": rancher.cluster_id is not None}


class CollectPodRestartTime(Resource):
    def get(self):
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
                        create_at=datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
                    )
                    db.session.add(row)
                    db.session.commit()

    def delete(self):
        expired_date = datetime.utcnow() - timedelta(days=30)
        ServerDataCollection.query.filter_by(type_id=1).filter(ServerDataCollection.create_at <= expired_date).delete()
        db.session.commit()
