import os
import subprocess
from asyncio.log import logger
from datetime import datetime
from datetime import timedelta

from flask_apispec import marshal_with, doc, use_kwargs
from flask_apispec.views import MethodResource
from flask_jwt_extended import jwt_required
from flask_restful import Resource

import util
from model import Project, db, ServerDataCollection, SystemParameter
from resources import logger
from resources import role
from resources.kubernetesClient import list_namespace_pods_info
from resources.monitoring import Monitoring, row_to_dict, verify_github_info, docker_image_pull_limit_alert, \
    harbor_nfs_storage_remain_limit, server_alive, ServicesNames
from resources.rancher import rancher
from resources.rancher import remove_extra_executions
from resources.redis import get_server_alive, update_server_alive
from urls.monitoring import router_model


####################
# All
####################
@doc(tags=['Monitoring'], description="Get all services list")
@marshal_with(router_model.ServiceListSchema)
class ServicesListV2(MethodResource):
    @jwt_required()
    def get(self):
        return util.success(ServicesNames)


@doc(tags=['Monitoring'], description="Check all server is alive and update cache.")
@marshal_with(util.CommonResponse)
class ServersAliveHelper(MethodResource):
    @jwt_required()
    def post(self):
        try:
            all_alive = Monitoring().check_project_alive()["all_alive"]
            update_server_alive(str(all_alive))
        except Exception as e:
            logger.logger.exception(str(e))
            update_server_alive("False")
        return util.success()


@doc(tags=['Monitoring'], description="Get All plugin servers' status")
@use_kwargs(router_model.ServersAliveSchema, location="query")
@marshal_with(router_model.ServersAliveResponse)
class ServersAliveV2(MethodResource):
    @jwt_required()
    def get(self, **kwargs):
        all_alive = get_server_alive()
        if all_alive is None:
            all_alive = Monitoring().check_project_alive()["all_alive"]
            update_server_alive(str(all_alive))
        return util.success({"all_alive": all_alive})


class ServersAlive(Resource):
    @jwt_required()
    def get(self):
        all_alive = get_server_alive()
        if all_alive is None:
            all_alive = Monitoring().check_project_alive()["all_alive"]
            update_server_alive(str(all_alive))
        return util.success({"all_alive": all_alive})


####################
# redmine
####################
@doc(tags=['Monitoring'], description="Get Redmine server's status")
@marshal_with(router_model.ServerAliveResponse)
class RedmineAliveV2(MethodResource):
    @jwt_required()
    def get(self):
        return server_alive("Redmine")


class RedmineAlive(Resource):
    @jwt_required()
    def get(self):
        return server_alive("Redmine")


####################
# gitlab
####################
@doc(tags=['Monitoring'], description="Get Gitlab server's status")
@marshal_with(router_model.ServerAliveResponse)
class GitlabAliveV2(MethodResource):
    @jwt_required()
    def get(self):
        return server_alive("GitLab")


class GitlabAlive(Resource):
    @jwt_required()
    def get(self):
        return server_alive("GitLab")


####################
# harbor
####################
@doc(tags=['Monitoring'], description="Get Harbor server's status")
@marshal_with(router_model.ServerAliveResponse)
class HarborAliveV2(MethodResource):
    @jwt_required()
    def get(self):
        return server_alive("Harbor")


class HarborAlive(Resource):
    @jwt_required()
    def get(self):
        return server_alive("Harbor")


@doc(tags=['Monitoring'], description="Get Harbor remain time of pull image from docker hub")
@marshal_with(router_model.HarborProxyResponse)
class HarborProxyV2(MethodResource):
    @jwt_required()
    def get(self):
        return docker_image_pull_limit_alert()


class HarborProxy(Resource):
    @jwt_required()
    def get(self):
        return docker_image_pull_limit_alert()


@doc(tags=['Monitoring'], description="Get Harbor server's status")
@marshal_with(router_model.HarborStorageResponse)
class HarborStorageV2(MethodResource):
    @jwt_required()
    def get(self):
        alive = harbor_nfs_storage_remain_limit()
        update_server_alive(str(alive["status"]))
        return alive


class HarborStorage(Resource):
    @jwt_required()
    def get(self):
        alive = harbor_nfs_storage_remain_limit()
        update_server_alive(str(alive["status"]))
        return alive


####################
# sonarqube
####################
@doc(tags=['Monitoring'], description="Get SonarQube server's status")
@marshal_with(router_model.ServerAliveResponse)
class SonarQubeAliveV2(MethodResource):
    @jwt_required()
    def get(self):
        return server_alive("Sonarqube")


class SonarQubeAlive(Resource):
    @jwt_required()
    def get(self):
        return server_alive("Sonarqube")


####################
# rancher
####################
@doc(tags=['Monitoring'], description="Get Rancher server's status")
@marshal_with(router_model.ServerAliveResponse)
class RancherAliveV2(MethodResource):
    @jwt_required()
    def get(self):
        return server_alive("Rancher")


class RancherAlive(Resource):
    @jwt_required()
    def get(self):
        return server_alive("Rancher")


@doc(tags=['Monitoring'], description="Check Rancher name is changed to default or not")
@marshal_with(router_model.RancherDefaultNameResponse)
class RancherDefaultNameV2(MethodResource):
    @jwt_required()
    def get(self):
        rancher.rc_get_cluster_id()
        return {"default_cluster_name": rancher.cluster_id is not None}


class RancherDefaultName(Resource):
    @jwt_required()
    def get(self):
        rancher.rc_get_cluster_id()
        return {"default_cluster_name": rancher.cluster_id is not None}


@doc(tags=['monitoring'], description="DeleteApprevisions")
@marshal_with(util.CommonResponse)
class DeleteApprevisions(MethodResource):
    def delete(self):
        os.chmod('./apis/urls/monitoring/apprevisions.sh', 0o777)
        subprocess.run('./apis/urls/monitoring/apprevisions.sh')
        return util.success()


####################
# k8s
####################
@doc(tags=['Monitoring'], description="Get Kubernetes server's status")
@marshal_with(router_model.ServerAliveResponse)
class K8sAliveV2(MethodResource):
    @jwt_required()
    def get(self):
        return server_alive("K8s")


class K8sAlive(Resource):
    @jwt_required()
    def get(self):
        return server_alive("K8s")


class CollectPodRestartTimeV2(MethodResource):
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


@doc(tags=['Monitoring'], description="Remove extra k8s executions.")
class RemoveExtraExecutionsV2(MethodResource):
    def post(self):
        remove_extra_executions()


class RemoveExtraExecutions(Resource):
    def post(self):
        remove_extra_executions()


####################
# GitHub
####################
@doc(tags=['Monitoring'], description="Validate Github token.")
@marshal_with(router_model.GithubTokenVerifyResponse)
class GithubTokenVerifyV2(MethodResource):
    @jwt_required()
    def post(self):
        role.require_admin()
        value = row_to_dict(SystemParameter.query.filter_by(name="github_verify_info").one())["value"]
        return util.success(verify_github_info(value))


class GithubTokenVerify(Resource):
    @jwt_required()
    def post(self):
        role.require_admin()
        value = row_to_dict(SystemParameter.query.filter_by(name="github_verify_info").one())["value"]
        return util.success(verify_github_info(value))


####################
# excalidraw
####################
@doc(tags=['Monitoring'], description="Get Excalidraw server's status")
@marshal_with(router_model.ServerAliveResponse)
class ExcalidrawAliveV2(MethodResource):
    @jwt_required()
    def get(self):
        return server_alive("Excalidraw")
