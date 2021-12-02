import base64
import json
import numbers
import os
import time
from datetime import datetime, timezone

import yaml
from flask_socketio import Namespace, emit
from kubernetes import client as k8s_client
from kubernetes import config as k8s_config
from kubernetes import utils as k8s_utils
from kubernetes.client import ApiException
from kubernetes.stream import stream as k8s_stream
from util import read_json_file

import config
import resources.apiError as apiError
from resources.logger import logger

# kubernetes 抓取 III 定義 annotations 標籤
iii_template = {
    'project_name': 'iiidevops.org/project_name',
    'branch': 'iiidevops.org/branch',
    'commit_id': 'iiidevops.org/commit_id',
    'type': 'iiidevops.org/type'
}

system_parameter = read_json_file("apis/resources/maintenance/system_parameter.json")
iii_env_default = system_parameter["secret"] + system_parameter["registry"]

env_normal_type = ['Opaque']

DEFAULT_NAMESPACE = 'default'
SYSTEM_SECRET_NAMESPACE = 'iiidevops-env-secret'


class ApiK8sClient:
    def __init__(self, configuration=None, configuration_file=None):
        if configuration_file is not None:
            configuration = k8s_config.load_kube_config(
                config_file=configuration_file)
        elif configuration is None:
            configuration = k8s_config.load_kube_config()

        self.configuration = configuration
        self.api_k8s_client = k8s_client.ApiClient(configuration=configuration)
        self.core_v1 = k8s_client.CoreV1Api(self.api_k8s_client)
        self.rbac_auth_v1 = k8s_client.RbacAuthorizationV1Api(
            self.api_k8s_client)
        self.app_v1 = k8s_client.AppsV1Api(self.api_k8s_client)
        self.extensions_v1beta1 = k8s_client.ExtensionsV1beta1Api(
            self.api_k8s_client)
        self.batch_v1beta1 = k8s_client.BatchV1beta1Api(self.api_k8s_client)
        self.batch_v1 = k8s_client.BatchV1Api(self.api_k8s_client)
        self.network_v1beta1 = k8s_client.NetworkingV1beta1Api(
            self.api_k8s_client)

    # api  version
    def get_api_resources(self):
        try:
            return self.core_v1.get_api_resources()
        except apiError.DevOpsError as e:
            if e.status_code != 404:
                raise e

    # Ingress
    def list_ingress_for_all_namespaces(self):
        try:
            return self.network_v1beta1.list_ingress_for_all_namespaces()
        except apiError.DevOpsError as e:
            if e.status_code != 404:
                raise e

    def read_namespaced_ingress(self, name, namespace):
        try:
            return self.network_v1beta1.read_namespaced_ingress(
                name, namespace)
        except apiError.DevOpsError as e:
            if e.status_code != 404:
                raise e

    def create_namespaced_ingress(self, namespace, body):
        try:
            return self.network_v1beta1.create_namespaced_ingress(
                namespace, body)
        except apiError.DevOpsError as e:
            if e.status_code != 404:
                raise e

    def patch_namespaced_ingress(self, name, namespace, body):
        try:
            return self.network_v1beta1.patch_namespaced_ingress(
                name, namespace, body)
        except apiError.DevOpsError as e:
            if e.status_code != 404:
                raise e

    def delete_namespaced_ingress(self, name, namespace):
        try:
            return self.network_v1beta1.delete_namespaced_ingress(
                name, namespace)
        except apiError.DevOpsError as e:
            if e.status_code != 404:
                raise e

    def list_namespaced_ingress(self, namespace):
        try:
            return self.extensions_v1beta1.list_namespaced_ingress(namespace)
        except apiError.DevOpsError as e:
            if e.status_code != 404:
                raise e

    #  ConfigMap

    def list_namespaced_config_map(self, namespace):
        try:
            return self.core_v1.list_namespaced_config_map(namespace)
        except apiError.DevOpsError as e:
            if e.status_code != 404:
                raise e

    def create_namespaced_config_map(self, namespace, body):
        try:
            return self.core_v1.create_namespaced_config_map(namespace, body)
        except apiError.DevOpsError as e:
            if e.status_code != 404:
                raise e

    def read_namespaced_config_map(self, name, namespace):
        try:
            return self.core_v1.read_namespaced_config_map(name, namespace)
        except apiError.DevOpsError as e:
            if e.status_code != 404:
                raise e

    def patch_namespaced_config_map(self, name, namespace, body):
        try:
            return self.core_v1.patch_namespaced_config_map(
                name, namespace, body)
        except apiError.DevOpsError as e:
            if e.status_code != 404:
                raise e

    def delete_namespaced_configmap(self, name, namespace):
        try:
            return self.core_v1.delete_namespaced_config_map(name, namespace)
        except apiError.DevOpsError as e:
            if e.status_code != 404:
                raise e

    #  Secret
    def list_namespaced_secret(self, namespace):
        try:
            return self.core_v1.list_namespaced_secret(namespace)
        except apiError.DevOpsError as e:
            if e.status_code != 404:
                raise e

    def create_namespaced_secret(self, namespace, body):
        try:
            return self.core_v1.create_namespaced_secret(namespace, body)
        except apiError.DevOpsError as e:
            if e.status_code != 404:
                raise e

    def read_namespaced_secret(self, secret_name, namespace):
        try:
            return self.core_v1.read_namespaced_secret(secret_name, namespace)
        except apiError.DevOpsError as e:
            if e.status_code != 404:
                raise e

    def patch_namespaced_secret(self, secret_name, namespace, body):
        try:
            return self.core_v1.patch_namespaced_secret(
                secret_name, namespace, body)
        except apiError.DevOpsError as e:
            if e.status_code != 404:
                raise e

    def delete_namespaced_secret(self, name, namespace):
        try:
            return self.core_v1.delete_namespaced_secret(name, namespace)
        except apiError.DevOpsError as e:
            if e.status_code != 404:
                raise e

    #  Service
    def list_service_for_all_namespaces(self):
        try:
            return self.core_v1.list_service_for_all_namespaces()
        except apiError.DevOpsError as e:
            if e.status_code != 404:
                raise e

    def delete_namespaced_service(self, name, namespace):
        try:
            return self.core_v1.delete_namespaced_service(name, namespace)
        except apiError.DevOpsError as e:
            if e.status_code != 404:
                raise e

    def read_namespaced_service(self, name, namespace):
        try:
            return self.core_v1.read_namespaced_service(name, namespace)
        except apiError.DevOpsError as e:
            if e.status_code != 404:
                raise e

    def list_namespaced_service(self, namespace):
        try:
            return self.core_v1.list_namespaced_service(namespace)
        except apiError.DevOpsError as e:
            if e.status_code != 404:
                raise e

    def create_namespaced_service(self, namespace, body):
        try:
            return self.core_v1.create_namespaced_service(namespace, body)
        except apiError.DevOpsError as e:
            if e.status_code != 404:
                raise e

    def patch_namespaced_service(self, name, namespace, body):
        try:
            return self.core_v1.patch_namespaced_service(name, namespace, body)
        except apiError.DevOpsError as e:
            if e.status_code != 404:
                raise e

    #  Deployment

    def list_namespaced_deployment(self, namespace):
        try:
            return self.app_v1.list_namespaced_deployment(namespace)
        except apiError.DevOpsError as e:
            if e.status_code != 404:
                raise e

    def create_namespaced_deployment(self, namespace, body):
        try:
            return self.app_v1.create_namespaced_deployment(namespace, body)
        except apiError.DevOpsError as e:
            if e.status_code != 404:
                raise e

    def read_namespaced_deployment(self, name, namespace):
        try:
            return self.app_v1.read_namespaced_deployment(name, namespace)
        except apiError.DevOpsError as e:
            if e.status_code != 404:
                raise e

    def patch_namespaced_deployment(self, name, namespace, body):
        try:
            return self.app_v1.patch_namespaced_deployment(
                name, namespace, body)
        except apiError.DevOpsError as e:
            if e.status_code != 404:
                raise e

    def delete_namespaced_deployment(self, name, namespace):
        try:
            return self.app_v1.delete_namespaced_deployment(name, namespace)
        except apiError.DevOpsError as e:
            if e.status_code != 404:
                raise e

    # Pod
    def list_pod_for_all_namespaces(self):
        try:
            return self.core_v1.list_pod_for_all_namespaces(watch=False)
        except apiError.DevOpsError as e:
            if e.status_code != 404:
                raise e

    def list_namespaced_pod(self, namespace):
        try:
            return self.core_v1.list_namespaced_pod(namespace)
        except apiError.DevOpsError as e:
            if e.status_code != 404:
                raise e

    def delete_namespaced_pod(self, name, namespace):
        try:
            return self.core_v1.delete_namespaced_pod(name, namespace)
        except apiError.DevOpsError as e:
            if e.status_code != 404:
                raise e

    def read_namespaced_pod_log(self, name, namespace, container=None):
        try:
            return self.core_v1.read_namespaced_pod_log(name,
                                                        namespace,
                                                        container=container)
        except apiError.DevOpsError as e:
            if e.status_code != 404:
                raise apiError.error_3rd_party_api('kubernetes', e)

    def read_namespaced_pod_status(self, name, namespace):
        try:
            return self.core_v1.read_namespaced_pod_status(name, namespace)
        except apiError.DevOpsError as e:
            if e.status_code != 404:
                raise e

    #  RBAC

    def create_namespaced_role(self, namespace, role):
        try:
            return self.rbac_auth_v1.create_namespaced_role(namespace, role)
        except apiError.DevOpsError as e:
            if e.status_code != 404:
                raise e

    def list_namespaced_role(self, namespace):
        try:
            return self.rbac_auth_v1.list_namespaced_role(namespace)
        except apiError.DevOpsError as e:
            if e.status_code != 404:
                raise e

    def delete_namespaced_role(self, name, namespace):
        try:
            return self.rbac_auth_v1.delete_namespaced_role(name, namespace)
        except apiError.DevOpsError as e:
            if e.status_code != 404:
                raise e

    def list_namespaced_role_binding(self, namespace):
        try:
            return self.rbac_auth_v1.list_namespaced_role_binding(namespace)
        except apiError.DevOpsError as e:
            if e.status_code != 404:
                raise e

    def create_namespaced_role_binding(self, namespace=None, body=None):
        try:
            return self.rbac_auth_v1.create_namespaced_role_binding(
                namespace=namespace, body=body)
        except apiError.DevOpsError as e:
            if e.status_code != 404:
                raise e

    def delete_namespaced_role_binding(self, role_binding_name, namespace):
        try:
            return self.rbac_auth_v1.delete_namespaced_role_binding(
                role_binding_name, namespace)
        except apiError.DevOpsError as e:
            if e.status_code != 404:
                raise e

    # namespace Quota

    def read_namespaced_resource_quota(self, name, namespace):
        try:
            return self.core_v1.read_namespaced_resource_quota(name, namespace)
        except apiError.DevOpsError as e:
            if e.status_code != 404:
                raise e

    def create_namespaced_resource_quota(self, namespace, resource_quota):
        try:
            return self.core_v1.create_namespaced_resource_quota(
                namespace, resource_quota)
        except apiError.DevOpsError as e:
            if e.status_code != 404:
                raise e

    def replace_namespaced_resource_quota(self, name, namespace,
                                          namespace_quota):
        try:
            return self.core_v1.replace_namespaced_resource_quota(
                name, namespace, namespace_quota)
        except apiError.DevOpsError as e:
            if e.status_code != 404:
                raise e

    # namespace limit Range
    def create_namespaced_limit_range(self, namespace, resource_quota):
        try:
            return self.core_v1.create_namespaced_limit_range(
                namespace, resource_quota)
        except apiError.DevOpsError as e:
            if e.status_code != 404:
                raise e

    def list_namespaced_limit_range(self, namespace):
        try:
            return self.core_v1.list_namespaced_limit_range(namespace)
        except apiError.DevOpsError as e:
            if e.status_code != 404:
                raise e

    # namespace service account

    def list_namespaced_service_account(self, namespace):
        try:
            return self.core_v1.list_namespaced_service_account(namespace)
        except apiError.DevOpsError as e:
            if e.status_code != 404:
                raise e

    def create_namespaced_service_account(self, namespace, body):
        try:
            return self.core_v1.create_namespaced_service_account(
                namespace, body)
        except apiError.DevOpsError as e:
            if e.status_code != 404:
                raise e

    def read_namespaced_service_account(self, name, namespace):
        try:
            return self.core_v1.read_namespaced_service_account(
                name, namespace)
        except apiError.DevOpsError as e:
            if e.status_code != 404:
                raise e

    def delete_namespaced_service_account(self, name, namespace):
        try:
            return self.core_v1.delete_namespaced_service_account(
                name, namespace)
        except apiError.DevOpsError as e:
            if e.status_code != 404:
                raise e

    # namespace
    def list_namespace(self):
        try:
            return self.core_v1.list_namespace()
        except apiError.DevOpsError as e:
            if e.status_code != 404:
                raise e

    def create_namespace(self, body):
        try:
            return self.core_v1.create_namespace(body)
        except apiError.DevOpsError as e:
            if e.status_code != 404:
                raise e

    def read_namespace(self, name):
        try:
            return self.core_v1.read_namespace(name)
        except apiError.DevOpsError as e:
            if e.status_code != 404:
                raise e

    def delete_namespace(self, name):
        try:
            return self.core_v1.delete_namespace(name)
        except apiError.DevOpsError as e:
            if e.status_code != 404:
                raise e

    # node

    def list_node(self):
        try:
            return self.core_v1.list_node()
        except apiError.DevOpsError as e:
            if e.status_code != 404:
                raise e

    # Job
    def list_namespaced_job(self, namespace):
        try:
            return self.batch_v1.list_namespaced_job(namespace)
        except apiError.DevOpsError as e:
            if e.status_code != 404:
                raise e

    def delete_namespaced_job(self, name, namespace):
        try:
            return self.batch_v1.delete_namespaced_job(name, namespace)
        except apiError.DevOpsError as e:
            if e.status_code != 404:
                raise e

    # Cron Job
    def list_namespaced_cron_job(self, namespace):
        return self.batch_v1beta1.list_namespaced_cron_job(namespace)

    def delete_namespaced_cron_job(self, name, namespace):
        return self.batch_v1beta1.delete_namespaced_cron_job(name, namespace)

    def get_api_client(self):
        return self.api_k8s_client


MAX_RETRY_APPLY_CRONJOB = 30


def apply_cronjob_yamls():
    api_k8s_client = ApiK8sClient()
    for root, dirs, files in os.walk("k8s-yaml/api-init/cronjob"):
        for file in files:
            if file.endswith(".yaml") or file.endswith(".yml"):
                with open(os.path.join(root, file)) as f:
                    json_file = yaml.safe_load(f)
                    for cronjob_json in api_k8s_client.list_namespaced_cron_job(
                            "default").items:
                        if cronjob_json.metadata.name == json_file["metadata"][
                                "name"]:
                            api_k8s_client.delete_namespaced_cron_job(
                                cronjob_json.metadata.name, "default")
                            retry = 0
                            while retry < MAX_RETRY_APPLY_CRONJOB:
                                time.sleep(1)
                                still_has_cj = False
                                for cj in api_k8s_client.list_namespaced_cron_job(
                                        "default").items:
                                    if cronjob_json.metadata.name in cj.metadata.name:
                                        still_has_cj = True
                                if still_has_cj is False:
                                    break
                                retry += 1
                            if retry >= MAX_RETRY_APPLY_CRONJOB:
                                logger.critical(
                                    f'Cannot delete existing cronjob {cronjob_json.metadata.name}!'
                                    f' Cronjob is not applied.')
                                return
                            for j in api_k8s_client.list_namespaced_job(
                                    "default").items:
                                if f"{cronjob_json.metadata.name}-" in j.metadata.name:
                                    api_k8s_client.delete_namespaced_job(
                                        j.metadata.name, "default")
                            for pod in api_k8s_client.list_namespaced_pod(
                                    "default").items:
                                if f"{cronjob_json.metadata.name}-" in pod.metadata.name:
                                    pod = api_k8s_client.delete_namespaced_pod(
                                        pod.metadata.name, "default")
                try:
                    k8s_utils.create_from_yaml(api_k8s_client.get_api_client(),
                                               os.path.join(root, file))
                except k8s_utils.FailToCreateError as e:
                    print('e1')
                    info = json.loads(e.api_exceptions[0].body)
                    print(f'e2 {info}')
                    if info.get('reason').lower() == 'alreadyexists':
                        pass
                    else:
                        raise e


def list_service_all_namespaces():
    list_services = []
    for service in ApiK8sClient().list_service_for_all_namespaces().items:
        logger.info("{0}, {1}, {2}, {3}".format(
            service.metadata.name, service.metadata.namespace,
            service.spec.type, service.spec.ports[0].node_port))
        list_ports = []
        for port in service.spec.ports:
            list_ports.append({
                "nodePort": port.node_port,
                "protocol": port.protocol,
                "target_port": port.target_port,
                "name": port.name,
                "port": port.port
            })
        list_services.append({
            "name": service.metadata.name,
            "namespace": service.metadata.namespace,
            "type": service.spec.type,
            "ports": list_ports
        })
    return list_services


def get_the_oldest_node():
    the_oldest_node = ['', datetime.now(timezone.utc)]
    for node in ApiK8sClient().list_node().items:
        if node.metadata.creation_timestamp < the_oldest_node[1]:
            for address in node.status.addresses:
                if address.type == "InternalIP":
                    the_oldest_node[0] = address.address
                    the_oldest_node[1] = node.metadata.creation_timestamp
                    break
    return the_oldest_node


def list_work_node():
    list_nodes = []
    for node in ApiK8sClient().list_node().items:
        ip = None
        hostname = None
        if 'node-role.kubernetes.io/worker' in node.metadata.labels:
            ip = node.metadata.annotations[
                'projectcalico.org/IPv4Address'].split('/')[0]
            for address in node.status.addresses:
                if address.type == 'Hostname':
                    hostname = address.address
            list_nodes.append({
                "worker":
                node.metadata.labels['node-role.kubernetes.io/worker'],
                "ip":
                ip,
                "hostname":
                hostname
            })
    logger.info("list_worknode node_list: {0}".format(list_nodes))
    return list_nodes


def create_iiidevops_env_secret_namespace():
    if "iiidevops-env-secret" not in list_namespace():
        create_namespace("iiidevops-env-secret")


def create_namespace(project_name):
    try:
        ApiK8sClient().create_namespace(
            k8s_client.V1Namespace(metadata=k8s_client.V1ObjectMeta(
                name=project_name)))
    except apiError.DevOpsError as e:
        if e.status_code != 404:
            raise e


def get_namespace(project_name):
    return ApiK8sClient().read_namespace(project_name)


def list_namespace():
    try:
        list_namespaces = []
        for namespace in ApiK8sClient().list_namespace().items:
            list_namespaces.append(namespace.metadata.name)
        return list_namespaces
    except apiError.DevOpsError as e:
        if e.status_code != 404:
            raise e


def delete_namespace(project_name):
    try:
        ApiK8sClient().delete_namespace(project_name)
    except ApiException as e:
        if e.status != 404:
            raise e


def create_service_account(login_sa_name):
    sa = ApiK8sClient().create_namespaced_service_account(
        "account",
        k8s_client.V1ServiceAccount(metadata=k8s_client.V1ObjectMeta(
            name=login_sa_name)))
    return sa


def delete_service_account(login_sa_name):
    sa = ApiK8sClient().delete_namespaced_service_account(
        login_sa_name, "account")
    return sa


def list_service_account():
    list_service_accouts = []
    for sa in ApiK8sClient().list_namespaced_service_account("account").items:
        list_service_accouts.append(sa.metadata.name)
    return list_service_accouts


def get_service_account_config(sa_name):
    list_nodes = []
    api_k8s_client = ApiK8sClient()
    for node in api_k8s_client.list_node().items:
        ip = None
        hostname = None
        if "node-role.kubernetes.io/controlplane" in node.metadata.labels:
            for address in node.status.addresses:
                if address.type == 'InternalIP':
                    ip = address.address
                elif address.type == 'Hostname':
                    hostname = address.address
            list_nodes.append({
                "controlplane":
                node.metadata.labels['node-role.kubernetes.io/controlplane'],
                "ip":
                ip,
                "hostname":
                hostname
            })
    sa_secrets_name = api_k8s_client.read_namespaced_service_account(
        sa_name, "account").secrets[0].name
    if config.get("KUBERNETES_MASTER_DOMAIN") is not None:
        server_ip = str(config.get("KUBERNETES_MASTER_DOMAIN"))
    else:
        server_ip = str(list_nodes[0]['ip'])
    sa_secret = api_k8s_client.read_namespaced_secret(sa_secrets_name,
                                                      "account")
    sa_ca = sa_secret.data['ca.crt']
    sa_token = str(
        base64.b64decode(str(sa_secret.data['token'])).decode('utf-8'))
    sa_config = "apiVersion: v1\nclusters:\n- cluster:\n    certificate-authority-data: " + sa_ca + "\n    server: https://" + server_ip + ":6443" + \
                "\n  name: cluster\ncontexts:\n- context:\n    cluster: cluster\n    user: " + sa_name + "\n  name: default\ncurrent-context: default\nkind: Config\npreferences: {}\nusers:\n- name: " + sa_name + \
                "\n  user:\n    token: " + sa_token
    k8s_sa_config = {'name': sa_name, 'config': sa_config}
    return k8s_sa_config


def get_namespace_quota(namespace):
    namespace_quota = ApiK8sClient().read_namespaced_resource_quota(
        "project-quota", namespace)
    resource = {
        'quota': namespace_quota.status.hard,
        'used': namespace_quota.status.used
    }
    return resource


def create_namespace_quota(namespace):
    try:
        resource_quota = k8s_client.V1ResourceQuota(
            spec=k8s_client.V1ResourceQuotaSpec(
                hard={
                    "cpu": "10",
                    "memory": "10G",
                    "pods": "20",
                    "persistentvolumeclaims": "0",
                    "configmaps": "60",
                    "services.nodeports": "10"
                }))
        resource_quota.metadata = k8s_client.V1ObjectMeta(namespace=namespace,
                                                          name="project-quota")
        ApiK8sClient().create_namespaced_resource_quota(
            namespace, resource_quota)
    except apiError.DevOpsError as e:
        if e.status_code != 404:
            raise e


def update_namespace_quota(namespace, resource):
    try:
        api_k8s_client = ApiK8sClient()
        namespace_quota = api_k8s_client.read_namespaced_resource_quota(
            "project-quota", namespace)
        namespace_quota.spec.hard = resource
        api_k8s_client.replace_namespaced_resource_quota(
            "project-quota", namespace, namespace_quota)
    except apiError.DevOpsError as e:
        if e.status_code != 404:
            raise e


def create_namespace_limitrange(namespace):
    try:
        resource_quota = k8s_client.V1LimitRange(
            spec=k8s_client.V1LimitRangeSpec(limits=[{
                "default": {
                    "memory": "10Gi",
                    "cpu": 10
                },
                "defaultRequest": {
                    "memory": "64Mi",
                    "cpu": 0.1
                },
                "type": "Container"
            }]),
            metadata=k8s_client.V1ObjectMeta(namespace=namespace,
                                             name="project-limitrange"))
        ApiK8sClient().create_namespaced_limit_range(namespace, resource_quota)
    except apiError.DevOpsError as e:
        if e.status_code != 404:
            raise e


def list_limitrange_in_namespace(namespace):
    try:
        list_limitranges = []
        for limitrange in ApiK8sClient().list_namespaced_limit_range(
                namespace).items:
            list_limitranges.append(limitrange.metadata.name)
        return list_limitranges
    except apiError.DevOpsError as e:
        if e.status_code != 404:
            raise e


def create_role_in_namespace(namespace):
    rules = [k8s_client.V1PolicyRule(
        ["*"],
        resources=["*"],
        verbs=["*"],
    )]
    role = k8s_client.V1Role(rules=rules)
    role.metadata = k8s_client.V1ObjectMeta(namespace=namespace,
                                            name="user-role")
    try:
        ApiK8sClient().create_namespaced_role(namespace, role)
    except apiError.DevOpsError as e:
        if e.status_code != 404:
            raise e


def list_role_in_namespace(namespace):
    try:
        list_roles = []
        for role in ApiK8sClient().list_namespaced_role(namespace).items:
            list_roles.append(role.metadata.name)
        return list_roles
    except apiError.DevOpsError as e:
        if e.status_code != 404:
            raise e


def delete_role_in_namespace(namespace, name):
    try:
        ApiK8sClient().delete_namespaced_role(name, namespace)
    except apiError.DevOpsError as e:
        if e.status_code != 404:
            raise e


def list_role_binding_in_namespace(namespace):
    return ApiK8sClient().list_namespaced_role_binding(namespace)


def create_role_binding(namespace, sa_name):
    # create ns RoleBinding
    role_binding = k8s_client.V1RoleBinding(
        metadata=k8s_client.V1ObjectMeta(namespace=namespace,
                                         name="{0}-rb".format(sa_name)),
        subjects=[
            k8s_client.V1Subject(namespace="account",
                                 name=sa_name,
                                 kind="ServiceAccount")
        ],
        role_ref=k8s_client.V1RoleRef(
            kind="Role",
            api_group="rbac.authorization.k8s.io",
            name="user-role",
        ))
    try:
        ApiK8sClient().create_namespaced_role_binding(namespace=namespace,
                                                      body=role_binding)
    except apiError.DevOpsError as e:
        if e.status_code != 404:
            raise e


def delete_role_binding(namespace, role_binding_name):
    try:
        ApiK8sClient().delete_namespaced_role_binding(role_binding_name,
                                                      namespace)
    except apiError.DevOpsError as e:
        if e.status_code != 404:
            raise e


def list_namespace_pods_info(namespace):
    try:
        list_pods = []
        for pod in ApiK8sClient().list_namespaced_pod(namespace).items:
            containers = []
            if pod.status.container_statuses is not None:
                for container_status in pod.status.container_statuses:
                    container_status_time = analysis_container_status_time(
                        container_status)
                    containers.append({
                        "name":
                        container_status.name,
                        "image":
                        container_status.image,
                        "restart":
                        container_status.restart_count,
                        "state":
                        container_status_time['state'],
                        "time":
                        container_status_time['status_time']
                    })
            list_pods.append({
                'name':
                pod.metadata.name,
                "created_time":
                str(pod.metadata.creation_timestamp),
                'containers':
                containers
            })
        return list_pods
    except apiError.DevOpsError as e:
        if e.status_code != 404:
            raise e


def delete_namespace_pod(namespace, name):
    try:
        pod = ApiK8sClient().delete_namespaced_pod(name, namespace)
        link_path = pod.metadata.self_link
        paths = link_path.split('/')
        return paths[len(paths) - 1]
    except apiError.DevOpsError as e:
        if e.status_code != 404:
            raise e


def read_namespace_pod_log(namespace, name, container=None):
    try:
        pod_log = ApiK8sClient().read_namespaced_pod_log(
            name, namespace, container)
        return pod_log
    except apiError.DevOpsError as e:
        if e.status_code != 404:
            raise e


def read_namespaced_pod_status(name, namespace):
    try:
        pod_status = ApiK8sClient().read_namespaced_pod_status(name, namespace)
        return pod_status
    except apiError.DevOpsError as e:
        if e.status_code != 404:
            raise e


def get_deployments_info(deployment):
    output = {
        "name": None,
        "available_pod_number": None,
        "total_pod_number": None,
        "created_time": None,
        "containers": None
    }
    if deployment is None:
        return output
    return {
        "name":
        deployment.metadata.name,
        "available_pod_number":
        deployment.status.available_replicas,
        "total_pod_number":
        deployment.status.replicas,
        "created_time":
        str(deployment.metadata.creation_timestamp),
        "containers":
        get_spec_containers_image_and_name(
            deployment.spec.template.spec.containers)
    }


def list_namespace_deployments(namespace):
    try:
        list_deployments = []
        for deployment in ApiK8sClient().list_namespaced_deployment(
                namespace).items:
            list_deployments.append({
                "name":
                deployment.metadata.name,
                "available_pod_number":
                deployment.status.available_replicas,
                "total_pod_number":
                deployment.status.replicas,
                "created_time":
                str(deployment.metadata.creation_timestamp),
                "containers":
                get_spec_containers_image_and_name(
                    deployment.spec.template.spec.containers)
            })
        return list_deployments
    except apiError.DevOpsError as e:
        if e.status_code != 404:
            raise e


def read_namespace_deployment(namespace, name):
    try:
        return ApiK8sClient().read_namespaced_deployment(name, namespace)
    except apiError.DevOpsError as e:
        if e.status_code != 404:
            raise e


def update_namespace_deployment(namespace, name, body):
    try:
        return ApiK8sClient().patch_namespaced_deployment(
            name, namespace, body)
    except apiError.DevOpsError as e:
        if e.status_code != 404:
            raise e


def delete_namespace_deployment(namespace, name):
    try:
        deployment = ApiK8sClient().delete_namespaced_deployment(
            name, namespace)
        return deployment.details.name
    except apiError.DevOpsError as e:
        if e.status_code != 404:
            raise e


def update_deployment_image_tag(namespace, deployment_name, new_image_tag):
    deployment = read_namespace_deployment(namespace, deployment_name)
    image_api = deployment.spec.template.spec.containers[0].image
    parts = image_api.split(':')
    parts[-1] = new_image_tag
    if deployment.spec.template.metadata.annotations is None:
        deployment.spec.template.metadata.annotations = {
            'iiidevops_redeploy_at': str(datetime.utcnow())
        }
    else:
        deployment.spec.template.metadata.annotations[
            "iiidevops_redeploy_at"] = str(datetime.utcnow())
    deployment.spec.template.spec.containers[0].image = ':'.join(parts)
    update_namespace_deployment(namespace, deployment_name, deployment)


def list_namespace_services(namespace):
    try:
        list_services = []
        for service in ApiK8sClient().list_namespaced_service(namespace).items:
            list_services.append({
                'name':
                service.metadata.name,
                'is_iii':
                check_if_iii_template(service.metadata)
            })
        return list_services
    except apiError.DevOpsError as e:
        if e.status_code != 404:
            raise e


def delete_namespace_service(namespace, name):
    try:
        service = ApiK8sClient().delete_namespaced_service(name, namespace)
        return service.details.name
    except apiError.DevOpsError as e:
        if e.status_code != 404:
            raise e


# K8s Secret Usage
def list_namespace_secrets(namespace):
    try:
        list_secrets = []
        for secret in ApiK8sClient().list_namespaced_secret(namespace).items:
            list_secrets.append(secret_info_by_iii(secret))
        return list_secrets
    except apiError.DevOpsError as e:
        if e.status_code != 404:
            raise e


def read_namespace_secret(namespace, secret_name):
    try:
        secret_data = {}
        secret = ApiK8sClient().read_namespaced_secret(secret_name, namespace)
        if secret.data is None:
            return {}
        for key, value in secret.data.items():
            secret_data[key] = str(
                base64.b64decode(str(value)).decode('utf-8'))
        return secret_data
    except ApiException as e:
        if e.status != 404:
            raise e
        return None


def create_namespace_secret(namespace, secret_name, secrets):
    for key, value in secrets.items():
        secrets[key] = base64.b64encode(bytes(
            value, encoding='utf-8')).decode('utf-8')
    try:
        body = k8s_client.V1Secret(metadata=k8s_client.V1ObjectMeta(
            namespace=namespace, name=secret_name),
            data=secrets)
        ApiK8sClient().create_namespaced_secret(namespace, body)
        return {}
    except apiError.DevOpsError as e:
        if e.status_code != 404:
            raise e


def patch_namespace_secret(namespace, secret_name, secrets):
    for key, value in secrets.items():
        secrets[key] = base64.b64encode(bytes(
            value, encoding='utf-8')).decode('utf-8')
    try:
        body = k8s_client.V1Secret(metadata=k8s_client.V1ObjectMeta(
            namespace=namespace, name=secret_name),
            data=secrets)
        ApiK8sClient().patch_namespaced_secret(secret_name, namespace, body)
        return {}
    except apiError.DevOpsError as e:
        if e.status_code != 404:
            raise e


def delete_namespace_secret(namespace, name):
    try:
        secret = ApiK8sClient().delete_namespaced_secret(name, namespace)
        return secret.details.name
    except apiError.DevOpsError as e:
        if e.status_code != 404:
            raise e


# K8s ConfigMaps Usage


def list_namespace_configmap(namespace):
    try:
        list_configmaps = []
        for configmap in ApiK8sClient().list_namespaced_config_map(
                namespace).items:
            list_configmaps.append(configmap_info_by_iii(configmap))
        return list_configmaps
    except apiError.DevOpsError as e:
        if e.status_code != 404:
            raise e


def read_namespace_configmap(namespace, name):
    try:
        configmap_data = {}
        configmaps = ApiK8sClient().read_namespaced_config_map(name, namespace)
        for key, value in configmaps.data.items():
            configmap_data[key] = str(value)
        return configmap_data
    except apiError.DevOpsError as e:
        if e.status_code != 404:
            raise e


def create_namespace_configmap(namespace, name, configmaps):
    try:
        body = k8s_client.V1ConfigMap(
            metadata=k8s_client.V1ObjectMeta(name=name), data=configmaps)
        ApiK8sClient().create_namespaced_config_map(namespace, body)
        return {}
    except apiError.DevOpsError as e:
        if e.status_code != 404:
            raise e


def put_namespace_configmap(namespace, name, configmaps):
    try:
        body = k8s_client.V1ConfigMap(metadata=k8s_client.V1ObjectMeta(
            namespace=namespace, name=name),
            data=configmaps)
        ApiK8sClient().patch_namespaced_config_map(name, namespace, body)
        return {}
    except apiError.DevOpsError as e:
        if e.status_code != 404:
            raise e


def delete_namespace_configmap(namespace, name):
    try:

        configmap = ApiK8sClient().delete_namespaced_configmap(name, namespace)
        return configmap.details.name
    except apiError.DevOpsError as e:
        if e.status_code != 404:
            raise e


def list_namespace_ingresses(namespace):
    try:
        list_ingresses = []
        for ingress in ApiK8sClient().list_namespaced_ingress(namespace).items:
            ingress_info = {
                "name": ingress.metadata.name,
                "created_time": str(ingress.metadata.creation_timestamp)
            }
            ip = None
            if ingress.status.load_balancer.ingress is not None:
                ip = ingress.status.load_balancer.ingress[0].ip
            ingress_info["ingress_list"] = map_ingress_with_host(
                ingress.spec.rules)
            ingress_info["tls"] = ingress.spec.tls
            list_ingresses.append(ingress_info)
        return list_ingresses
    except apiError.DevOpsError as e:
        if e.status_code != 404:
            raise e


def check_ingress_exist(namespace, branch):
    ingress_list = list_namespace_ingresses(namespace)
    for ingress in ingress_list:
        if f"{namespace}-{branch}-serv-ing" == ingress['name']:
            return True
    return False


def map_ingress_with_host(rules):
    try:
        info = []
        for rule in rules:
            if rule.host is not None:
                hostname = rule.host
                for path in rule.http.paths:
                    if hostname is not None:
                        info.append({
                            "hostname_path":
                            hostname + path.path,
                            "service":
                            f"{path.backend.service_name}:{path.backend.service_port}"
                        })
                    else:
                        info.append({
                            "hostname_path":
                            path.path,
                            "service":
                            f"{path.backend.service_name}:{path.backend.service_port}"
                        })
        return info
    except apiError.DevOpsError as e:
        if e.status_code != 404:
            raise e


def list_dev_environment_by_branch(namespace, git_url):
    try:
        list_services = list_namespace_services_by_iii(namespace)
        pods_info = {}

        for pod in ApiK8sClient().list_namespaced_pod(namespace).items:
            annotations = pod.metadata.annotations
            labels = pod.metadata.labels
            is_iii = check_if_iii_template(pod.metadata)
            if is_iii is True and pod.status.container_statuses is not None:
                pods_info, environment = check_iii_project_branch_key_exist(
                    pod.metadata, pods_info, git_url, 'pods')
                pod_info = {
                    'app_name': labels['app'],
                    'pod_name': pod.metadata.name,
                    'type': annotations[iii_template['type']],
                    'containers': []
                }
                namespace_services_info = get_list_service_match_pods_labels(
                    list_services, labels, environment)
                container_status_info = get_list_container_statuses(
                    pod.status.container_statuses)
                container_info = {}
                for container in pod.spec.containers:
                    if container.name in container_status_info:
                        container_info[container.name] = {
                            'name':
                            container.name,
                            'image':
                            container.image,
                            'status':
                            container_status_info[container.name],
                            'service_port_mapping':
                            map_service_to_container(container.ports,
                                                     namespace_services_info)
                        }
                    else:
                        container_info[container.name] = {
                            'name': container.name,
                            'image': container.image,
                            'port': get_spec_container_ports(container.ports)
                        }
                pod_info['containers'] = list(container_info.values())

                pods_info[environment]['pods'].append(pod_info)
        return list(pods_info.values())
    except apiError.DevOpsError as e:
        if e.status_code != 404:
            raise e


def delete_dev_environment_by_branch(namespace, branch_name):
    try:
        info = []
        for deployment in ApiK8sClient().list_namespaced_deployment(
                namespace).items:
            is_iii = check_if_iii_template(deployment.metadata)
            if is_iii is True and branch_name == deployment.metadata.annotations[
                    iii_template['branch']]:
                info.append(
                    delete_namespace_deployment(namespace,
                                                deployment.metadata.name))
        return info
    except apiError.DevOpsError as e:
        if e.status_code != 404:
            raise e


def update_dev_environment_by_branch(namespace, branch_name):
    try:
        info = []
        for deployment in ApiK8sClient().list_namespaced_deployment(
                namespace).items:
            is_iii = check_if_iii_template(deployment.metadata)
            if is_iii is True and branch_name == deployment.metadata.annotations[
                    iii_template['branch']]:
                deployment.spec.template.metadata.annotations[
                    "iiidevops_redeploy_at"] = str(datetime.utcnow())
                update_namespace_deployment(namespace,
                                            deployment.metadata.name,
                                            deployment)
        return info
    except apiError.DevOpsError as e:
        if e.status_code != 404:
            raise e


def redeploy_deployment(namespace, deployment_name):
    try:
        deploy = read_namespace_deployment(namespace, deployment_name)
        if deploy.spec.template.metadata.annotations is None:
            deploy.spec.template.metadata.annotations = {}
        deploy.spec.template.metadata.annotations[
            f"{deployment_name}_redeploy_at"] = str(datetime.utcnow())
        update_namespace_deployment(namespace, deployment_name, deploy)
    except apiError.DevOpsError as e:
        if e.status_code != 404:
            raise e


def get_list_container_statuses(container_statuses):
    try:
        container_status_info = {}
        for container_status in container_statuses:
            container_status_info[
                container_status.name] = analysis_k8s_container_status(
                    container_status)
        return container_status_info
    except apiError.DevOpsError as e:
        if e.status_code != 404:
            raise e


def secret_info_by_iii(secret):
    try:
        info = {
            'is_iii': check_if_iii_default(secret.metadata.name, secret.type),
            'name': secret.metadata.name,
            'data': secret.data
        }
        return info
    except apiError.DevOpsError as e:
        if e.status_code != 404:
            raise e


def configmap_info_by_iii(configmap):
    try:
        info = {
            'is_iii': check_if_iii_default(configmap.metadata.name),
            'name': configmap.metadata.name,
            'data': configmap.data
        }
        return info
    except apiError.DevOpsError as e:
        if e.status_code != 404:
            raise e


def list_namespace_services_by_iii(namespace):
    try:
        list_services = {}
        for service in ApiK8sClient().list_namespaced_service(namespace).items:
            annotations = service.metadata.annotations
            is_iii = check_if_iii_template(service.metadata)
            if is_iii is True:
                list_services, environment = check_iii_project_branch_key_exist(
                    service.metadata, list_services, '', 'services')
                service_info = {
                    'type':
                    service.spec.type,
                    'name':
                    service.metadata.name,
                    'service_selector':
                    service.spec.selector,
                    'service_type':
                    annotations[iii_template['type']],
                    'public_endpoints':
                    json.loads(annotations['field.cattle.io/publicEndpoints'])
                }
                service_info['url'] = map_port_and_public_endpoint(
                    service.spec.ports, service_info['public_endpoints'],
                    annotations[iii_template['type']], namespace,
                    list_services[environment]['branch'])
                list_services[environment]['services'].append(service_info)
        return list_services
    except apiError.DevOpsError as e:
        if e.status_code != 404:
            raise e


def get_list_service_match_pods_labels(list_services, pod_labels, environment):
    namespace_services_info = []
    if environment in list_services:
        for service in list_services[environment]['services']:
            is_match = check_match_selector(service['service_selector'],
                                            pod_labels)
            if is_match is True:
                for url in service['url']:
                    url['name'] = service['name']
                    url['service_type'] = service['service_type']
                    namespace_services_info.append(url)
    return namespace_services_info


def check_iii_project_branch_key_exist(metadata,
                                       target_info,
                                       git_url='',
                                       info_type='pods'):
    project_name = metadata.annotations[iii_template['project_name']]
    branch = metadata.annotations[iii_template['branch']]
    commit_id = metadata.annotations[iii_template['commit_id']]
    environment = f'{project_name}:{branch}'
    if environment not in target_info:
        target_info[environment] = {}
        target_info[environment]['project_name'] = project_name
        target_info[environment]['branch'] = branch
        target_info[environment]['commit_id'] = commit_id
        if git_url != '':
            target_info[environment][
                'commit_url'] = f'{git_url[0:-4]}/-/commit/{commit_id}'
        target_info[environment][info_type] = []
    return target_info, environment


def analysis_k8s_container_status(container_status):
    info = {}
    analysis_status = analysis_container_status_time(container_status)
    info['state'] = analysis_status['state']
    info['time'] = analysis_status['status_time']
    info['restart'] = container_status.restart_count
    info['image'] = container_status.image
    info['name'] = container_status.name
    info['ready'] = container_status.ready
    return info


def check_match_selector(selectors, pod_label):
    try:
        res = all(
            pod_label.get(key, None) == val for key, val in selectors.items())
        return res
    except apiError.DevOpsError as e:
        if e.status_code != 404:
            raise e


def map_service_to_container(container_ports, services):
    try:
        mapping_info = []
        for container_port in container_ports:
            port_info = analysis_container_port(container_port)
            port_info['services'] = check_service_map_container(
                port_info, services)
            mapping_info.append(port_info)
        return mapping_info
    except apiError.DevOpsError as e:
        if e.status_code != 404:
            raise e


def check_service_map_container(container_port, services):
    try:
        services_info = []
        for service in services:
            if service['port_name'] == container_port['name'] or \
                    service['target_port'] == container_port['container_port']:
                services_info.append(service)
        return services_info
    except apiError.DevOpsError as e:
        if e.status_code != 404:
            raise e


def analysis_container_port(port):
    try:
        port_info = {
            'container_port': port.container_port,
            'name': port.name,
            'protocol': port.protocol
        }
        return port_info
    except apiError.DevOpsError as e:
        if e.status_code != 404:
            raise e


def get_spec_container_ports(ports):
    try:
        info = []
        for port in ports:
            info.append(analysis_container_port(port))
        return info
    except apiError.DevOpsError as e:
        if e.status_code != 404:
            raise e


def map_port_and_public_endpoint(ports,
                                 public_endpoints,
                                 service_type='',
                                 namespace='',
                                 branch=''):
    try:
        info = []
        for port in ports:
            for public_endpoint in public_endpoints:
                url_info = {}
                if getattr(port, 'node_port') == public_endpoint.get('port'):
                    url_info['port_name'] = getattr(port, 'name')
                    url_info['target_port'], url_info[
                        'port'] = identify_target_port(
                            getattr(port, 'target_port'),
                            getattr(port, 'port'))
                    url_info['url'] = identify_external_url(
                        public_endpoint, port.node_port, service_type,
                        namespace, branch)
                    info.append(url_info)
        return info
    except apiError.DevOpsError as e:
        if e.status_code != 404:
            raise e


# Identify Service Exact target port on container port
def identify_target_port(target_port, port):
    try:
        output_target_port = port
        # M Check The Direct User Target Port
        if isinstance(target_port, numbers.Integral) is True:
            output_target_port = target_port
        return output_target_port, port
    except apiError.DevOpsError as e:
        if e.status_code != 404:
            raise e


# Identify Service Exact External URL
def identify_external_url(public_endpoint,
                          node_port,
                          service_type='',
                          namespace='',
                          branch=''):
    try:
        external_url_format = ""
        http_base = "http://"
        https_base = "https://"
        if service_type != 'db-server':
            external_url_format = http_base
            if config.get('INGRESS_EXTERNAL_TLS') is not None and config.get(
                    'INGRESS_EXTERNAL_TLS') != '':
                external_url_format = https_base

        url = []
        if config.get('INGRESS_EXTERNAL_BASE') != '' and config.get('INGRESS_EXTERNAL_BASE') is not None \
                and service_type not in ['db-server', 'db-gui'] and namespace != '' and branch != '' and \
                check_ingress_exist(namespace, branch):
            url.append(
                f"{external_url_format}{namespace}-{branch}.{config.get('INGRESS_EXTERNAL_BASE')}"
            )
        elif 'hostname' in public_endpoint:
            if service_type != 'db-server':
                external_url_format = http_base
            url.append(
                f"{external_url_format}{public_endpoint['hostname']}:{node_port}"
            )
        else:
            if service_type != 'db-server':
                external_url_format = http_base
            for address in public_endpoint['addresses']:
                url.append(f"{external_url_format}{address}:{node_port}")
        return url
    except apiError.DevOpsError as e:
        if e.status_code != 404:
            raise e


def get_spec_containers_image_and_name(containers):
    try:
        container_list = []
        for container in containers:
            container_info = {'image': container.image, 'name': container.name}
            container_list.append(container_info)
        return container_list
    except apiError.DevOpsError as e:
        if e.status_code != 404:
            raise e


def analysis_container_status_time(container_status):
    try:
        container_status_time = {}
        status_time = None
        if container_status.state.running is not None:
            status = "running"
            if container_status.state.running.started_at is not None:
                status_time = str(container_status.state.running.started_at)
        elif container_status.state.terminated is not None:
            status = "terminated"
            if container_status.state.terminated.finished_at is not None:
                status_time = str(
                    container_status.state.terminated.finished_at)
        else:
            status = "waiting"
        container_status_time['status_time'] = status_time
        container_status_time['state'] = status
        return container_status_time
    except apiError.DevOpsError as e:
        if e.status_code != 404:
            raise e


def check_if_iii_default(name, var_type=None):
    is_iii = False
    if name in iii_env_default and (var_type not in env_normal_type
                                    or var_type is None):
        is_iii = True
    return is_iii


def check_if_iii_template(metadata):
    is_iii = False
    if metadata.annotations is not None and \
            iii_template['project_name'] in metadata.annotations and \
            iii_template['branch'] in metadata.annotations and \
            iii_template['commit_id'] in metadata.annotations and \
            'app' in metadata.labels:
        is_iii = True
    return is_iii


def get_iii_template_info(metadata):
    template_info = {
        'label': metadata.labels['app'],
        'branch': metadata.annotations[iii_template['branch']],
        'project_name': metadata.annotations[iii_template['project_name']],
        'commit_id': metadata.annotations[iii_template['commit_id']]
    }
    return template_info


class K8sPodExec(object):
    def __init__(self, data):
        self.namespace_name = data['project_name']
        self.pod_name = data['pod_name']
        self.container_name = data.get("container_name")
        self.exec_command = ['/bin/bash']
        if self.container_name is None:
            self.resp = k8s_stream(
                ApiK8sClient().core_v1.connect_get_namespaced_pod_exec,
                self.pod_name,
                self.namespace_name,
                command=self.exec_command,
                stderr=True,
                stdin=True,
                stdout=True,
                tty=True,
                _preload_content=False)
        else:
            self.resp = k8s_stream(
                ApiK8sClient().core_v1.connect_get_namespaced_pod_exec,
                self.pod_name,
                self.namespace_name,
                command=self.exec_command,
                container=self.container_name,
                stderr=True,
                stdin=True,
                stdout=True,
                tty=True,
                _preload_content=False)

    def exec_namespace_pod(self, data):
        command = data['command']
        while self.resp.is_open():
            self.resp.update(timeout=1)
            if self.resp.peek_stdout():
                output_mess = self.resp.read_stdout()
                print("STDOUT: %s" % output_mess)
                emit('get_cmd_response', {'output': output_mess})
            elif self.resp.peek_stderr():
                output_err = self.resp.read_stderr()
                print("STDERR: %s" % output_err)
                emit('get_cmd_response', output_err)
            elif command:
                print("Running command... %s\n" % command)
                self.resp.write_stdin(command + "\n")
                command = None
            else:
                break

        # self.resp.close()


class KubernetesPodExec(Namespace):
    k8s_pod_exec = None

    def on_connect(self):
        print('connect')

    def on_disconnect(self):
        print('Client disconnected')

    def on_pod_exec_cmd(self, data):
        print('exec_namespace_pod_log')
        if self.k8s_pod_exec is None or (self.k8s_pod_exec.namespace_name != data['project_name']
                                         or self.k8s_pod_exec.pod_name != data['pod_name']
                                         or self.k8s_pod_exec.container_name != data.get("container_name")):
            self.k8s_pod_exec = K8sPodExec(data)
        self.k8s_pod_exec.exec_namespace_pod(data)
