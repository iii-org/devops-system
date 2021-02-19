import os
import json

from kubernetes.client import ApiException

import util as util

import base64
from kubernetes import client as k8s_client
from kubernetes import config as k8s_config

from flask_restful import Resource, reqparse


import resources.apiError as apiError
from resources.logger import logger

con = k8s_client.Configuration()
con.verify_ssl = False
k8s_client.Configuration.set_default(con)
k8s_config.load_kube_config()
v1 = k8s_client.CoreV1Api()
rbac = k8s_client.RbacAuthorizationV1Api()
extensions_v1beta1 =k8s_client.ExtensionsV1beta1Api()

def list_service_all_namespaces():
    service_list = []
    for service in v1.list_service_for_all_namespaces().items:
        logger.info("{0}, {1}, {2}, {3}".format(service.metadata.name,
                                                service.metadata.namespace, service.spec.type,
                                                service.spec.ports[0].node_port))
        port_list = []
        for port in service.spec.ports:
            port_list.append({"nodePort": port.node_port, "protocol": port.protocol,
                              "target_port": port.target_port, "name": port.name, "port": port.port})
        service_list.append({
            "name": service.metadata.name,
            "namespace": service.metadata.namespace,
            "type": service.spec.type,
            "ports": port_list
        })
    # logger.info("list_service_all_namespaces service_list: {0}".format(service_list))
    return service_list


def list_work_node():
    node_list = []
    for node in v1.list_node().items:
        ip = None
        hostname = None
        if 'node-role.kubernetes.io/worker' in node.metadata.labels:
            ip = node.metadata.annotations['projectcalico.org/IPv4Address'].split('/')[0]
            for address in node.status.addresses:
                # logger.info('address: {0}'.format(address))
                #if address.type == 'InternalIP':
                #    ip = address.address
                if address.type == 'Hostname':
                    hostname = address.address
            node_list.append({
                "worker": node.metadata.labels['node-role.kubernetes.io/worker'],
                "ip": ip,
                "hostname": hostname
            })
    logger.info("list_worknode node_list: {0}".format(node_list))
    return node_list


def create_namespace(project_name):
    try:
        ret = v1.create_namespace(k8s_client.V1Namespace(metadata=k8s_client.V1ObjectMeta(name=project_name)))
    except apiError.DevOpsError as e:
        if e.status_code != 404:
            raise e


def list_namespace():
    try:
        namespace_list = []
        for namespace in v1.list_namespace().items:
            namespace_list.append(namespace.metadata.name)
        return namespace_list
    except apiError.DevOpsError as e:
        if e.status_code != 404:
            raise e


def delete_namespace(project_name):
    try:
        ret = v1.delete_namespace(project_name)
    except ApiException as e:
        if e.status != 404:
            raise e


def create_service_account(login_sa_name):
    sa = v1.create_namespaced_service_account("account", k8s_client.V1ServiceAccount(
        metadata=k8s_client.V1ObjectMeta(name=login_sa_name)))
    return sa


def delete_service_account(login_sa_name):
    sa = v1.delete_namespaced_service_account(login_sa_name, "account")
    return sa


def list_service_account():
    sa_list = []
    for sa in v1.list_namespaced_service_account("account").items:
        sa_list.append(sa.metadata.name)
    return sa_list


def get_service_account_config(sa_name):
    node_list = []
    for node in v1.list_node().items:
        ip = None
        hostname = None
        if "node-role.kubernetes.io/controlplane" in node.metadata.labels:
            for address in node.status.addresses:
                if address.type == 'InternalIP':
                    ip = address.address
                elif address.type == 'Hostname':
                    hostname = address.address
            node_list.append({
                "controlplane": node.metadata.labels['node-role.kubernetes.io/controlplane'],
                "ip": ip,
                "hostname": hostname
            })
    sa_secrets_name = v1.read_namespaced_service_account(sa_name, "account").secrets[0].name
    server_ip = str(node_list[0]['ip'])
    sa_secret = v1.read_namespaced_secret(sa_secrets_name, "account")
    sa_ca = sa_secret.data['ca.crt']
    sa_token = str(base64.b64decode(str(sa_secret.data['token'])).decode('utf-8'))
    sa_config = "apiVersion: v1\nclusters:\n- cluster:\n    certificate-authority-data: " + sa_ca + "\n    server: https://" + server_ip + ":6443" + \
                "\n  name: cluster\ncontexts:\n- context:\n    cluster: cluster\n    user: " + sa_name + "\n  name: default\ncurrent-context: default\nkind: Config\npreferences: {}\nusers:\n- name: " + sa_name + \
                "\n  user:\n    token: " + sa_token
    config = {
        'name': sa_name,
        'config': sa_config
    }
    return config


def get_namespace_quota(namespace):
    namespace_quota = v1.read_namespaced_resource_quota("project-quota", namespace)
    resource = {
        'quota': namespace_quota.status.hard,
        'used': namespace_quota.status.used
    }
    return resource


def create_namespace_quota(namespace):
    try:
        resource_quota = k8s_client.V1ResourceQuota(
            spec=k8s_client.V1ResourceQuotaSpec(
                hard={"cpu": "10", "memory": "10G", "pods": "20", "persistentvolumeclaims": "0", "configmaps": "60",
                      "secrets": "60", "services.nodeports": "10"}))
        resource_quota.metadata = k8s_client.V1ObjectMeta(namespace=namespace, name="project-quota")
        ret = v1.create_namespaced_resource_quota(namespace, resource_quota)
    except apiError.DevOpsError as e:
        if e.status_code != 404:
            raise e


def create_namespace_limitrange(namespace):
    try:
        resource_quota = k8s_client.V1LimitRange(spec=k8s_client.V1LimitRangeSpec(
            limits=[{"default": {"memory": "10Gi", "cpu": 10},
                     "defaultRequest": {"memory": "64Mi", "cpu": 0.1}, "type": "Container"}]),
            metadata=k8s_client.V1ObjectMeta(namespace=namespace, name="project-limitrange"))
        ret = v1.create_namespaced_limit_range(namespace, resource_quota)
    except apiError.DevOpsError as e:
        if e.status_code != 404:
            raise e


def list_limitrange_in_namespace(namespace):
    try:
        limitrange_list = []
        for limitrange in v1.list_namespaced_limit_range(namespace).items:
            limitrange_list.append(limitrange.metadata.name)
        return limitrange_list
    except apiError.DevOpsError as e:
        if e.status_code != 404:
            raise e


def update_namespace_quota(namespace, resource):
    try:
        namespace_quota = v1.read_namespaced_resource_quota("project-quota", namespace)
        namespace_quota.spec.hard = resource
        ret = v1.replace_namespaced_resource_quota("project-quota", namespace, namespace_quota)
    except apiError.DevOpsError as e:
        if e.status_code != 404:
            raise e


def create_role_in_namespace(namespace):
    rules = [k8s_client.V1PolicyRule(["*"], resources=["*"], verbs=["*"], )]
    role = k8s_client.V1Role(rules=rules)
    role.metadata = k8s_client.V1ObjectMeta(namespace=namespace, name="user-role")
    try:
        rbac.create_namespaced_role(namespace, role)
    except apiError.DevOpsError as e:
        if e.status_code != 404:
            raise e


def list_role_in_namespace(namespace):
    try:
        role_list = []
        for roles in rbac.list_namespaced_role(namespace).items:
            role_list.append(roles.metadata.name)
        return role_list
    except apiError.DevOpsError as e:
        if e.status_code != 404:
            raise e


def delete_role_in_namespace(namespace, name):
    try:
        rbac.delete_namespaced_role(name, namespace)
    except apiError.DevOpsError as e:
        if e.status_code != 404:
            raise e


def create_role_binding(namespace, sa_name):
    # create ns RoleBinding
    role_binding = k8s_client.V1RoleBinding(
        metadata=k8s_client.V1ObjectMeta(namespace=namespace, name="{0}-rb".format(sa_name)),
        subjects=[k8s_client.V1Subject(namespace="account", name=sa_name, kind="ServiceAccount")],
        role_ref=k8s_client.V1RoleRef(kind="Role", api_group="rbac.authorization.k8s.io", name="user-role", ))
    try:
        rbac.create_namespaced_role_binding(namespace=namespace, body=role_binding)
    except apiError.DevOpsError as e:
        if e.status_code != 404:
            raise e


def delete_role_binding(namespace, role_binding_name):
    try:
        rbac.delete_namespaced_role_binding(role_binding_name, namespace)
    except apiError.DevOpsError as e:
        if e.status_code != 404:
            raise e


def list_pod(namespace):
    try:
        pod_list = []
        for pods in v1.list_namespaced_pod(namespace).items:
            containers = []
            if pods.status.container_statuses is not None:
                for container_status in pods.status.container_statuses:
                    status=None
                    status_time=None
                    if container_status.state.running is not None:
                        status = "running"
                        if container_status.state.running.started_at is not None:
                            status_time = str(container_status.state.running.started_at)
                    elif container_status.state.terminated is not None:
                        status = "terminated"
                        if container_status.state.terminated.finished_at is not None:
                            status_time = str(container_status.state.terminated.finished_at)
                    else:
                        status = "waiting"
                    containers.append({"name": container_status.name, "image": container_status.image,
                                    "restart": container_status.restart_count, "state": status, 
                                    "time": status_time})
            pod_list.append({'name':pods.metadata.name, 
                             "created_time": str(pods.metadata.creation_timestamp),
                             'containers': containers})
        return pod_list
    except apiError.DevOpsError as e:
        if e.status_code != 404:
            raise e


def delete_pod(namespace, name):
    try:
        pod = v1.delete_namespaced_pod(name, namespace)
        return pod.metadata.self_link
    except apiError.DevOpsError as e:
        if e.status_code != 404:
            raise e


def get_pod_logs(namespace, name, container_name=None):
    try:
        pod_log = v1.read_namespaced_pod_log(name, namespace, container=container_name)
        return pod_log
    except apiError.DevOpsError as e:
        if e.status_code != 404:
            raise e


def list_deployment(namespace):
    try:
        deployment_list = []
        for deployments in k8s_client.AppsV1Api().list_namespaced_deployment(namespace).items:
            deployment_list.append({"deployment_name": deployments.metadata.name,
                                    "available_pod_number": deployments.status.available_replicas,
                                    "total_pod_number": deployments.status.replicas,
                                    "createion_timestamp" : str(deployments.metadata.creation_timestamp),
                                    "container": deployment_analysis_containers(deployments.spec.template.spec.containers)
                                    })
        return deployment_list
    except apiError.DevOpsError as e:
        if e.status_code != 404:
            raise e


def get_deployment(namespace, name):
    try:
        return k8s_client.AppsV1Api().read_namespaced_deployment(name, namespace)
    except apiError.DevOpsError as e:
        if e.status_code != 404:
            raise e


def update_deployment(namespace, name, body):
    try:
        return k8s_client.AppsV1Api().patch_namespaced_deployment(name, namespace, body)
    except apiError.DevOpsError as e:
        if e.status_code != 404:
            raise e


def delete_deployment(namespace, name):
    try:
        deployment = k8s_client.AppsV1Api().delete_namespaced_deployment(name, namespace)
        return deployment.details.name
    except apiError.DevOpsError as e:
        if e.status_code != 404:
            raise e


def list_service(namespace):
    try:
        service_list = []
        for services in v1.list_namespaced_service(namespace).items:
            service_list.append(services.metadata.name)
        return service_list
    except apiError.DevOpsError as e:
        if e.status_code != 404:
            raise e


def delete_service(namespace, name):
    try:
        service = v1.delete_namespaced_service(name, namespace)
        return service.details.name
    except apiError.DevOpsError as e:
        if e.status_code != 404:
            raise e


def create_secret(namespace, secret_name, secrets):
    for key, value in secrets.items():
        secrets[key] = base64.b64encode(bytes(value, encoding='utf-8')).decode('utf-8')
    try:
        body = k8s_client.V1Secret(
            metadata=k8s_client.V1ObjectMeta(namespace=namespace, name=secret_name),
            data=secrets)
        secret = v1.create_namespaced_secret(namespace, body)
    except apiError.DevOpsError as e:
        if e.status_code != 404:
            raise e

def patch_secret(namespace, secret_name, secrets):
    for key, value in secrets.items():
        secrets[key] = base64.b64encode(bytes(value, encoding='utf-8')).decode('utf-8')
    try:
        body = k8s_client.V1Secret(
            metadata=k8s_client.V1ObjectMeta(namespace=namespace, name=secret_name),
            data=secrets)
        secret = v1.patch_namespaced_secret(secret_name, namespace, body)
    except apiError.DevOpsError as e:
        if e.status_code != 404:
            raise e


def list_secret(namespace):
    try:
        secret_list = []
        for secrets in v1.list_namespaced_secret(namespace).items:
            secret_list.append(secrets.metadata.name)
        return secret_list
    except apiError.DevOpsError as e:
        if e.status_code != 404:
            raise e


def delete_secret(namespace, name):
    try:
        secret = v1.delete_namespaced_secret(name, namespace)
        return secret.details.name
    except apiError.DevOpsError as e:
        if e.status_code != 404:
            raise e


def list_configmap(namespace):
    try:
        configmap_list = []
        for configmaps in v1.list_namespaced_config_map(namespace).items:
            configmap_list.append(configmaps.metadata.name)
        return configmap_list
    except apiError.DevOpsError as e:
        if e.status_code != 404:
            raise e


def delete_configmap(namespace, name):
    try:
        configmap = v1.delete_namespaced_config_map(name, namespace)
        return configmap.details.name
    except apiError.DevOpsError as e:
        if e.status_code != 404:
            raise e


def list_ingress(namespace):
    try:
        ingress_list = []
        for ingress in extensions_v1beta1.list_namespaced_ingress(namespace).items:
            ingress_info ={}
            ingress_info["name"] = ingress.metadata.name
            ingress_info["created_time"] = str(ingress.metadata.creation_timestamp)
            ip = None
            if ingress.status.load_balancer.ingress is not None:
                ip = ingress.status.load_balancer.ingress[0].ip
            ingress_info["ingress_list"] = []
            for rule in ingress.spec.rules:
                hostname = ip
                if rule.host != None:
                    hostname = rule.host
                for path in rule.http.paths:
                    if hostname is not None:
                        ingress_info["ingress_list"].append({"hostname_path": hostname+path.path,
                            "service": f"{path.backend.service_name}:{path.backend.service_port}"})
                    else:
                        ingress_info["ingress_list"].append({"hostname_path": path.path,
                            "service": f"{path.backend.service_name}:{path.backend.service_port}"})
            ingress_info["tls"] = ingress.spec.tls
            ingress_list.append(ingress_info)
        return ingress_list
    except apiError.DevOpsError as e:
        if e.status_code != 404:
            raise e

def list_deployment_environement(namespace):
    try:

        deployment_info = {}
        list_node = list_work_node()
        print(list_node)
        work_node_ip = list_node[0]['ip']
        for deployments in k8s_client.AppsV1Api().list_namespaced_deployment(namespace).items:
            if 'iiidevops.org/project_name' in deployments.spec.template.metadata.labels and 'iiidevops.org/branch' in  deployments.spec.template.metadata.labels:    
                project_name = deployments.spec.template.metadata.labels['iiidevops.org/project_name']
                branch_name = deployments.spec.template.metadata.labels['iiidevops.org/branch']                                
                environement = f'{project_name} {branch_name}'
                if environement not in deployment_info:
                    deployment_info[environement] = {}
                    deployment_info[environement]['project_name'] = project_name
                    deployment_info[environement]['branch'] = branch_name
                    deployment_info[environement]['workload'] = []                
                workload_info = {}
                workload_info['name']= deployments.metadata.name
                workload_info['create_time']= str(deployments.metadata.creation_timestamp)
                workload_info['pulicEnpoints'] = get_deployment_publicEndpoint(deployments.metadata.annotations['field.cattle.io/publicEndpoints'],work_node_ip)
                workload_info['container'] = []
                for container in deployments.spec.template.spec.containers:
                    container_info = {}
                    container_info['name'] = container.name
                    container_info['image'] = container.image
                    container_info['commit_id'] = get_container_commit_id(container)
                    workload_info['container'].append(container_info)
                deployment_info[environement]['workload'].append(workload_info)
                # list_environment.append(deployment_info)

        return deployment_info
        # return service_list
    except apiError.DevOpsError as e:
        if e.status_code != 404:
            raise e

def deployment_analysis_containers(containers):
    try:
        container_list = []
        for container in containers:
            container_info = {}
            container_info['image'] = container.image
            container_info['name'] = container.name
            container_list.append(container_info)        
        return container_list
    except apiError.DevOpsError as e:
        if e.status_code != 404:
            raise e
def get_deployment_publicEndpoint(public_endpoints,work_node_ip):
    try:
        
        # print(json.loads(public_endpoints))
        # print(type(publicEndpoints))
        # print
        list_public_endpoint = []
        for public_endpoint in json.loads(public_endpoints):
            endpoint_info ={}
            if "hostname" in public_endpoint:
                endpoint_info['name'] = public_endpoint['serviceName']               
                endpoint_info['url'] = "http://{0}/{1}".format(public_endpoint['hostname'], public_endpoint['path'])
                list_public_endpoint.append(endpoint_info)
            else:
                endpoint_info['name'] = public_endpoint['serviceName']               
                endpoint_info['url'] = "http://{0}:{1}".format(work_node_ip, public_endpoint['port'])
                list_public_endpoint.append(endpoint_info)
        return list_public_endpoint
    except apiError.DevOpsError as e:
        if e.status_code != 404:
            raise e

def get_container_commit_id(container):
    try:
        commit_id = ''
        print(container)
        if container.env is not None:
            for env  in container.env:                                                
                 if env.name is 'commitID':
                     commit_id = env.value
                     break
        return commit_id
    except apiError.DevOpsError as e:
        if e.status_code != 404:
            raise e