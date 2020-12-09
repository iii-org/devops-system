import os
import json
import util as util

import base64
from kubernetes import client as k8s_client
from kubernetes import config as k8s_config


from flask_restful import Resource, reqparse

import resources.apiError as apiError
from resources.logger import logger

k8s_config.load_kube_config()
v1 = k8s_client.CoreV1Api()
rbac = k8s_client.RbacAuthorizationV1Api()
util.enable_k8s_proxy()

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
        logger.info("{0}, {1}".format(node.status.addresses,
                                      node.metadata.labels['node-role.kubernetes.io/worker']))
        ip = None
        hostname = None
        if node.metadata.labels['node-role.kubernetes.io/worker']:
            for address in node.status.addresses:
                # logger.info('address: {0}'.format(address))
                if address.type == 'InternalIP':
                    ip = address.address
                elif address.type == 'Hostname':
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

def delete_namespace(project_name):
    try:
        ret = v1.delete_namespace(project_name)
        os.system("kubectl get ns {0} -o json > {0}.json".format(project_name))
        ns_json = json.load(open("{0}.json".format(project_name)))
        os.remove("{0}.json".format(project_name))
        ns_json['spec']['finalizers']=[]
        url = "http://127.0.0.1:8001/api/v1/namespaces/{0}/finalize".format(project_name)
        headers={}
        headers['Content-Type'] = 'application/json'
        util.api_request('PUT', url, headers=headers, data=ns_json)
    except apiError.DevOpsError as e:
        if e.status_code != 404:
            raise e
    
    
def create_service_account(login_sa_name):
    sa = v1.create_namespaced_service_account("account", k8s_client.V1ServiceAccount(
        metadata=k8s_client.V1ObjectMeta(name=login_sa_name)))
    return sa

def delete_service_account(login_sa_name):
    sa = v1.delete_namespaced_service_account(login_sa_name,"account")
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
    sa_secrets_name = v1.read_namespaced_service_account(sa_name,"account").secrets[0].name
    server_ip = str(node_list[0]['ip'])
    sa_secret = v1.read_namespaced_secret(sa_secrets_name,"account")
    sa_ca =  sa_secret.data['ca.crt']
    sa_token = str(base64.b64decode(str(sa_secret.data['token'])).decode('utf-8'))
    sa_config = "apiVersion: v1\nclusters:\n- cluster:\n    certificate-authority-data: "+sa_ca+"\n    server: https://"+server_ip+":6443"+\
                "\n  name: cluster\ncontexts:\n- context:\n    cluster: cluster\n    user: "+sa_name+"\n  name: default\ncurrent-context: default\nkind: Config\npreferences: {}\nusers:\n- name: "+sa_name+\
                "\n  user:\n    token: "+sa_token
    config = {
            'name' : sa_name,
            'config' : sa_config
        }
    return config

def get_namespace_quota(namespace):
    namespace_quota = v1.read_namespaced_resource_quota("project-quota",namespace)
    resource = {
        'quota' : namespace_quota.status.hard,
        'used' : namespace_quota.status.used
    }
    return resource
    
def create_role_in_namespace(namespace):
    rules = [k8s_client.V1PolicyRule(["*"], resources=["*"], verbs=["*"], )]
    role = k8s_client.V1Role(rules=rules)
    role.metadata = k8s_client.V1ObjectMeta(namespace = namespace, name = "{0}-user-role".format(namespace))
    try:
        rbac.create_namespaced_role(namespace,role)
    except apiError.DevOpsError as e:
        if e.status_code != 404:
            raise e

def create_role_binding(namespace, sa_name):
    # create ns RoleBinding
    role_binding = k8s_client.V1RoleBinding(
            metadata=k8s_client.V1ObjectMeta(namespace=namespace, name="{0}-rb".format(sa_name)),
            subjects=[k8s_client.V1Subject(namespace="account", name=sa_name, kind="ServiceAccount")],
            role_ref=k8s_client.V1RoleRef(kind="Role", api_group="rbac.authorization.k8s.io", name="user-role",))
    try:
        rbac.create_namespaced_role_binding(namespace=namespace,body=role_binding)
    except apiError.DevOpsError as e:
        if e.status_code != 404:
            raise e
