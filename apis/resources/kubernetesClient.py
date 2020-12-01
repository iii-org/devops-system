import os
import json

from kubernetes import client as k8s_client
from kubernetes import config as k8s_config

from flask_restful import Resource, reqparse

from resources.logger import logger


def list_service_all_namespaces():
    k8s_config.load_kube_config()
    v1 = k8s_client.CoreV1Api()
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
    k8s_config.load_kube_config()
    v1 = k8s_client.CoreV1Api()
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
    k8s_config.load_kube_config()
    v1 = k8s_client.CoreV1Api()
    ret = v1.create_namespace(k8s_client.V1Namespace(metadata=k8s_client.V1ObjectMeta(name=project_name)))
    print ("create_name_space: {0}".format(ret))
    
def delete_namespace(project_name):
    k8s_config.load_kube_config()
    v1 = k8s_client.CoreV1Api()
    os.system("kubectl get ns {0} -o json > {0}-ns.json".format(project_name))
    # os.system("cat {0}-ns.json".format(project_name))
    ns_json = json.load(open("{0}-ns.json".format(project_name)))
    ns_json['spec']['finalizers']=[]
    print(ns_json)
    #ret = v1.create_namespace(k8s_client.V1Namespace(metadata=k8s_client.V1ObjectMeta(name=project_name, finalizers=[])))
    #ret = v1.delete_namespace(project_name)
    #print("delete K8s namespace {0}".format(ret))

class tmp_api(Resource):
    def post(self):
        parser = reqparse.RequestParser()
        parser.add_argument('project_name', type=str)
        args = parser.parse_args()
        create_namespace(args['project_name'])
    
    def delete(self):
        parser = reqparse.RequestParser()
        parser.add_argument('project_name', type=str)
        args = parser.parse_args()
        delete_namespace(args['project_name'])