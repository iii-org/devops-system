from kubernetes import client as k8s_client
from kubernetes import config as k8s_config

from resources.logger import logger

k8s_config.load_kube_config()
v1 = k8s_client.CoreV1Api()

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

def create_service_account(self,login_name):
    sa = v1.create_namespaced_service_account("account",k8s_client.V1ServiceAccount(metadata=k8s_client.V1ObjectMeta(name=login_name)))
    return sa

def list_service_account():
    sa_list = []
    for sa in v1.list_namespaced_service_account("account").items:
        sa_list.append(sa.metadata.name)
    return sa_list