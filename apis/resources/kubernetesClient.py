from kubernetes import client as k8s_client
from kubernetes import config as k8s_config
import logging
logger = logging.getLogger('devops.api')

class KubernetesClient(object):
    
    def list_service_all_namespaces(self):
        k8s_config.load_kube_config()
        v1 = k8s_client.CoreV1Api()
        service_list =[]
        for service in v1.list_service_for_all_namespaces().items:
            logger.info("{0}, {1}, {2}, {3}".format(service.metadata.name, 
                service.metadata.namespace, service.spec.type, service.spec.ports[0].node_port))
            port_list =[]
            for port in service.spec.ports:
                port_list.append({"nodePort": port.node_port, "protocol": port.protocol,
                    "target_port": port.target_port, "name": port.name, "port": port.port})
            service_list.append({
                "name": service.metadata.name,
                "namespce": service.metadata.namespace,
                "type": service.spec.type,
                "ports": port_list
            })
        logger.info("list_service_all_namespaces service_list: {0}".format(service_list))
        return service_list

    def list_worknode(self):
        k8s_config.load_kube_config()
        v1 = k8s_client.CoreV1Api()
        node_list =[]
        for node in v1.list_node().items:
            logger.info("{0}, {1}".format(node.status.addresses, \
                node.metadata.labels['node-role.kubernetes.io/worker']))
            ip = None
            hostname = None
            for address in node.status.addresses:
                if address['type'] == 'InternalIP':
                    ip = address['address']
                elif address['type']  
            node_list.append({
                "worker": node.metadata.labels['node-role.kubernetes.io/worker'],
                "ip": service.metadata.namespace,
                "hostname": service.spec.type
            })
        logger.info("list_worknode node_list: {0}".format(node_list))
        return node_list