import base64
import json
import os
from datetime import datetime, date
from pathlib import Path

import werkzeug
import yaml
from flask_jwt_extended import jwt_required, get_jwt_identity
from flask_restful import Resource, reqparse, inputs
from kubernetes import client as k8s_client
from sqlalchemy.orm.exc import NoResultFound
from werkzeug.utils import secure_filename

import config
import model
import util as util
from model import db
from resources import apiError, role
from resources import harbor, kubernetesClient
from resources import release

DEFAULT_RESTART_NUMBER = 30
default_project_id = "-1"
error_clusters_not_found = "No Exact Cluster Found"
error_clusters_created = "No Exact Cluster Created or Update"
error_application_exists = "Application had been deployed"
DEFAULT_K8S_CONFIG_FILE = 'k8s_config'
DEFAULT_APPLICATION_STATUS = 'Something Error'
APPLICATION_STATUS = {
    1: 'Initializing',
    2: 'Start Image replication',
    3: 'Finish Image replication',
    4: 'Start Kubernetes deployment',
    5: 'Finish Kubernetes deployment',
    9: 'Start Kubernetes deletion',
    10: 'Finish Kubernetes deletion',
    32: 'Deploy stopped',
    3001: 'Error, No Image need to be replicated',
    5001: 'Error, K8s Error'
}


def is_json(string):
    try:
        json.loads(string)
    except ValueError:
        return False
    return True


def get_environments_value(items, value_type):
    out_dict = {}
    for item in items:
        #  config map
        if item.get('type') == value_type and value_type == 'configmap':
            out_dict[str(item.get('key')).strip()] = str(item.get('value')).strip()
        #  secret
        elif item.get('type') == value_type and value_type == 'secret':
            out_dict[str(item.get('key')).strip()] = str(util.base64encode(item.get('value'))).strip()
    return out_dict


def row_to_dict(row):
    ret = {}
    if row is None:
        return row
    for key in type(row).__table__.columns.keys():
        value = getattr(row, key)
        if type(value) is datetime or type(value) is date:
            ret[key] = str(value)
        elif isinstance(value, str) and is_json(value) is True:
            ret[key] = json.loads(value)
        else:
            ret[key] = value
    return ret


def get_cluster_directory_path(server_name):
    root_path = config.get('DEPLOY_CERTIFICATE_ROOT_PATH')
    return root_path + '/cluster/' + util.base64encode(server_name)


def get_cluster_config_path(server_name):
    return get_cluster_directory_path(server_name) + "/" + DEFAULT_K8S_CONFIG_FILE


def check_directory_exists(server_name):
    cluster_path = get_cluster_directory_path(server_name)
    try:
        Path(cluster_path).mkdir(parents=True, exist_ok=True)
        return cluster_path
    except NoResultFound:
        return util.respond(404, "Create Server Directory Error")


def check_cluster(server_name):
    return model.Cluster.query. \
        filter(model.Cluster.name == server_name). \
        first()


def get_cluster_application_information(cluster):
    if cluster is None:
        return []
    output = row_to_dict(cluster)
    ret_output = []
    for application in cluster.application:
        if application is None or application.harbor_info is None:
            continue
        app = {}
        harbor_info = json.loads(application.harbor_info)
        app['id'] = application.id
        app['tag'] = harbor_info.get('tag_name')
        app['project_name'] = harbor_info.get('project')
        app['namespace'] = harbor_info.get('dest_repo_name')
        k8s_yaml = json.loads(application.k8s_yaml)
        cluster_status_id = k8s_yaml.get('status_id', 1)
        app['status'] = APPLICATION_STATUS.get(cluster_status_id, DEFAULT_APPLICATION_STATUS)
        ret_output.append(app)
    output['application'] = ret_output
    return output


def get_clusters(cluster_id=None):
    output = []
    if cluster_id is not None:
        return get_cluster_application_information(model.Cluster.query.filter_by(id=cluster_id).first())
    for cluster in model.Cluster.query.all():
        output.append(get_cluster_application_information(cluster))
    return output


def save_clusters(args, server_name):
    cluster_path = check_directory_exists(server_name)
    file_name = secure_filename(DEFAULT_K8S_CONFIG_FILE)
    file_path = os.path.join(cluster_path, file_name)
    if args.get('k8s_config_file') is not None:
        file = args.get('k8s_config_file', None)
        file.save(os.path.join(cluster_path, file_name))
        file.seek(0)
        content = file.read()
        content = str(content, 'utf-8')
    elif args.get('k8s_config_string') is not None:
        content = util.base64decode(args.get('k8s_config_string'))
        Path(file_path).write_text(content)
    else:
        return util.respond(404, error_clusters_created)
    deploy_k8s_client = DeployK8sClient(server_name)
    deploy_k8s_client.get_api_resources()
    k8s_json = yaml.safe_load(content)
    return k8s_json


def create_cluster(args, server_name, user_id):
    k8s_json = save_clusters(args, server_name)
    now = str(datetime.utcnow())
    new = model.Cluster(
        name=server_name,
        disabled=False,
        creator_id=user_id,
        create_at=now,
        update_at=now,
        cluster_name=k8s_json['clusters'][0]['name'],
        cluster_host=k8s_json['clusters'][0]['cluster']['server'],
        cluster_user=k8s_json['users'][0]['name']
    )
    db.session.add(new)
    db.session.commit()
    return new.id


def update_cluster(cluster_id, args):
    cluster = model.Cluster.query.filter_by(id=cluster_id).one()
    for key in args.keys():
        if not hasattr(cluster, key):
            continue
        elif args[key] is not None:
            setattr(cluster, key, args[key])
    server_name = args.get('name').strip()
    k8s_json = save_clusters(args, server_name)
    cluster.name = server_name
    cluster.cluster_name = k8s_json['clusters'][0]['name'],
    cluster.cluster_host = k8s_json['clusters'][0]['cluster']['server'],
    cluster.cluster_user = k8s_json['users'][0]['name']
    cluster.update_at = str(datetime.utcnow())
    db.session.commit()
    return cluster.id


def delete_cluster(cluster_id):
    cluster = model.Cluster.query.filter_by(id=cluster_id).one()
    k8s_config_path = get_cluster_directory_path(cluster.name)
    k8s_file = Path(get_cluster_config_path(cluster.name))
    k8s_file.unlink()
    k8s_directory = Path(k8s_config_path)
    k8s_directory.rmdir()
    db.session.delete(cluster)
    db.session.commit()


class Clusters(Resource):
    @jwt_required
    def get(self):
        try:
            output = get_clusters()
            return util.success({"cluster": output})
        except NoResultFound:
            return util.respond(404, error_clusters_not_found,
                                error=apiError.repository_id_not_found)

    @jwt_required
    def post(self):
        try:
            user_id = get_jwt_identity()["user_id"]
            role.require_admin()
            parser = reqparse.RequestParser()
            parser.add_argument('name', type=str)
            parser.add_argument(
                'k8s_config_file', type=werkzeug.datastructures.FileStorage, location='files')
            parser.add_argument(
                'k8s_config_string', type=str)
            args = parser.parse_args()
            server_name = args.get('name').strip()
            if check_cluster(server_name) is not None:
                return util.respond(404)
            output = {"cluster_id": create_cluster(
                args, server_name, user_id)}
            return util.success(output)
        except NoResultFound:
            return util.respond(404, error_clusters_not_found,
                                error=apiError.repository_id_not_found)


class Cluster(Resource):
    @jwt_required
    def get(self, cluster_id):
        try:
            output = get_clusters(cluster_id)
            if output is None:
                return util.success()
            return util.success(output)
        except NoResultFound:
            return util.respond(404, error_clusters_not_found,
                                error=apiError.repository_id_not_found)

    @jwt_required
    def put(self, cluster_id):
        try:
            role.require_admin()
            parser = reqparse.RequestParser()
            parser.add_argument('name', type=str)
            parser.add_argument(
                'k8s_config_file', type=werkzeug.datastructures.FileStorage, location='files')
            parser.add_argument('disabled', type=inputs.boolean)
            parser.add_argument(
                'k8s_config_string', type=str)
            args = parser.parse_args()
            output = {"cluster_id": update_cluster(cluster_id, args)}
            return util.success(output)
        except NoResultFound:
            return util.respond(404, error_clusters_not_found,
                                error=apiError.repository_id_not_found)

    @jwt_required
    def delete(self, cluster_id):
        try:
            role.require_admin()
            delete_cluster(cluster_id)
            return util.success()
        except NoResultFound:
            return util.respond(404, error_clusters_not_found,
                                error=apiError.repository_id_not_found)


def get_registries_application_information(registry):
    if registry is None:
        return []
    output = row_to_dict(registry)
    if output.get('type') == 'harbor':
        output.update({
            'access_secret': util.base64decode(output.get('access_secret'))
        })
    ret_output = []
    for application in registry.application:
        if application is None or application.harbor_info is None:
            continue
        app = {}
        harbor_info = json.loads(application.harbor_info)
        app['id'] = application.id
        app['tag'] = harbor_info.get('tag_name')
        app['project_name'] = harbor_info.get('project')
        app['namespace'] = harbor_info.get('dest_repo_name')
        registry_status_id = harbor_info.get('status_id', 1)
        app['status'] = APPLICATION_STATUS.get(registry_status_id, DEFAULT_APPLICATION_STATUS)
        ret_output.append(app)
    output['application'] = ret_output
    return output


def get_registries(registry_id=None):
    output = []
    if registry_id is not None:
        return get_registries_application_information(
            model.Registries.query.filter_by(registries_id=registry_id).first())
    for registry in model.Registries.query.filter().all():
        output.append(get_registries_application_information(registry))

    return output


class Registries(Resource):
    @jwt_required
    def get(self):
        try:
            output = get_registries()
            return util.success({"registries": output})
        except NoResultFound:
            return util.respond(404, error_clusters_not_found,
                                error=apiError.repository_id_not_found)


class Registry(Resource):
    @jwt_required
    def get(self, registry_id):
        try:
            output = get_registries(registry_id)
            return util.success({"registries": output})
        except NoResultFound:
            return util.respond(404, error_clusters_not_found,
                                error=apiError.repository_id_not_found)


def create_default_harbor_data(project, db_release, registry_id, namespace):
    harbor_data = {
        "project": project.display,
        "project_id": project.name,
        "policy_name": project.name + "-release-" + str(db_release.id) + '-at-' + namespace,
        "repo_name": project.name,
        "image_name": db_release.branch,
        "tag_name": db_release.tag_name,
        "description": 'Automate create replication policy ' + project.name + " release ID " + str(db_release.id),
        "registry_id": registry_id,
        "dest_repo_name": namespace,
        "status": 'initial'
    }
    return harbor_data


# Remove Object Key with Target
def remove_object_key_by_value(items, target=None):
    output = {}
    if items is None:
        return output
    for key in items.keys():
        m_key = str(key).strip()
        m_value = items[key]
        if isinstance(items[key], int) is not True:
            m_value = str(items[key]).strip()
        if target is None:
            output[m_key] = m_value
        elif items[key] != target:
            output[m_key] = m_value
    return output


def create_default_k8s_data(db_project, db_release, args):
    k8s_data = {
        "project": db_project.display,
        "project_id": db_project.name,
        "repo_name": db_project.name,
        "image_name": db_release.branch,
        "tag_name": db_release.tag_name,
        "namespace": args.get('namespace'),
        "image": args.get('image', {"policy": "Always"}),
        "status_id": 1
    }
    resources = remove_object_key_by_value(args.get('resources', {}), "")
    if resources != {}:
        k8s_data['resources'] = resources

    network = remove_object_key_by_value(args.get('network', {}), "")
    if network != {}:
        k8s_data['network'] = network

    environments = args.get('environments', None)
    if environments is not None:
        items = []
        for env in environments:
            items.append(env)
            item = remove_object_key_by_value(env)
            if item is not None:
                items.append(item)
        if len(items) > 0:
            k8s_data['environments'] = items
    return k8s_data


def harbor_policy_exist(target, policies):
    check_result = False
    policy_id = 0
    for policy in policies:
        if str(target) == str(policy.get('name')):
            check_result = True
            policy_id = policy.get('id')
            break

    return check_result, policy_id


def initial_harbor_replication_image_policy(
        app
):
    harbor_info = json.loads(app.harbor_info)
    if 'project' in harbor_info:
        harbor_info.pop('project')
    if 'status' in harbor_info:
        harbor_info.pop('status')

    query_data = {'name': harbor_info.get('policy_name')}
    check, policy_id = harbor_policy_exist(
        harbor_info.get('policy_name'),
        harbor.hb_get_replication_policies(args=query_data)
    )
    if check is False:
        policy_id = harbor.hb_create_replication_policy(harbor_info)
    else:
        harbor.hb_put_replication_policy(harbor_info, policy_id)
    return policy_id


def execute_replication_policy(policy_id):
    return harbor.hb_execute_replication_policy(policy_id)


def get_replication_executions(policy_id):
    return harbor.hb_get_replication_executions(policy_id)


def get_replication_execution_task(policy_id):
    return harbor.hb_get_replication_execution_task(policy_id)


def check_replication_policy(policy_id):
    polices = harbor.hb_get_replication_policy()
    check = False
    for policy in polices:
        if policy.get('id') == policy_id:
            check = True
            break
    return check


def get_replication_policy(policy_id):
    return harbor.hb_get_replication_policy(policy_id)


def delete_replication_policy(policy_id):
    return harbor.hb_delete_replication_policy(policy_id)


def check_image_replication_status(task):
    output = False
    if task.get("status") == "Succeed":
        output = True
    return output


def execute_image_replication(app, restart=False):
    task_info = None
    output = create_replication_policy(app)
    execution_info = check_execute_replication_policy(output.get('policy_id'), restart)
    output.update(execution_info)
    if execution_info.get('status_id') == 2:
        task_info = check_replication_execution_task(execution_info.get('execution_id'))
    if task_info is not None:
        output.update(task_info)
    return output


def create_replication_policy(app):
    policy_id = initial_harbor_replication_image_policy(app)
    policy = get_replication_policy(policy_id)
    return {
        'policy': policy,
        'policy_id': policy_id
    }


def check_execute_replication_policy(policy_id, restart=False):
    executions = get_replication_executions(policy_id)
    output = {}
    if len(executions) == 0 or restart is True:
        image_uri = execute_replication_policy(policy_id)
        executions = get_replication_executions(policy_id)
        output = {
            "image_uri": image_uri,
        }
    execution = executions[0]
    output.update(
        {
            "executions": executions,
            "execution_id": executions[0]['id'],
            'status_id': 2
        }
    )
    if execution.get('total') == 0 and execution.get('status') == "Succeed":
        output['status'] = 'Error'
        output['error'] = 'no resource need to be replicated'
        output['status_id'] = 3001
    return output


def check_replication_execution_task(execution_id):
    output = None
    tasks = get_replication_execution_task(execution_id)
    if len(tasks) > 0:
        output = {
            'task_id': tasks[0]['id'],
            'task': tasks,
            'status': tasks[0]['status'],
            'status_id': 2
        }
        if tasks[0]['status'] == "Succeed":
            output['status_id'] = 3
    return output


def check_image_replication(app):
    output = False
    harbor_info = json.loads(app.harbor_info)
    tasks = []
    if harbor_info.get('execution', None) is None:
        execute_replication_policy(harbor_info.get('policy_id'))
    # Restart Image Replication task
    if len(harbor_info.get('task', [])) == 0:
        execute_replication_policy(harbor_info.get('policy_id'))
        return tasks, output
    else:
        tasks = get_replication_execution_task(harbor_info.get('execution_id'))

    if len(tasks) == 0:
        return tasks, False
    harbor_info['task'] = tasks
    task_id = harbor_info.get('task_id', None)
    if task_id is None and len(tasks) != 0:
        output = check_image_replication_status(tasks[-1])
    else:
        for task in tasks:
            if task.get('id') == harbor_info.get('task_id'):
                output = check_image_replication_status(task)
                break
    return tasks, output


def create_registry_data(server_name, user_name, password):
    pay_load = {
        "auths": {
            server_name: {
                "Username": user_name,
                "Password": password
            }
        }
    }
    return {
        ".dockerconfigjson": base64.b64encode(
            json.dumps(pay_load).encode()
        ).decode()
    }


def create_registry_secret_object(secret_name, data):
    return k8s_client.V1Secret(
        api_version="v1",
        data=data,
        kind="Secret",
        metadata=k8s_client.V1ObjectMeta(name=secret_name),
        type="kubernetes.io/dockerconfigjson"
    )


def create_secret_object(secret_name, secret_dict):
    body = k8s_client.V1Secret(
        api_version='v1',
        kind='Secret',
        metadata=k8s_client.V1ObjectMeta(
            name=secret_name,
        ),
        data=secret_dict
    )
    return body


def create_configmap_object(configmap_name, configmap_dict):
    body = k8s_client.V1ConfigMap(
        metadata=k8s_client.V1ObjectMeta(
            name=configmap_name,
        ),
        data=configmap_dict
    )
    return body


def create_service_object(app_name, service_name, network):
    return k8s_client.V1Service(
        api_version="v1",
        kind="Service",
        metadata=k8s_client.V1ObjectMeta(
            name=service_name
        ),
        spec=k8s_client.V1ServiceSpec(
            type=network.get('type'),
            selector={"app": app_name},
            ports=[k8s_client.V1ServicePort(
                protocol=network.get('protocol'),
                port=network.get('port')
            )]
        )
    )


def init_resource_requirements(resources):
    if resources is None:
        return k8s_client.V1ResourceRequirements()
    else:
        return k8s_client.V1ResourceRequirements(
            limits={
                'cpu': resources.get('cpu'),
                'memory': resources.get('memory')
            }
        )


def create_deployment_object(
        app_name,
        deployment_name,
        image_uri,
        port,
        registry_secret_name,
        resource=None,
        image=None
):
    # Configured Pod template container
    default_image_policy = 'Always'
    if image is not None and image.get('policy', None) is not None:
        default_image_policy = image.get('policy', None)
    container = k8s_client.V1Container(
        name=app_name,
        image=image_uri,
        ports=[k8s_client.V1ContainerPort(container_port=port)],
        resources=init_resource_requirements(resource),
        image_pull_policy=default_image_policy
    )
    # Create and configure a spec section
    template = k8s_client.V1PodTemplateSpec(
        metadata=k8s_client.V1ObjectMeta(labels={"app": app_name}),
        spec=k8s_client.V1PodSpec(
            containers=[container],
            image_pull_secrets=[
                k8s_client.V1LocalObjectReference(name=registry_secret_name)]
        )
    )
    num_replicas = 1
    if resource is not None and resource.get('replicas', None) is not None:
        num_replicas = resource.get('replicas', None)
    # Create the specification of deployment
    spec = k8s_client.V1DeploymentSpec(
        replicas=num_replicas,
        template=template,
        selector={'matchLabels': {'app': app_name}})
    # Instantiate the deployment object
    deployment = k8s_client.V1Deployment(
        api_version="apps/v1",
        kind="Deployment",
        metadata=k8s_client.V1ObjectMeta(name=deployment_name),
        spec=spec)
    return deployment


def create_ingress_object(ingress_name, domain, service_name, port, path):
    spec = k8s_client.NetworkingV1beta1IngressSpec(
        rules=[k8s_client.NetworkingV1beta1IngressRule(
            host=domain,
            http=k8s_client.NetworkingV1beta1HTTPIngressRuleValue(
                paths=[k8s_client.NetworkingV1beta1HTTPIngressPath(
                    path=path,
                    backend=k8s_client.NetworkingV1beta1IngressBackend(
                        service_name=service_name,
                        service_port=port
                    )
                )]
            )
        )])
    metadata = k8s_client.V1ObjectMeta(
        name=ingress_name,
        annotations={
            "nginx.ingress.kubernetes.io/rewrite-target": "/",
        }
    )
    body = k8s_client.NetworkingV1beta1Ingress(
        # NetworkingV1beta1Api
        api_version="networking.k8s.io/v1beta1",
        kind="Ingress",
        metadata=metadata,
        spec=spec
    )
    return body


def create_namespace_object(namespace):
    return k8s_client.V1Namespace(
        metadata=k8s_client.V1ObjectMeta(name=namespace))


class DeployK8sClient:
    def __init__(self, server_name):
        print(get_cluster_config_path(server_name))
        self.client = kubernetesClient.ApiK8sClient(
            configuration_file=get_cluster_config_path(server_name))

    def get_api_resources(self):
        return self.client.get_api_resources()

    # namespace
    def read_namespace(self, namespace):
        if self.check_namespace(namespace) is True:
            return self.client.read_namespace(namespace)
        else:
            return {}

    def create_namespace(self, namespace, body):
        check = k8s_resource_exist(
            namespace,
            self.client.list_namespace()
        )
        if check is False:
            self.client.create_namespace(
                body
            )

    def delete_namespace(self, namespace):
        check = k8s_resource_exist(
            namespace,
            self.client.list_namespace()
        )
        if check is True:
            self.client.delete_namespace(namespace)

    def check_namespace(self, namespace):
        return k8s_resource_exist(
            namespace,
            self.client.list_namespace()
        )

    def execute_namespace_secret(self, name, namespace, body):
        if self.check_namespace_secret(name, namespace) is False:
            return self.client.create_namespaced_secret(namespace, body)
        else:
            return self.client.patch_namespaced_secret(name, namespace, body)

    def check_namespace_secret(self, name, namespace):
        return k8s_resource_exist(
            name,
            self.client.list_namespaced_secret(namespace)
        )

    def execute_namespace_service(self, name, namespace, body):
        if self.check_namespace_service(name, namespace) is False:
            return self.client.create_namespaced_service(namespace, body)
        else:
            return self.client.patch_namespaced_service(name, namespace, body)

    def check_namespace_service(self, name, namespace):
        return k8s_resource_exist(
            name,
            self.client.list_namespaced_service(namespace)
        )

    def execute_namespace_ingress(self, name, namespace, body):
        if self.check_namespace_ingress(name, namespace) is False:
            return self.client.create_namespaced_ingress(namespace, body)
        else:
            return self.client.patch_namespaced_ingress(name, namespace, body)

    def check_namespace_ingress(self, name, namespace):
        return k8s_resource_exist(
            name,
            self.client.list_namespaced_ingress(namespace)
        )

    def execute_namespace_deployment(self, name, namespace, body):
        if self.check_namespace_deployment(name, namespace) is False:
            return self.client.create_namespaced_deployment(namespace, body)
        else:
            return self.client.patch_namespaced_deployment(name, namespace, body)

    def check_namespace_deployment(self, name, namespace):
        return k8s_resource_exist(
            name,
            self.client.list_namespaced_deployment(namespace)
        )

    def execute_namespace_configmap(self, name, namespace, body):
        if self.check_namespace_configmap(name, namespace) is False:
            return self.client.create_namespaced_config_map(namespace, body)
        else:
            return self.client.patch_namespaced_config_map(name, namespace, body)

    def check_namespace_configmap(self, name, namespace):
        return k8s_resource_exist(
            name,
            self.client.list_namespaced_config_map(namespace)
        )


class DeployNamespace:
    def __init__(self, namespace):
        self.namespace = namespace

    def namespace_body(self):
        return create_namespace_object(self.namespace)


class DeployConfigMap:

    def __init__(self, app, project):
        self.app = app
        self.project = project
        self.configmap_name = None
        self.configmap_dict = None
        self.set_configmap_data()

    def get_configmap_info(self):
        return {
            'configmap-name': self.configmap_name
        }

    def set_configmap_data(self):
        environments = json.loads(self.app.k8s_yaml).get('environments', None)
        self.configmap_dict = get_environments_value(environments, 'configmap')
        self.configmap_name = self.project.name + "-configmap"

    def configmap_body(self):
        return create_configmap_object(
            self.configmap_name,
            self.configmap_dict
        )


class DeploySecret:

    def __init__(self, app, project):
        self.app = app
        self.project = project
        self.secret_name = None
        self.secret_dict = None
        self.set_secret_data()

    def get_secret_info(self):
        return {
            'secret-name': self.secret_name
        }

    def set_secret_data(self):
        environments = json.loads(self.app.k8s_yaml).get('environments', None)
        self.secret_dict = get_environments_value(environments, 'secret')
        self.secret_name = self.project.name + "-secret"

    def secret_body(self):
        return create_secret_object(
            self.secret_name,
            self.secret_dict
        )


class DeployRegistrySecret:
    def __init__(self, app, registry):
        self.registry = registry
        self.app = app
        self.registry_server_url = None
        self.registry_secret_name = None
        self.set_registry_secret_info()

    def set_registry_secret_info(self):
        harbor_info = json.loads(self.app.harbor_info)
        self.registry_server_url = harbor_info.get('image_uri').split(
            '/')[0]
        self.registry_secret_name = self.registry_server_url.translate(
            str.maketrans({'.': '-', ':': '-'})) + '-harbor'

    def get_registry_secret_info(self):
        return {
            'registry_server_url': self.registry_server_url,
            'registry_secret_name': self.registry_secret_name
        }

    def registry_secret_body(self):
        return create_registry_secret_object(
            self.registry_secret_name,
            create_registry_data(self.registry_server_url, self.registry.access_key,
                                 util.base64decode(self.registry.access_secret))

        )


class DeployService:
    def __init__(self, app, project):
        self.app = app
        self.project = project
        self.k8s_info = json.loads(app.k8s_yaml)
        self.name = project.name + "-release-" + str(app.release_id)
        self.service_name = self.project.name + "-service"

    def get_service_info(self):
        return {
            'service_name': self.service_name,
            'port': self.k8s_info.get('network').get('port')
        }

    def service_body(self):
        return create_service_object(self.name, self.service_name,
                                     self.k8s_info.get('network'))


class DeployIngress:
    def __init__(self, app, project):
        self.app = app
        self.k8s_info = json.loads(app.k8s_yaml)
        self.service_name = project.name + "-service"
        self.ingress_name = project.name + "-ingress"

    def get_ingress_info(self):
        return {
            'ingress_name': self.ingress_name,
            'domain': self.k8s_info.get('network').get('domain'),
            'port': self.k8s_info.get('network').get('port'),
            'path': self.k8s_info.get('network').get('path'),
        }

    def ingress_body(self):
        return create_ingress_object(
            self.ingress_name,
            self.k8s_info.get('network').get('domain'),
            self.service_name,
            self.k8s_info.get('network').get('port'),
            self.k8s_info.get('network').get('path')
        )


class DeployDeployment:
    def __init__(self, app, project, service_info, registry_secret_info):
        self.app = app
        self.namespace = self.app.namespace
        self.name = project.name + "-release-" + str(app.release_id)
        self.harbor_info = json.loads(app.harbor_info)
        self.k8s_info = json.loads(app.k8s_yaml)
        self.deployment_name = project.name + "-dep"
        self.service_info = service_info
        self.registry_secret_info = registry_secret_info

    def get_deployment_info(self):
        return {
            'deployment_name': self.deployment_name
        }

    def deployment_body(self):
        return create_deployment_object(
            self.name,
            self.deployment_name,
            self.harbor_info.get('image_uri'),
            self.service_info.get('port'),
            self.registry_secret_info.get('registry_secret_name'),
            self.k8s_info.get('resources', {}),
            self.k8s_info.get('image')
        )


class K8sDeployment:
    def __init__(self, app):
        self.app = app
        self.cluster = model.Cluster.query.filter_by(id=app.cluster_id).first()
        self.project = model.Project.query.filter_by(id=app.project_id).first()
        self.registry = model.Registries.query.filter_by(registries_id=app.registry_id).first()
        self.k8s_client = DeployK8sClient(self.cluster.name)
        self.namespace = None
        self.registry_secret = None
        self.service = None
        self.ingress = None
        self.deployment = None
        self.configmap = None
        self.secret = None
        self.deployment_info = {}

    def check_namespace(self):
        self.namespace = DeployNamespace(self.app.namespace)
        self.k8s_client.create_namespace(self.app.namespace, self.namespace.namespace_body())

    def check_registry_secret(self):
        if self.registry_secret is None:
            self.registry_secret = DeployRegistrySecret(self.app, self.registry)

    def execute_registry_secret(self):
        self.check_registry_secret()
        self.k8s_client.execute_namespace_secret(
            self.registry_secret.registry_secret_name,
            self.app.namespace,
            self.registry_secret.registry_secret_body()
        )
        self.deployment_info['registry_secret'] = self.registry_secret.get_registry_secret_info()

    def check_service(self):
        if self.service is None:
            self.service = DeployService(self.app, self.project)

    def execute_service(self):
        self.check_service()
        self.k8s_client.execute_namespace_service(
            self.service.service_name,
            self.app.namespace,
            self.service.service_body()
        )
        self.deployment_info['service'] = self.service.get_service_info()

    def check_ingress(self):
        if self.ingress is None:
            self.ingress = DeployIngress(self.app, self.project)

    def execute_ingress(self):
        self.check_ingress()
        self.k8s_client.execute_namespace_ingress(
            self.ingress.ingress_name,
            self.app.namespace,
            self.ingress.ingress_body()
        )
        self.deployment_info['ingress'] = self.ingress.get_ingress_info()

    def check_deployment(self):
        if self.deployment is None:
            self.check_service()
            self.check_registry_secret()
            self.deployment = DeployDeployment(self.app,
                                               self.project,
                                               self.service.get_service_info(),
                                               self.registry_secret.get_registry_secret_info()
                                               )

    def execute_deployment(self):
        self.check_deployment()
        self.k8s_client.execute_namespace_deployment(
            self.deployment.deployment_name,
            self.app.namespace,
            self.deployment.deployment_body()
        )
        self.deployment_info['deployment'] = self.deployment.get_deployment_info()

    def check_configmap(self):
        if self.configmap is None:
            self.configmap = DeployConfigMap(self.app, self.project)

    def execute_configmap(self):
        self.check_configmap()
        if self.configmap.configmap_dict != {}:
            self.k8s_client.execute_namespace_configmap(
                self.configmap.configmap_name,
                self.app.namespace,
                self.configmap.configmap_body()
            )
            self.deployment_info['configmap'] = self.configmap.get_configmap_info()
            self.deployment_info['status_id'] = 4

    def check_secret(self):
        if self.secret is None:
            self.secret = DeploySecret(self.app, self.project)

    def execute_secret(self):
        self.check_secret()
        if self.secret.secret_dict != {}:
            self.k8s_client.execute_namespace_secret(
                self.secret.secret_name,
                self.app.namespace,
                self.secret.secret_body()
            )
            self.deployment_info['secret'] = self.secret.get_secret_info()

    def get_deployment_information(self):
        return self.deployment_info


def execute_k8s_deployment(app):
    k8s_deployment = K8sDeployment(app)
    k8s_deployment.check_namespace()
    k8s_deployment.execute_registry_secret()
    k8s_deployment.execute_service()
    k8s_info = json.loads(app.k8s_yaml)
    if k8s_info.get('network').get('domain', None) is not None:
        k8s_deployment.execute_ingress()
    if k8s_info.get('environments', None) is not None:
        k8s_deployment.execute_configmap()
        k8s_deployment.execute_secret()
    k8s_deployment.execute_deployment()
    return k8s_deployment.get_deployment_information()


# check Deployment status
def check_k8s_deployment(app, deployed=True):
    deployed_status = []
    deploy_object = json.loads(app.k8s_yaml)
    cluster = model.Cluster.query.filter_by(id=app.cluster_id).first()
    deploy_k8s_client = DeployK8sClient(cluster.name)

    if deploy_object.get("deployment") is not None:
        deployed_status.append(deploy_k8s_client.check_namespace_deployment(
            deploy_object.get("deployment").get("deployment_name"),
            app.namespace
        ))

    if deploy_object.get('ingress') is not None:
        deployed_status.append(deploy_k8s_client.check_namespace_ingress(
            deploy_object.get('ingress').get('ingress_name'),
            app.namespace
        ))

    if deploy_object.get('service') is not None:
        deployed_status.append(deploy_k8s_client.check_namespace_service(
            deploy_object.get('service').get('service_name'),
            app.namespace
        ))
    if deploy_object.get('registry_secret') is not None:
        deployed_status.append(deploy_k8s_client.check_namespace_secret(
            deploy_object.get('registry_secret').get('registry_secret_name'),
            app.namespace
        ))

    return deployed_status.count(deployed) == len(deployed_status)


def check_application_restart(app):
    if app.restart_number is None:
        app.restart_number = 1
    else:
        app.restart_number = app.restart_number + 1
    app.restarted_at = str(datetime.utcnow())
    db.session.commit()


def check_application_status(app):
    output = {}
    if app is None:
        return output
    application_id = app.id
    check_application_restart(app)
    app = model.Application.query.filter_by(id=application_id).first()
    # Check Harbor Replication execution
    if app.status_id == 1 or app.status_id == 2:
        output = execute_image_replication(app)
        harbor_info = json.loads(app.harbor_info)
        harbor_info.update(output)
        app.harbor_info = json.dumps(harbor_info)
        app.status_id = harbor_info.get('status_id')
        app.restart_number = 1
        app.restarted_at = str(datetime.utcnow())
        db.session.commit()
    # Restart Execution Replication
    elif app.status_id == 11:
        harbor_info = json.loads(app.harbor_info)
        output = execute_image_replication(app, True)
        harbor_info.update(output)
        app.status_id = harbor_info.get('status_id')
        app.harbor_info = json.dumps(harbor_info)
        if harbor_info.get('status_id') == 3:
            app.restart_number = 1
            app.restarted_at = str(datetime.utcnow())
        db.session.commit()
    elif app.status_id == 3:
        k8s_yaml = json.loads(app.k8s_yaml)
        output = execute_k8s_deployment(app)
        k8s_yaml.update(output)
        app.status_id = 4
        app.k8s_yaml = json.dumps(k8s_yaml)
        app.restart_number = 1
        app.restarted_at = str(datetime.utcnow())
        db.session.commit()
    elif app.status_id == 4:
        k8s_yaml = json.loads(app.k8s_yaml)
        k8s_yaml['deploy_finish'] = check_k8s_deployment(app)
        if k8s_yaml['deploy_finish'] is True:
            k8s_yaml['status_id'] = 5
            app.status_id = 5
            app.restart_number = 1
            app.restarted_at = str(datetime.utcnow())
        app.k8s_yaml = json.dumps(k8s_yaml)
        db.session.commit()
    elif app.status_id == 9:
        finished = check_k8s_deployment(app, False)
        if finished is False:
            app.status_id = 10
            db.session.commit()

    return {'id': app.id, 'status': APPLICATION_STATUS.get(app.status_id, DEFAULT_APPLICATION_STATUS), 'output': output,
            'database': row_to_dict(app)}


def check_application_exists(project_id, namespace):
    return model.Application.query. \
        filter(model.Application.namespace == namespace, model.Application.project_id == project_id). \
        first()


def k8s_resource_exist(target, response):
    check_result = False
    for i in response.items:
        if str(target) == str(i.metadata.name):
            # Start
            check_result = True
            # if str(i.status.phase) == "Active":
            #     check_result = True
            # elif str(i.status.phase) == "Terminating":
            #     check_result = True
    return check_result


def get_clusters_name(cluster_id, info=None):
    if info is None:
        info = {}
    cluster = model.Cluster.query.filter_by(id=cluster_id).first()
    info[str(cluster_id)] = cluster.name
    return info


def get_application_information(application, cluster_info=None):
    # output = row_to_dict(application)
    if application is None:
        return []
    output = row_to_dict(application)
    output['status'] = APPLICATION_STATUS.get(application.status_id, DEFAULT_APPLICATION_STATUS)
    output.pop('k8s_yaml')
    output.pop('harbor_info')
    if application.harbor_info is None or application.k8s_yaml is None:
        return output
    harbor_info = json.loads(application.harbor_info)
    k8s_yaml = json.loads(application.k8s_yaml)
    if cluster_info is None:
        cluster_info = get_clusters_name(application.cluster_id)
    elif str(application.cluster_id) not in cluster_info:
        cluster_info = get_clusters_name(application.cluster_id, cluster_info)
    output['cluster'] = {}
    output['cluster']['id'] = application.cluster_id
    output['cluster']['name'] = cluster_info[str(application.cluster_id)]
    output['registry'] = {}
    output['registry']['id'] = application.cluster_id
    output['image'] = k8s_yaml.get('image')
    output['project_name'] = harbor_info.get('project')
    output['tag_name'] = harbor_info.get('tag_name')
    output['k8s_status'] = k8s_yaml.get('deploy_finish')
    output['resources'] = k8s_yaml.get('resources')
    output['network'] = k8s_yaml.get('network')
    output['environments'] = k8s_yaml.get('environments')
    return output, cluster_info


def get_applications(args=None):
    output = []
    cluster_info = {}
    app = None
    if args is None:
        app = model.Application.query.filter().all()
    elif 'application_id' in args:
        app = model.Application.query.filter_by(id=args.get('application_id')).first()
    elif 'project_id' in args:
        app = model.Application.query.filter_by(project_id=args.get('project_id')).all()

    if app is None:
        return output
    elif isinstance(app, list):
        for application in app:
            output_app, cluster_info = get_application_information(application, cluster_info)
            output.append(output_app)
    else:
        output, cluster_info = get_application_information(app, cluster_info)
    return output


def create_application(args):
    if check_application_exists(args.get('project_id'), args.get('namespace')) is not None:
        return util.respond(404, error_application_exists,
                            error=apiError.repository_id_not_found)
    cluster = model.Cluster.query.filter_by(id=args.get('cluster_id')).first()
    db_release, db_project = db.session.query(model.Release, model.Project).join(model.Project).filter(
        model.Release.id == args.get('release_id'),
        model.Release.project_id == model.Project.id
    ).one()
    harbor_info = create_default_harbor_data(
        db_project, db_release, args.get('registry_id'), args.get('namespace'))
    k8s_yaml = create_default_k8s_data(db_project, db_release, args)
    # check namespace
    deploy_k8s_client = DeployK8sClient(cluster.name)
    deploy_namespace = DeployNamespace(args.get('namespace'))
    deploy_k8s_client.create_namespace(args.get('namespace'), deploy_namespace.namespace_body())
    now = str(datetime.utcnow())
    new = model.Application(
        name=args.get('name'),
        disabled=False,
        project_id=args.get('project_id'),
        registry_id=args.get('registry_id'),
        cluster_id=args.get('cluster_id'),
        release_id=args.get('release_id'),
        namespace=args.get('namespace'),
        created_at=now,
        updated_at=now,
        status_id=1,
        harbor_info=json.dumps(harbor_info),
        k8s_yaml=json.dumps(k8s_yaml),
        status="Initial Creating",
    )
    db.session.add(new)
    db.session.commit()
    return new.id


def check_update_application_status(app, args):
    status_id = 1
    # Project Change
    if app.cluster_id != args.get('cluster_id'):
        delete_application(app.id)
        status_id = 1

    return status_id


def update_application(application_id, args):
    app = model.Application.query.filter_by(id=application_id).first()
    db_release, db_project = db.session.query(model.Release, model.Project).join(model.Project).filter(
        model.Release.id == args.get('release_id'),
        model.Release.project_id == model.Project.id
    ).one()
    for key in args.keys():
        if not hasattr(app, key):
            continue
        elif args[key] is not None:
            setattr(app, key, args[key])
    #  Change Harbor Info
    db_harbor_info = json.loads(app.harbor_info)
    delete_image_replication_policy(db_harbor_info.get('policy_id'))
    db_harbor_info.update(
        create_default_harbor_data(
            db_project, db_release, args.get('registry_id'), args.get('namespace'))
    )
    #  Change k8s Info
    db_k8s_yaml = json.loads(app.k8s_yaml)
    db_k8s_yaml.update(
        create_default_k8s_data(db_project, db_release, args)
    )
    # check namespace
    app.status_id = disable_application(
        args.get('disabled'),
        app.namespace,
        app.cluster_id
    )

    app.harbor_info = json.dumps(db_harbor_info)
    app.k8s_yaml = json.dumps(db_k8s_yaml)
    app.updated_at = (datetime.utcnow())
    db.session.commit()
    return app.id


def patch_application(application_id, args):
    app = model.Application.query.filter_by(id=application_id).first()
    release_id = args.get('release_id', app.release_id)
    db_release, db_project = db.session.query(model.Release, model.Project).join(model.Project).filter(
        model.Release.id == release_id,
        model.Project.id == model.Release.project_id
    ).one()
    for key in args.keys():
        if not hasattr(app, key):
            continue
        elif args[key] is not None:
            setattr(app, key, args[key])

    #  Delete Application
    if 'disabled' in args:
        app.status_id = disable_application(
            args.get('disabled'),
            args.get('namespace', app.namespace),
            args.get('cluster_id', app.cluster_id)
        )

    #  Change K8s Deploy
    if 'namespace' in args or \
            'image' in args or \
            'resources' in args or \
            'network' in args or \
            'environments' in args or \
            'release_id' in args:
        db_k8s_yaml = json.loads(app.k8s_yaml)
        db_k8s_yaml.update(
            create_default_k8s_data(db_project, db_release, args)
        )
        app.k8s_yaml = json.dumps(db_k8s_yaml)
    #  Change harbor_info Deploy
    if 'namespace' in args or \
            'registry_id' in args or \
            'release_id' in args:
        db_harbor_info = json.loads(app.harbor_info)
        delete_image_replication_policy(db_harbor_info.get('policy_id'))
        db_release, db_project = db.session.query(model.Release, model.Project).join(model.Project).filter(
            model.Release.id == release_id,
            model.Project.id == model.Release.project_id
        ).one()
        db_harbor_info.update(
            create_default_harbor_data(
                db_project, db_release, args.get('registry_id'), args.get('namespace'))
        )
    app.status = APPLICATION_STATUS.get(app.status_id, DEFAULT_APPLICATION_STATUS)
    app.updated_at = (datetime.utcnow())
    db.session.commit()
    return application_id


def redeploy_application(application_id):
    app = model.Application.query.filter_by(id=application_id).first()
    app.status_id = 1
    app.restart_number = 1
    app.restarted_at = str(datetime.utcnow())
    app.status = APPLICATION_STATUS.get(1, DEFAULT_APPLICATION_STATUS)
    db.session.commit()
    return app.id


def delete_application(application_id, delete_db=False):
    app = model.Application.query.filter_by(id=application_id).first()
    if app is None:
        return {}
    harbor_info = json.loads(app.harbor_info)
    delete_image_replication_policy(harbor_info.get('policy_id'))
    delete_k8s_application(app.cluster_id, app.namespace)
    if delete_db is False:
        app.status_id = 9
        app.status = APPLICATION_STATUS.get(9, DEFAULT_APPLICATION_STATUS)
        db.session.commit()
    elif delete_db is True:
        db.session.delete(app)
        db.session.commit()
    return app.id


def disable_application(disabled, namespace, cluster_id):
    if disabled is True:
        #  Delete Application
        delete_k8s_application(cluster_id, namespace)
        status_id = 32
    else:
        # Redeploy K8s
        cluster = model.Cluster.query.filter_by(id=cluster_id).first()
        deploy_k8s_client = DeployK8sClient(cluster.name)
        deploy_namespace = DeployNamespace(namespace)
        deploy_k8s_client.create_namespace(namespace, deploy_namespace.namespace_body())
        status_id = 1
    return status_id


def delete_image_replication_policy(policy_id):
    if policy_id is not None and check_replication_policy(policy_id) is True:
        delete_replication_policy(policy_id)


def delete_k8s_application(cluster_id, namespace):
    if cluster_id is not None and namespace is not None:
        cluster = model.Cluster.query.filter_by(id=cluster_id).first()
        deploy_k8s_client = DeployK8sClient(cluster.name)
        deploy_k8s_client.delete_namespace(namespace)


class Applications(Resource):
    @jwt_required
    def get(self):
        try:
            parser = reqparse.RequestParser()
            parser.add_argument('project_id', type=str)
            args = parser.parse_args()
            role_id = get_jwt_identity()['role_id']
            project_id = args.get('project_id', None)
            if role_id == 5 and project_id is None:
                role.require_admin()
                output = get_applications()
            else:
                output = get_applications(args)
            return util.success({"applications": output})
        except NoResultFound:
            return util.respond(404, error_clusters_not_found,
                                error=apiError.repository_id_not_found)

    @jwt_required
    def post(self):
        try:
            parser = reqparse.RequestParser()
            parser.add_argument('name', type=str)
            parser.add_argument('project_id', type=int)
            parser.add_argument('registry_id', type=int)
            parser.add_argument('cluster_id', type=int)
            parser.add_argument('release_id', type=int)
            parser.add_argument('namespace', type=str)
            parser.add_argument('resources', type=dict)
            parser.add_argument('network', type=dict)
            parser.add_argument('image', type=dict)
            parser.add_argument('environments', type=dict, action='append')
            parser.add_argument('disabled', type=inputs.boolean)
            args = parser.parse_args()
            if check_application_exists(args.get('project_id'), args.get('namespace')) is not None:
                return util.respond(404, error_application_exists)
            output = create_application(args)
            return util.success({"applications": {"id": output}})
        except NoResultFound:
            return util.respond(404, error_clusters_not_found,
                                error=apiError.repository_id_not_found)


class Application(Resource):
    @jwt_required
    def get(self, application_id):
        try:
            args = {
                'application_id': application_id
            }
            output = get_applications(args)
            return util.success({"application": output})
        except NoResultFound:
            return util.respond(404, error_clusters_not_found,
                                error=apiError.repository_id_not_found)

    @jwt_required
    def patch(self, application_id):
        try:
            parser = reqparse.RequestParser()
            parser.add_argument('disabled', type=inputs.boolean)
            args = parser.parse_args()
            output = patch_application(application_id, args)
            return util.success({"applications": output})
        except NoResultFound:
            return util.respond(404, error_clusters_not_found,
                                error=apiError.repository_id_not_found)

    @jwt_required
    def delete(self, application_id):
        try:
            output = delete_application(application_id, True)
            return util.success(output)
        except NoResultFound:
            return util.respond(404, error_clusters_not_found,
                                error=apiError.repository_id_not_found)

    @jwt_required
    def put(self, application_id):
        try:
            parser = reqparse.RequestParser()
            parser.add_argument('name', type=str)
            parser.add_argument('project_id', type=int)
            parser.add_argument('registry_id', type=int)
            parser.add_argument('cluster_id', type=int)
            parser.add_argument('release_id', type=int)
            parser.add_argument('namespace', type=str)
            parser.add_argument('resources', type=dict)
            parser.add_argument('network', type=dict)
            parser.add_argument('image', type=dict)
            parser.add_argument('environments', type=dict, action='append')
            parser.add_argument('disabled', type=inputs.boolean)
            args = parser.parse_args()
            output = update_application(application_id, args)
            return util.success({"applications": {"id": output}})
        except NoResultFound:
            return util.respond(404, error_clusters_not_found,
                                error=apiError.repository_id_not_found)


class RedeployApplication(Resource):
    @jwt_required
    def patch(self, application_id):
        try:
            output = redeploy_application(application_id)
            return util.success({"applications": output})
        except NoResultFound:
            return util.respond(404, error_clusters_not_found,
                                error=apiError.repository_id_not_found)


class UpdateApplication(Resource):
    @jwt_required
    def patch(self, application_id):
        try:
            app = model.Application.query.filter_by(id=application_id).first()
            if app.restart_number > DEFAULT_RESTART_NUMBER:
                return util.respond(404, error_clusters_not_found,
                                    error=apiError.repository_id_not_found)
            output = check_application_status(app)
            return util.success({"applications": output})
        except NoResultFound:
            return util.respond(404, error_clusters_not_found,
                                error=apiError.repository_id_not_found)


class ReleaseApplication(Resource):
    @jwt_required
    def get(self, release_id):
        try:
            release_file = release.ReleaseFile(release_id)
            env = release_file.get_release_env_from_file()
            return util.success({"env": env})
        except NoResultFound:
            return util.respond(404, error_clusters_not_found,
                                error=apiError.repository_id_not_found)


class Cronjob(Resource):
    @staticmethod
    def patch():
        try:
            execute_list = []
            check_list = [1, 2, 3, 4, 9]
            apps = db.session.query(model.Application).filter(model.Application.status_id.in_(check_list)).all()
            for app in apps:
                if app.restart_number < DEFAULT_RESTART_NUMBER:
                    temp = check_application_status(app)
                    execute_list.append(temp['id'])
            return util.success({"applications": execute_list})
        except NoResultFound:
            return util.respond(404, error_clusters_not_found,
                                error=apiError.repository_id_not_found)
