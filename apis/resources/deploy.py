import base64
import json
import os
from datetime import datetime, date
from pathlib import Path

import werkzeug
import yaml
from flask_jwt_extended import jwt_required, get_jwt_identity
from flask_restful import Resource, reqparse
from kubernetes import client as k8s_client
from sqlalchemy.orm.exc import NoResultFound
from werkzeug.utils import secure_filename

import config
import model
import util as util
from model import db
from resources import apiError, role
from resources import harbor, kubernetesClient

default_project_id = "-1"
error_clusters_not_found = "No Exact Cluster Found"
error_application_exists = "Application had been deployed"
DEFAULT_K8S_CONFIG_FILE = 'k8s_config'

APPLICATION_STATUS = {
    1: 'Initial',
    2: 'Start Image Replication',
    3: 'Finish Image Replication',
    4: 'Start Kubernetes Deploy ',
    5: 'Finish Kubernetes Deploy ',
    8: 'Deployment Disabled',
}


def is_json(string):
    try:
        json.loads(string)
    except ValueError:
        return False
    return True


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
        k8s_yaml = json.loads(application.k8s_yaml)
        harbor_filter = harbor_info.get('policy').get('filters')
        app['tag'] = [context['value']
                      for context in harbor_filter if context['type'] == 'tag'][0]
        image_name = [context['value']
                      for context in harbor_filter if context['type'] == 'name'][0]
        app['project_name'] = image_name[0: image_name.rfind('/')]
        app['status'] = k8s_yaml.get('deploy_finish')
        app['namespace'] = harbor_info.get('dest_repo_name')
        ret_output.append(app)
    output['application'] = ret_output
    return output


def get_clusters(cluster_id=None):
    output = []
    if cluster_id is not None:
        return get_cluster_application_information(model.Cluster.query.filter_by(id=cluster_id).first())
    for cluster in model.Cluster.query.filter(model.Cluster.disabled.isnot(True)).all():
        output.append(get_cluster_application_information(cluster))
    return output


def create_cluster(args, server_name, user_id):
    cluster_path = check_directory_exists(server_name)
    file = args.get('k8s_config_file')
    filename = secure_filename(DEFAULT_K8S_CONFIG_FILE)
    file.save(os.path.join(cluster_path, filename))
    file.seek(0)
    content = file.read()
    content = str(content, 'utf-8')
    k8s_json = yaml.safe_load(content)
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
        setattr(cluster, key, args[key])
    cluster.update_at = str(datetime.utcnow())
    model.db.session.commit()
    cluster_path = check_directory_exists(args.get('name').strip())
    file = args.get('k8s_config_file')
    filename = secure_filename(DEFAULT_K8S_CONFIG_FILE)
    file.save(os.path.join(cluster_path, filename))
    file.seek(0)
    content = file.read()
    content = str(content, 'utf-8')
    k8s_json = yaml.safe_load(content)
    cluster.name = args.get('name')
    cluster.cluster_name = k8s_json['clusters'][0]['name'],
    cluster.cluster_host = k8s_json['clusters'][0]['cluster']['server'],
    cluster.cluster_user = k8s_json['users'][0]['name']
    cluster.update_at = str(datetime.utcnow())
    cluster.disabled = args.get('disabled')
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
            # k8s_config_file = open(get_cluster_config_path(output.get('name')))
            # parsed_yaml_file = yaml.load(
            #     k8s_config_file, Loader=yaml.FullLoader)
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
    ret_output = []
    for application in registry.application:
        if application is None or application.harbor_info is None:
            continue
        app = {}
        harbor_info = json.loads(application.harbor_info)
        harbor_filter = harbor_info.get('policy').get('filters')
        app['tag'] = [context['value']
                      for context in harbor_filter if context['type'] == 'tag'][0]
        image_name = [context['value']
                      for context in harbor_filter if context['type'] == 'name'][0]
        app['project_name'] = image_name[0: image_name.rfind('/')]
        app['status'] = harbor_info['task'][-1]['status']
        ret_output.append(app)
    output['application'] = ret_output
    return output


def get_registries(registry_id=None):
    output = []
    if registry_id is not None:
        return get_registries_application_information(
            model.Registries.query.filter_by(registries_id=registry_id).first())
    for cluster in model.Registries.query.filter(model.Registries.disabled.isnot(True)).all():
        output.append(get_registries_application_information(cluster))

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


def create_default_harbor_data(project, release, registry_id, namespace):
    harbor_data = {
        "project": project.name,
        "policy_name": project.name + "-release-" + str(release.id) + '-at-' + namespace,
        "repo_name": project.name,
        "image_name": release.branch,
        "tag_name": release.tag_name,
        "description": 'Automate create replication policy ' + project.name + " release ID " + str(release.id),
        "registry_id": registry_id,
        "dest_repo_name": namespace,
        "status": 'initial'
    }
    return harbor_data


def create_default_k8s_data(args):
    k8s_data = {
        "resources": args.get('resources'),
        "network": args.get('network'),
        "environments": args.get('environments'),
    }
    return k8s_data


def initial_harbor_replication_image_policy(
        app
):
    harbor_info = json.loads(app.harbor_info)
    harbor_info.pop('project')
    harbor_info.pop('status')
    policy_id = harbor.hb_create_replication_policy(harbor_info)
    return policy_id


def execute_replication_policy(policy_id):
    return harbor.hb_execute_replication_policy(policy_id)


def get_replication_executions(policy_id):
    return harbor.hb_get_replication_executions(policy_id)


def get_replication_execution_task(policy_id):
    return harbor.hb_get_replication_execution_task(policy_id)


def get_replication_policy(policy_id):
    return harbor.hb_get_replication_policy(policy_id)


def delete_replication_policy(policy_id):
    return harbor.hb_delete_replication_policy(policy_id)


def execute_image_replication(app):
    policy_id = initial_harbor_replication_image_policy(app)
    policy = get_replication_policy(policy_id)
    image_uri = execute_replication_policy(policy_id)
    executions = get_replication_executions(policy_id)
    execution_id = executions[-1]['id']
    tasks = get_replication_execution_task(execution_id)
    task_id = tasks[-1]['id']

    return {
        "policy_id": policy_id,
        "policy": policy,
        "image_uri": image_uri,
        "execution_id": execution_id,
        "task_id": task_id,
        "task": tasks
    }


def check_image_replication_status(task):
    output = False
    if task.get("status") == "Succeed":
        output = True
    return output


def check_image_replication(app):
    output = False
    harbor_info = json.loads(app.harbor_info)
    tasks = get_replication_execution_task(harbor_info.get('execution_id'))
    harbor_info['task'] = tasks
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


def create_registry_secret_object(data, secret_name):
    return k8s_client.V1Secret(
        api_version="v1",
        data=data,
        kind="Secret",
        metadata=k8s_client.V1ObjectMeta(name=secret_name),
        type="kubernetes.io/dockerconfigjson"
    )


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
            requests={
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
    # Configureate Pod template container
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
    # Create and configurate a spec section
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


class DepolyK8sClient:
    def __init__(self, cluster):
        self.client = kubernetesClient.ApiK8sClient(
            configuration_file=get_cluster_config_path(cluster.name))

    def create_namespace(self, namespace):
        check = k8s_resource_exist(
            namespace,
            self.client.list_namespace()
        )
        if check is False:
            self.client.create_namespace(namespace)

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

    def create_namespace_secret(self, name, namespace, body):
        check = k8s_resource_exist(
            name,
            self.client.list_namespaced_secret(namespace)
        )
        if check is False:
            self.client.create_namespaced_secret(namespace, body)

    def check_namespace_secret(self, name, namespace):
        return k8s_resource_exist(
            name,
            self.client.list_namespaced_secret(namespace)
        )

    def create_namespace_service(self, name, namespace, body):
        check = k8s_resource_exist(
            name,
            self.client.list_namespaced_service(namespace)
        )
        if check is False:
            return self.client.create_namespaced_service(namespace, body)

    def check_namespace_service(self, name, namespace):
        return k8s_resource_exist(
            name,
            self.client.list_namespaced_service(namespace)
        )

    def create_namespace_ingress(self, name, namespace, body):
        check = k8s_resource_exist(
            name,
            self.client.list_namespaced_ingress(namespace)
        )
        if check is False:
            self.client.create_namespaced_ingress(namespace, body)

    def check_namespace_ingress(self, name, namespace):
        return k8s_resource_exist(
            name,
            self.client.list_namespaced_ingress(namespace)
        )

    def create_namespace_deployment(self, name, namespace, body):
        check = k8s_resource_exist(
            name,
            self.client.list_namespaced_deployment(namespace)
        )
        if check is False:
            self.client.create_namespaced_deployment(namespace, body)

    def check_namespace_deployment(self, name, namespace):
        return k8s_resource_exist(
            name,
            self.client.list_namespaced_deployment(namespace)
        )


class DeployNamespace:
    def __init__(self, namespace):
        self.namespace = namespace

    def namespace_body(self):
        return create_namespace_object(self.namespace)


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
            create_registry_data(self.registry_server_url, self.registry.access_key,
                                 util.base64decode(self.registry.access_secret)),
            self.registry_secret_name
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
            self.k8s_info.get('resources')
        )


def execute_k8s_deployment(app):
    output = {}
    cluster = model.Cluster.query.filter_by(id=app.cluster_id).first()
    project = model.Project.query.filter_by(id=app.project_id).first()
    deploy_k8s_client = DepolyK8sClient(cluster)
    registry = model.Registries.query.filter_by(registries_id=app.registry_id).first()
    deploy_registry_secret = DeployRegistrySecret(app, registry)
    # Create Docker Pull Registry
    deploy_k8s_client.create_namespace_secret(
        deploy_registry_secret.registry_secret_name,
        app.namespace,
        deploy_registry_secret.registry_secret_body()
    )
    output['registry_secret'] = deploy_registry_secret.get_registry_secret_info()
    # Create Deployment Service
    deploy_service = DeployService(app, project)
    deploy_k8s_client.create_namespace_service(
        deploy_service.service_name,
        app.namespace,
        deploy_service.service_body()
    )
    output['service'] = deploy_service.get_service_info()

    # Create Deployment Ingress
    k8s_info = json.loads(app.k8s_yaml)
    if k8s_info.get('network').get('domain', None) is not None:
        deploy_ingress = DeployIngress(app, project)
        deploy_k8s_client.create_namespace_ingress(
            deploy_ingress.ingress_name,
            app.namespace,
            deploy_ingress.ingress_body()
        )
        output['ingress'] = deploy_ingress.get_ingress_info()

    # Create Secret and Configmap

    # Create Deployment
    deploy_deployment = DeployDeployment(app,
                                         project,
                                         deploy_service.get_service_info(),
                                         deploy_registry_secret.get_registry_secret_info()
                                         )

    deploy_k8s_client.create_namespace_deployment(
        deploy_deployment.deployment_name,
        app.namespace,
        deploy_deployment.deployment_body()
    )
    output['deployment'] = deploy_deployment.get_deployment_info()
    return output


# check Deployment exists
def check_k8s_deployment(app):
    deploy_finish = True

    deploy_object = json.loads(app.k8s_yaml)
    cluster = model.Cluster.query.filter_by(id=app.cluster_id).first()
    deploy_k8s_client = DepolyK8sClient(cluster)
    if deploy_object.get("deployment") is not None:
        deploy_finish = deploy_k8s_client.check_namespace_deployment(
            deploy_object.get("deployment").get("deployment_name"),
            app.namespace
        )

    if deploy_object.get('ingress') is not None:
        deploy_finish = deploy_k8s_client.check_namespace_ingress(
            deploy_object.get('ingress').get('ingress_name'),
            app.namespace
        )

    if deploy_object.get('service') is not None:
        deploy_finish = deploy_k8s_client.check_namespace_service(
            deploy_object.get('service').get('service_name'),
            app.namespace
        )
    if deploy_object.get('registry_secret') is not None:
        deploy_finish = deploy_k8s_client.check_namespace_secret(
            deploy_object.get('registry_secret').get('registry_secret_name'),
            app.namespace
        )
    return deploy_finish


def check_application_status(application_id):
    output = {}
    app = model.Application.query.filter_by(id=application_id).one()
    # Initial Harbor Replication execution
    if app.status_id == 1:
        output = execute_image_replication(app)
        harbor_info = json.loads(app.harbor_info)
        harbor_info.update(output)
        app.harbor_info = json.dumps(harbor_info)
        app.status_id = 2
        db.session.commit()
    # Check Execution Replication
    elif app.status_id == 2:
        harbor_info = json.loads(app.harbor_info)
        task, status = check_image_replication(app)
        harbor_info['task'] = task
        if status is True:
            harbor_info['status'] = 'Success'
            app.status_id = 3
        app.harbor_info = json.dumps(harbor_info)
        db.session.commit()
    elif app.status_id == 3:
        k8s_yaml = json.loads(app.k8s_yaml)
        output = execute_k8s_deployment(app)
        k8s_yaml.update(output)
        app.status_id = 4
        app.k8s_yaml = json.dumps(k8s_yaml)
        db.session.commit()
    elif app.status_id == 4:
        k8s_yaml = json.loads(app.k8s_yaml)
        k8s_yaml['deploy_finish'] = check_k8s_deployment(app)
        if k8s_yaml['deploy_finish'] is True:
            app.status_id = 5
        app.k8s_yaml = json.dumps(k8s_yaml)
        db.session.commit()
    elif app.status_id == 8:
        output = check_k8s_deployment(app)

    return {'output': output, 'database': row_to_dict(app)}


def check_application_exists(project_id, namespace):
    return model.Application.query. \
        filter(model.Application.namespace == namespace, model.Application.project_id == project_id). \
        first()


def k8s_resource_exist(target, response):
    check_result = False
    for i in response.items:
        if str(target) == str(i.metadata.name):
            check_result = True
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

    output = {
        'id': application.id,
        'application_name': application.name,
        'created_at': str(application.created_at),
        'status_id': application.status_id,
        'status_str': APPLICATION_STATUS[application.status_id]
    }
    if application.harbor_info is None or application.k8s_yaml is None:
        return output
    harbor_info = json.loads(application.harbor_info)
    k8s_yaml = json.loads(application.k8s_yaml)
    if cluster_info is None:
        cluster_info = get_clusters_name(application.cluster_id)
    elif str(application.cluster_id) not in cluster_info:
        cluster_info = get_clusters_name(application.cluster_id, cluster_info)

    output['cluster_name'] = cluster_info[str(application.cluster_id)]
    output['project_name'] = harbor_info.get('project')
    output['tag_name'] = harbor_info.get('tag_name')
    output['k8s_status'] = k8s_yaml.get('deploy_finish')
    output['namespace'] = harbor_info.get('dest_repo_name')
    return output, cluster_info


def get_applications(args):
    output = []
    if 'application_id' in args:
        applications = model.Application.query.filter_by(id=args.get('application_id')).all()
    elif 'project_id' in args:
        applications = model.Application.query.filter_by(project_id=args.get('project_id')).all()
    else:
        applications = model.Application.query.filter(model.Application.disabled.isnot(True)).all()
    cluster_info = {}
    for application in applications:
        output_app, cluster_info = get_application_information(application, cluster_info)
        output.append(output_app)
    return output


def create_application(args):
    if check_application_exists(args.get('project_id'), args.get('namespace')) is not None:
        return util.respond(404, error_application_exists,
                            error=apiError.repository_id_not_found)
    cluster = model.Cluster.query.filter_by(id=args.get('cluster_id')).first()
    release, project = db.session.query(model.Release, model.Project).join(model.Project).filter(
        model.Release.id == args.get('release_id'),
        model.Release.project_id == model.Project.id
    ).one()
    harbor_data = create_default_harbor_data(
        project, release, args.get('registry_id'), args.get('namespace'))
    k8s_data = create_default_k8s_data(
        args)
    # check namespace
    deploy_k8s_client = DepolyK8sClient(cluster)
    deploy_namespace = DeployNamespace(args.get('namespace'))
    deploy_k8s_client.create_namespace(deploy_namespace.namespace_body())
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
        harbor_info=json.dumps(harbor_data),
        k8s_yaml=json.dumps(k8s_data),
        status="Initial Creating",
    )
    db.session.add(new)
    db.session.commit()
    return new.id


def delete_application(application_id, delete_option=False):
    app = model.Application.query.filter_by(id=application_id).first()
    harbor_info = json.loads(app.harbor_info)
    delete_replication_policy(harbor_info.get('policy_id'))
    cluster = model.Cluster.query.filter_by(id=app.cluster_id).first()
    deploy_k8s_client = DepolyK8sClient(cluster)
    deploy_k8s_client.delete_namespace(app.namespace)
    if delete_option is False:
        app.status_id = 8
        db.session.commit()
    elif delete_option is True:
        db.session.delete(app)
        db.session.commit()
    return app.id


class RedeployApplication(Resource):
    @jwt_required
    def patch(self, application_id):
        try:

            return util.success({"applications": application_id})
        except NoResultFound:
            return util.respond(404, error_clusters_not_found,
                                error=apiError.repository_id_not_found)


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
            parser.add_argument('environments', type=dict)
            parser.add_argument('disabled', type=bool)
            args = parser.parse_args()
            if check_application_exists(args.get('project_id'), args.get('namespace')) is not None:
                return util.respond(404)
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
            output = check_application_status(application_id)
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
