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
DEFAULT_K8S_CONFIG_FILE = 'k8s_config'


def is_json(myjson):
    try:
        json.loads(myjson)
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


def get_clusters(cluster_id=None):
    output = []
    if cluster_id is not None:
        return row_to_dict(model.Cluster.query.filter_by(id=cluster_id).first())
    clusters = model.Cluster.query.all()
    for cluster in clusters:
        output.append(row_to_dict(cluster))
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
            output = {}
            user_id = get_jwt_identity()["user_id"]
            role.require_admin()
            parser = reqparse.RequestParser()
            parser.add_argument('name', type=str)
            parser.add_argument(
                'k8s_config_file', type=werkzeug.datastructures.FileStorage, location='files')
            args = parser.parse_args()
            server_name = args.get('name').strip()
            if check_cluster(server_name) is None:
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


def create_application_image():
    image_uri = 1
    return image_uri


def create_default_harbor_data(project, release, registry_id, namespace):
    harbor_data = {
        "policy_name": project.name + '-' + release.branch + '-' + release.tag_name + "-" + str(datetime.utcnow()),
        "repo_name": project.name,
        "image_name": release.branch,
        "tag_name": release.tag_name,
        "description": 'Automatate create replication policy ' + project.name + " release ID" + str(release.id),
        "registry_id": registry_id,
        "dest_repo_name": namespace,
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
    policy_id = harbor.hb_create_replication_policy(
        json.loads(app.harbor_info))
    return policy_id


def execute_replication_policy(policy_id):
    return harbor.hb_execute_replication_policy(policy_id)


def get_replication_executions(policy_id):
    return harbor.hb_get_replication_executions(policy_id)


def get_replication_execution_task(policy_id):
    return harbor.hb_get_replication_execution_task(policy_id)


def get_replication_policy(policy_id):
    return harbor.hb_get_replication_policy(policy_id)


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
    for task in tasks:
        if task.get('id') == harbor_info.get('task_id'):
            output = check_image_replication_status(task)
            break
    return output


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


def create_service_object(app_name, network):
    service_name = app_name + "-service"
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


def create_deployment_object(
        app_name,
        image_uri,
        port,
        registry_secret_name
):
    # Configureate Pod template container
    container = k8s_client.V1Container(
        name=app_name,
        image=image_uri,
        ports=[k8s_client.V1ContainerPort(container_port=port)],
        resources=k8s_client.V1ResourceRequirements(
            requests={"cpu": "100m", "memory": "200Mi"},
            limits={"cpu": "500m", "memory": "500Mi"}
        ),
        image_pull_policy="Always"
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
    # Create the specification of deployment
    spec = k8s_client.V1DeploymentSpec(
        replicas=3,
        template=template,
        selector={'matchLabels': {'app': app_name}})
    # Instantiate the deployment object
    deployment = k8s_client.V1Deployment(
        api_version="apps/v1",
        kind="Deployment",
        metadata=k8s_client.V1ObjectMeta(name=app_name + "-dep"),
        spec=spec)
    return deployment


class DeploymentProcess:
    def __init__(self, app, cluster, registry, project):
        k8s_file = get_cluster_config_path(cluster.name)
        self.api_k8s_client = kubernetesClient.ApiK8sClient(
            configuration_file=k8s_file)
        self.cluster = cluster
        self.registry = registry
        self.project = project
        self.app = app
        self.harbor_info = json.loads(self.app.harbor_info)
        self.k8s_info = json.loads(self.app.k8s_yaml)
        self.registry_server_url = None
        self.registry_secret_name = None
        self.registry_server_url = self.harbor_info.get('image_uri').split(
            '/')[0]
        self.registry_secret_name = self.registry_server_url.translate(
            str.maketrans({'.': '-', ':': '-'})) + '-harbor'

    def create_namespace(self):
        self.api_k8s_client.create_namespace(
            k8s_client.V1Namespace(
                metadata=k8s_client.V1ObjectMeta(name=self.app.namespace))
        )

    def create_registry_secret(self):
        secret = create_registry_secret_object(
            create_registry_data(self.registry_server_url, self.registry.access_key,
                                 util.base64decode(self.registry.access_secret)),
            self.registry_secret_name
        )
        self.api_k8s_client.create_namespaced_secret(
            self.app.namespace, secret)

    def create_service(self):
        self.api_k8s_client.create_namespaced_service(self.app.namespace,
                                                      create_service_object(self.project.name,
                                                                            self.k8s_info.get('network')))

    def create_deployment(self):
        self.api_k8s_client.create_namespaced_deployment(
            self.app.namespace,
            create_deployment_object(
                self.project.name,
                self.harbor_info.get('image_uri'),
                self.k8s_info.get('network').get('port'),
                self.registry_secret_name
            )
        )


def execute_k8s_deployment(app):
    project = model.Project.query.filter_by(id=app.project_id).one()
    registry = model.Registries.query.filter_by(
        registries_id=app.registry_id).one()
    cluster = model.Cluster.query.filter_by(
        id=app.cluster_id).one()
    deployment_process = DeploymentProcess(app, cluster, registry, project)
    deployment_process.create_namespace()
    deployment_process.create_registry_secret()
    deployment_process.create_service()
    deployment_process.create_deployment()
    harbor_info = json.loads(app.harbor_info)
    return harbor_info


def check_application_type(application_id):
    output = {}
    app = model.Application.query.filter_by(id=application_id).one()
    # Initial Harbor Replication execution
    if app.status_id == 1:
        output = execute_image_replication(app)
        app.harbor_info = json.dumps(output)
        app.status_id = 2
        db.session.commit()
    # Check Execution Replication
    elif app.status_id == 2:
        if check_image_replication(app) is True:
            app.status_id = 3
            db.session.commit()
    elif app.status_id == 3:
        output = execute_k8s_deployment(app)
    return {'temp': output, 'database': row_to_dict(app)}


def create_application(args):
    release, project = db.session.query(model.Release, model.Project).join(model.Project).filter(
        model.Release.id == args.get('release_id'),
        model.Release.project_id == model.Project.id
    ).one()
    harbor_data = create_default_harbor_data(
        project, release, args.get('registry_id'), args.get('namespace'))
    k8s_data = create_default_k8s_data(
        args)
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


def update_application(application_id, args, user_id):
    app = model.Application.query.filter_by(id=application_id).first()
    project = model.Project.query.filter_by(id=app.project_id).one()
    registry = model.Registries.query.filter_by(
        registries_id=app.registry_id).one()
    cluster = model.Cluster.query.filter_by(
        id=app.cluster_id).one()
    deployment_process = DeploymentProcess(app, cluster, registry, project)
    deployment_process.create_namespace()
    deployment_process.create_registry_secret()
    deployment_process.create_service()
    deployment_process.create_deployment()
    return {}


def get_applications(project_id=None):
    if project_id is None:
        apps = model.Application.query.all()
    else:
        apps = model.Application.query.filter_by(project_id=project_id).all()
    output = []
    for app in apps:
        output.append(row_to_dict(app))
    return output


class Applications(Resource):
    @jwt_required
    def get(self):
        try:
            output = {}
            parser = reqparse.RequestParser()
            parser.add_argument('project_id', type=str)
            args = parser.parse_args()
            role_id = get_jwt_identity()['role_id']
            project_id = args.get('project_id', None)
            if role_id == 5 and project_id is None:
                role.require_admin()
            output = get_applications(project_id)
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
            output = create_application(args)
            return util.success({"applications": {"id": output}})
        except NoResultFound:
            return util.respond(404, error_clusters_not_found,
                                error=apiError.repository_id_not_found)


class Application(Resource):
    @jwt_required
    def get(self, application_id):
        try:
            output = {}
            output = harbor.hb_get_registries()
            return util.success({"cluster": output})
        except NoResultFound:
            return util.respond(404, error_clusters_not_found,
                                error=apiError.repository_id_not_found)

    @jwt_required
    def put(self, application_id):
        try:
            user_id = get_jwt_identity()['user_id']
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
            output = update_application(application_id, args, user_id)
            return util.success(output)
        except NoResultFound:
            return util.respond(404, error_clusters_not_found,
                                error=apiError.repository_id_not_found)

    @jwt_required
    def patch(self, application_id):
        try:
            output = check_application_type(application_id)
            return util.success({"applications": output})
        except NoResultFound:
            return util.respond(404, error_clusters_not_found,
                                error=apiError.repository_id_not_found)

    @jwt_required
    def delete(self, application_id):
        try:
            output = {"success"}
            return util.success({"cluster": {"id": output}})
        except NoResultFound:
            return util.respond(404, error_clusters_not_found,
                                error=apiError.repository_id_not_found)


class Pods(Resource):
    @jwt_required
    def get(self):
        try:
            output = []
            parser = reqparse.RequestParser()
            parser.add_argument('name', type=str)
            args = parser.parse_args()
            server_name = args.get('name').strip()
            k8s_file = get_cluster_config_path(server_name)
            api_k8s_client = kubernetesClient.ApiK8sClient(
                configuration_file=k8s_file)
            response = api_k8s_client.list_pod_for_all_namespaces()
            for i in response.items:
                output.append(
                    {
                        "ip": i.status.pod_ip,
                        "name": i.metadata.name,
                        "namespace": i.metadata.namespace,
                    })
            return util.success({"pod": output})
        except NoResultFound:
            return util.respond(404, error_clusters_not_found,
                                error=apiError.repository_id_not_found)


class Services(Resource):
    @jwt_required
    def get(self):
        try:
            output = []
            parser = reqparse.RequestParser()
            parser.add_argument('name', type=str)
            args = parser.parse_args()
            server_name = args.get('name').strip()
            k8s_file = get_cluster_config_path(server_name)
            api_k8s_client = kubernetesClient.ApiK8sClient(
                configuration_file=k8s_file)
            response = api_k8s_client.list_pod_for_all_namespaces()
            for i in response.items:
                output.append(
                    {
                        "ip": i.status.pod_ip,
                        "name": i.metadata.name,
                        "namespace": i.metadata.namespace,
                    })
            return util.success({"pod": output})
        except NoResultFound:
            return util.respond(404, error_clusters_not_found,
                                error=apiError.repository_id_not_found)
