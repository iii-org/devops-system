from pprint import pprint
from flask_jwt_extended import jwt_required, get_jwt_identity
from flask_restful import Resource, reqparse
from sqlalchemy.orm.exc import NoResultFound
from urllib.parse import urlparse
import werkzeug
from werkzeug.utils import secure_filename
import base64
import config
import model
import os
from model import db
import util as util
from resources import apiError, role
from datetime import datetime, date
from pathlib import Path
from resources import harbor, kubernetesClient
import yaml
import nexus

default_project_id = "-1"
error_clusters_not_found = "No Exact Cluster Found"


def base64decode(value):
    return str(base64.b64decode(str(value)).decode('utf-8'))


def base64encode(value):
    return base64.b64encode(
        bytes(str(value), encoding='utf-8')).decode('utf-8')


def row_to_dict(row):
    ret = {}
    if row is None:
        return row
    for key in type(row).__table__.columns.keys():
        value = getattr(row, key)
        if type(value) is datetime or type(value) is date:
            ret[key] = str(value)
        else:
            ret[key] = value
    return ret


def get_cluster_path(server_name):
    root_path = config.get('DEPLOY_CERTIFICATE_ROOT_PATH')
    return root_path + '/cluster/' + base64encode(server_name)


def check_directory_exists(server_name):
    cluster_path = get_cluster_path(server_name)
    try:
        Path(cluster_path).mkdir(parents=True, exist_ok=True)
        return cluster_path
    except NoResultFound:
        return util.respond(404, "Create Server Directory Error")


def check_cluster(server_name):
    return model.Cluster.query.\
        filter(model.Cluster.name == server_name).\
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
    filename = secure_filename(file.filename)
    file.save(os.path.join(cluster_path, filename))
    file.seek(0)
    content = file.read()
    content = str(content, 'utf-8')
    k8s_json = yaml.safe_load(content)
    cluster_name = k8s_json['clusters'][0]['name']
    cluster_host = k8s_json['clusters'][0]['cluster']['server']
    cluster_user = k8s_json['users'][0]['name']

    now = str(datetime.utcnow())
    new = model.Cluster(
        name=server_name,
        disabled=False,
        creator_id=user_id,
        create_at=now,
        update_at=now,
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
    filename = secure_filename(file.filename)
    file.save(os.path.join(cluster_path, filename))
    file.seek(0)
    content = file.read()
    content = str(content, 'utf-8')
    k8s_json = yaml.safe_load(content)
    cluster_name = k8s_json['clusters'][0]['name']
    cluster_host = k8s_json['clusters'][0]['cluster']['server']
    cluster_user = k8s_json['users'][0]['name']
    return cluster.id


def delete_cluster(cluster_id):
    cluster = model.Cluster.query.filter_by(id=cluster_id).one()
    k8s_config_path = get_cluster_path(cluster.name)
    print(k8s_config_path)
    k8s_file = Path(k8s_config_path+'/k8s_config')
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
            cluster_name = get_cluster_path(output.get('name'))
            k8s_config_file = open(cluster_name+"/k8s_config")
            parsed_yaml_file = yaml.load(
                k8s_config_file, Loader=yaml.FullLoader)
            return util.success({"cluster": output, "K8s_Config": parsed_yaml_file})
        except NoResultFound:
            return util.respond(404, error_clusters_not_found,
                                error=apiError.repository_id_not_found)

    @jwt_required
    def put(self, cluster_id):
        try:
            output = {}
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
            output = {}
            role.require_admin()
            delete_cluster(cluster_id)
            return util.success()
        except NoResultFound:
            return util.respond(404, error_clusters_not_found,
                                error=apiError.repository_id_not_found)


def create_application_image():
    image_uri = 1
    return image_uri


def create_application(args, user_id):

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
        update_at=now,
        status_id=1,
        status="Initial Creating",
    )
    db.session.add(new)
    db.session.commit()
    return new.id


def initial_harbor_replication_image_policy(
    app
):
    release, project = db.session.query(model.Release, model.Project).join(model.Project).filter(
        model.Release.id == app.release_id,
        model.Release.project_id == model.Project.id

    ).one()
    output = {
        "release": row_to_dict(release),
        "project": row_to_dict(project)
    }
    data = {
        "policy_name": project.name + '-' + release.branch+'-'+release.tag_name + "-"+str(datetime.utcnow()),
        "repo_name": project.name,
        "image_name": release.branch,
        "tag_name": release.tag_name,
        "description": 'Automatate create replication policy '+project.name+" release ID" + str(release.id),
        "registry_id": app.registry_id,
        "dest_repo_name": app.namespace,
    }
    policy_id = harbor.hb_create_replication_policy(data)
    return policy_id


def execute_replication_policy(policy_id):
    return harbor.hb_execute_replication_policy(policy_id)


def check_image_process(app):

    policy_id = initial_harbor_replication_image_policy(app)
    image_uri = execute_replication_policy(policy_id)

    return {
        "policy_id": policy_id,
        "image_uri": image_uri
    }


def check_application_type(application_id):
    output = {}
    app = model.Application.query.filter_by(id=application_id).one()
    # Initial Harbor Replication execution
    if app.status_id == 1:
        output['policy_id'] = check_image_process(
            app)
        output['status_id'] = 2
    # Execuation Replication
    elif app.status_id == 2:
        output['status_id'] = 3
    return output


class Applications(Resource):
    @jwt_required
    def get(self):
        try:
            output = {}
            role.require_admin()
            output = harbor.hb_get_registries()
            return util.success({"cluster": output})
        except NoResultFound:
            return util.respond(404, error_clusters_not_found,
                                error=apiError.repository_id_not_found)

    @jwt_required
    def post(self):
        try:
            output = {}
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
            args = parser.parse_args()
            output = create_application(args, user_id)
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
            output = {}
            return util.success({"cluster": {"id": output}})
        except NoResultFound:
            return util.respond(404, error_clusters_not_found,
                                error=apiError.repository_id_not_found)

    @jwt_required
    def patch(self, application_id):
        try:
            output = {}
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


class Registries(Resource):
    @jwt_required
    def get(self):
        try:
            output = {}
            role.require_admin()
            output = harbor.hb_get_registries()
            return util.success({"cluster": output})
        except NoResultFound:
            return util.respond(404, error_clusters_not_found,
                                error=apiError.repository_id_not_found)

    @jwt_required
    def post(self):
        try:
            output = {}
            parser = reqparse.RequestParser()
            parser.add_argument('name', type=str)
            parser.add_argument(
                'k8s_config_file', type=werkzeug.datastructures.FileStorage, location='files')
            args = parser.parse_args()
            harbor.hb_create_registries(args)
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
            k8s_file = get_cluster_path(server_name)+"/k8s_config"
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
            k8s_file = get_cluster_path(server_name)+"/k8s_config"
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
