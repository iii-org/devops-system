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
from kubernetes import client as k8s_client
from kubernetes import config as k8s_config
from kubernetes.client.rest import ApiException
from datetime import datetime, date
from pathlib import Path
import yaml
import nexus

default_project_id = "-1"

error_clusters_not_found = "No Exact Cluster Found"


def base64decode(value):
    return str(base64.b64decode(str(value)).decode('utf-8'))


def base64encode(value):
    return base64.b64encode(
        bytes(str(value), encoding='utf-8')).decode('utf-8')


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


def get_clusters():
    output = []
    clusters = model.Cluster.query.all()    
    for cluster in clusters:
        output.append(
            {
                "name": cluster.name,
                "disabled": cluster.disabled,
                "create_at": cluster.create_at,
                "update_at": cluster.update_at,
            }
        )
        
    return output



def add_cluster(args, server_name, user_id):
    cluster_path = check_directory_exists(server_name)
    print(args.get('k8s_config_file'))
    file = args.get('k8s_config_file')
    filename = secure_filename(file.filename)
    file.save(os.path.join(cluster_path, filename))
    file.seek(0)
    content = file.read()
    content = str(content, 'utf-8')
    k8s_json = yaml.safe_load(content)
    cluster_name = k8s_json['cluster'][0]['name']
    cluster_host = k8s_json['cluster'][0]['cluster']['server']
    cluster_user = k8s_json['users'][0]['name']    
    now= str(datetime.now())
    new = model.Cluster(
        name=server_name,
        cluster_name = cluster_name,
        cluster_host = cluster_host,
        cluster_user = cluster_user,
        disabled=False,
        creator_id=user_id,
        create_at=now,
        update_at=now,
    )
    db.session.add(new)
    db.session.commit()
    return filename

class K8SClient(object):
    def __init__(self, server_name):
        cluster_path = get_cluster_path(server_name)
        self.aApiClient = k8s_client.ApiClient(configuration=k8s_config.load_kube_config(
            config_file=cluster_path+'/k8s_config'
        ))

    def get_pods(self):
        output = []
        api_instance = k8s_client.CoreV1Api(self.aApiClient)
        try:
            ret = api_instance.list_pod_for_all_namespaces(watch=False)
            for i in ret.items:
                print("%s\t%s\t%s" %
                      (i.status.pod_ip, i.metadata.namespace, i.metadata.name))
                output.append("%s\t%s\t%s" %
                              (i.status.pod_ip, i.metadata.namespace, i.metadata.name))
            return output
        except ApiException as e:
            print("Exception when calling CoreV1Api->list_pods: %s\n" % e)


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
                output = add_cluster(args, server_name, user_id)
            return util.success({"cluster": output})
        except NoResultFound:
            return util.respond(404, error_clusters_not_found,
                                error=apiError.repository_id_not_found)


class Artifacts(Resource):
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
                output = add_cluster(args, server_name, user_id)
            return util.success({"cluster": output})
        except NoResultFound:
            return util.respond(404, error_clusters_not_found,
                                error=apiError.repository_id_not_found)


class Pods(Resource):
    @jwt_required
    def get(self):
        try:
            output = {}
            parser = reqparse.RequestParser()
            parser.add_argument('name', type=str)
            args = parser.parse_args()
            server_name = args.get('name').strip()
            api_k8s_client = K8SClient(server_name)
            output = api_k8s_client.get_pods()
            return util.success({"cluster": output})
        except NoResultFound:
            return util.respond(404, error_clusters_not_found,
                                error=apiError.repository_id_not_found)
    


