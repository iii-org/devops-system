from model import db, ProjectPluginRelation, Project
from resources import rancher, role
import util
from flask_restful import Resource, reqparse
from flask_jwt_extended import jwt_required
from resources.rancher import rancher
from resources.gitlab import gitlab

def update_db_rancher_projectid_and_pipelineid():
    # get all project
    rows = db.session.query(ProjectPluginRelation, Project). \
        join(Project, ProjectPluginRelation.project_id == Project.id).all()
    rancher.rc_get_project_id()
    now_pipe_data = rancher.rc_get_project_pipeline()
    for now_pipe in now_pipe_data:
        rancher.rc_disable_project_pipeline(now_pipe['projectId'], now_pipe['id'])
    for row in rows:
        pj_info = gitlab.gl_get_project(row.ProjectPluginRelation.git_repository_id)
        rancher_pipeline_id= rancher.rc_enable_project_pipeline(pj_info['http_url_to_repo'])
        ppro =ProjectPluginRelation.query.filter_by(id=row.ProjectPluginRelation.id).first()
        ppro.ci_project_id= rancher.project_id
        ppro.ci_pipeline_id= rancher_pipeline_id
        db.session.commit()


class UpdateDbRcProjectPipelineId(Resource):

    @jwt_required
    def get(self):
        role.require_admin()
        update_db_rancher_projectid_and_pipelineid()
        return util.success()

class SecretesIntoRcAll(Resource):

    @jwt_required
    def get(self):
        secret_list = rancher.rc_get_secrets_all_list()
        registry_list = rancher.rc_get_registry_into_rc_all()
        i = 0
        while i < len(secret_list):
            for registry in registry_list:
                if secret_list[i]["name"] == registry["name"]:
                    del secret_list[i]
                    break
            i += 1
        return util.success(secret_list)
        
    @jwt_required
    def post(self):
        parser = reqparse.RequestParser()
        parser.add_argument('name', type=str, required=True)
        parser.add_argument('type', type=str, required=True)
        parser.add_argument('data', type=dict, required=True)
        args = parser.parse_args()
        rancher.rc_add_secrets_into_rc_all(args)
        return util.success()

    @jwt_required
    def put(self, secret_name):
        parser = reqparse.RequestParser()
        parser.add_argument('type', type=str, required=True)
        parser.add_argument('data', type=dict, required=True)
        args = parser.parse_args()
        rancher.rc_put_secrets_into_rc_all(secret_name, args)
        return util.success()

    @jwt_required
    def delete(self, secret_name):
        return util.success(rancher.rc_delete_secrets_into_rc_all(secret_name))

class RegistryIntoRcAll(Resource):

    @jwt_required
    def get(self):
        return util.success(rancher.rc_get_registry_into_rc_all())
        
    @jwt_required
    def post(self):
        parser = reqparse.RequestParser()
        parser.add_argument('name')
        parser.add_argument('url')
        parser.add_argument('username')
        parser.add_argument('password')
        args = parser.parse_args()
        rancher.rc_add_registry_into_rc_all(args)
        return util.success()

    @jwt_required
    def delete(self, registry_name):
        return util.success(rancher.rc_delete_registry_into_rc_all(registry_name))