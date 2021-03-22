from model import db, ProjectPluginRelation, Project
from resources import rancher, role
import util
from flask_restful import Resource, reqparse
from flask_jwt_extended import jwt_required
from resources.rancher import rancher


def update_db_rancher_projectid_and_pipelineid():
    # get all project
    rows = db.session.query(ProjectPluginRelation, Project). \
        join(Project).all()
    # print(rows)
    rancher.rc_get_project_id()
    # print("ci_project_id: {0}".format(rancher.project_id))

    for row in rows:
        rancher.rc_disable_project_pipeline( row.ProjectPluginRelation.ci_project_id, \
            row.ProjectPluginRelation.ci_pipeline_id)
        rancher_pipeline_id= rancher.rc_enable_project_pipeline(row.Project.http_url)
        # print(row.ProjectPluginRelation.ci_pipeline_id)
        ppro =ProjectPluginRelation.query.filter_by(id=row.ProjectPluginRelation.id).first()
        ppro.ci_project_id= rancher.project_id
        ppro.ci_pipeline_id= rancher_pipeline_id
        # print("ci_pipeline_id: {0}".format(rancher_pipeline_id))
        db.session.commit()


class UpdateDbRcProjectPipelineId(Resource):
    
    @jwt_required
    def get(self):
        role.require_admin()
        update_db_rancher_projectid_and_pipelineid()

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
        parser.add_argument('name', type=str)
        parser.add_argument('type', type=str)
        parser.add_argument('data')
        args = parser.parse_args()
        rancher.rc_add_secrets_into_rc_all(args)
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