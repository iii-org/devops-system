from model import db, ProjectPluginRelation, Project
from resources import rancher, role
from flask_restful import Resource
from flask_jwt_extended import jwt_required
from resources.rancher import rancher


def update_db_rancher_projectid_and_pipelineid():
    # get all project
    rows = db.session.query(ProjectPluginRelation, Project). \
        join(Project).all()
    # print(rows)
    rancher_project_id = rancher.rc_get_project_id()
    print("ci_project_id: {0}".format(rancher_project_id))
    for row in rows:
        try:
            rancher.rc_disable_project_pipeline( row.ProjectPluginRelation.ci_project_id, \
                row.ProjectPluginRelation.ci_pipeline_id)
            rancher_pipeline_id= rancher.rc_enable_project_pipeline(row.Project.http_url)
            print(row.ProjectPluginRelation.ci_pipeline_id)
            ppro =ProjectPluginRelation.query.filter_by(id=row.ProjectPluginRelation.id).first()
            ppro.ci_project_id= rancher_project_id
            ppro.ci_pipeline_id= rancher_pipeline_id
            print("ci_pipeline_id: {0}".format(rancher_pipeline_id))
            db.session.commit()
        except:
            pass

class update_db_rc_project_pipeline_id(Resource):
    
    @jwt_required
    def get(self):
        role.require_admin()
        update_db_rancher_projectid_and_pipelineid()