from model import db, ProjectPluginRelation, Project
from resources import role
import util
import resources.apiError as apiError
from flask_restful import Resource
from resources.handler.jwt import jwt_required
from resources.gitlab import gitlab
import util


def get_system_parameter():
    return util.read_json_file("apis/resources/maintenance/system_parameter.json")



def update_pj_httpurl():
    rows = db.session.query(Project, ProjectPluginRelation).filter(ProjectPluginRelation.project_id == Project.id).all()
    gl_pjs = gitlab.gl_get_all_project()
    for row in rows:
        for gl_pj in gl_pjs:
            if row.ProjectPluginRelation.git_repository_id == gl_pj.id:
                if row.Project.http_url != gl_pj.http_url_to_repo:
                    row.Project.http_url = gl_pj.http_url_to_repo
                    db.session.commit()
                if row.Project.ssh_url != gl_pj.ssh_url_to_repo:
                    row.Project.ssh_url = gl_pj.ssh_url_to_repo
                    db.session.commit()
                break

    # class UpdateDbRcProjectPipelineId(Resource):
    #     @jwt_required
    #     def get(self):
    #         role.require_admin()
    #         parser = reqparse.RequestParser()
    #         parser.add_argument("force", type=str, location="args")
    #         args = parser.parse_args()
    #         update_db_rancher_projectid_and_pipelineid(args["force"])
    #         return util.success()

class UpdatePjHttpUrl(Resource):
    @jwt_required
    def put(self):
        role.require_admin()
        update_pj_httpurl()
        return util.success()
