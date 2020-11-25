from flask_jwt_extended import jwt_required
from flask_restful import Resource, reqparse

from model import db, ProjectPluginRelation, Project
from resources import role, harbor
import util


def create_harbor_projects():
    rows = db.session.query(ProjectPluginRelation, Project.name). \
        join(Project).all()
    for row in rows:
        if row.ProjectPluginRelation.harbor_project_id is None:
            hid = harbor.hb_create_project(row.name)
            row.ProjectPluginRelation.harbor_project_id = hid
            db.session.commit()


class Migrate(Resource):
    @jwt_required
    def patch(self):
        role.require_admin('Only admins can do migration.')
        parser = reqparse.RequestParser()
        parser.add_argument('command', type=str)
        args = parser.parse_args()

        if args['command'] == 'create_harbor_projects':
            create_harbor_projects()
            return util.success()

        return util.respond(400, 'Command not recognized.')