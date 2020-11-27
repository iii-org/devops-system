from pprint import pprint

from flask_jwt_extended import jwt_required
from flask_restful import Resource, reqparse

from model import db, ProjectPluginRelation, Project, UserPluginRelation, User, ProjectUserRole
from resources import role, harbor
import util


def create_harbor_projects():
    rows = db.session.query(ProjectPluginRelation, Project.name). \
        join(Project).all()
    for row in rows:
        if row.ProjectPluginRelation.harbor_project_id is None:
            harbor_project_id = harbor.hb_create_project(row.name)
            row.ProjectPluginRelation.harbor_project_id = harbor_project_id
            members = db.session.query(ProjectUserRole, UserPluginRelation). \
                join(UserPluginRelation, ProjectUserRole.user_id == UserPluginRelation.user_id). \
                filter(ProjectUserRole.project_id == row.ProjectPluginRelation.project_id
                       ).all()
            for m in members:
                harbor.hb_add_member(harbor_project_id,
                                     m.UserPluginRelation.harbor_user_id)
            db.session.commit()


def create_harbor_users():
    rows = db.session.query(UserPluginRelation, User). \
        join(User).all()
    for row in rows:
        if row.UserPluginRelation.harbor_user_id is None:
            args = {
                'login': row.User.login,
                'password': 'HarborFromIIIDevOps2020',
                'name': row.User.name,
                'email': row.User.email
            }
            hid = harbor.hb_create_user(args)
            row.UserPluginRelation.harbor_user_id = hid
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
        if args['command'] == 'create_harbor_users':
            create_harbor_users()
            return util.success()

        return util.respond(400, 'Command not recognized.')
