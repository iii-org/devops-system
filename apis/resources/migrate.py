from pprint import pprint

from flask_jwt_extended import jwt_required
from flask_restful import Resource, reqparse

import model
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


def cleanup_project_gone(rows):
    for row in rows:
        p_count = model.Project.query.filter_by(id=row.project_id).count()
        if p_count == 0:
            db.session.delete(row)
    db.session.commit()


def cleanup_change_to_orm():
    # Cleanup corrupted data violating foreign key constraints
    cleanup_project_gone(model.Flows.query.all())
    cleanup_project_gone(model.Parameters.query.all())
    cleanup_project_gone(model.Requirements.query.all())
    cleanup_project_gone(model.TestCases.query.all())
    # Insert dummy project
    p = model.Project.query.filter_by(id=-1).first()
    if p is None:
        new = model.Project(id=-1, name='dummy-project', disabled=False)
        db.session.add(new)
        db.session.commit()


class Migrate(Resource):
    @jwt_required
    def patch(self):
        role.require_admin('Only admins can do migration.')
        parser = reqparse.RequestParser()
        parser.add_argument('command', type=str)
        args = parser.parse_args()
        command = args['command']

        if command == 'create_harbor_projects':
            create_harbor_projects()
            return util.success()
        if command == 'create_harbor_users':
            create_harbor_users()
            return util.success()
        if command == 'cleanup_change_to_orm':
            cleanup_change_to_orm()
            return util.success()

        return util.respond(400, 'Command not recognized.')
