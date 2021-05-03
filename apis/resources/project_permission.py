import os
import model
import util
from resources import apiError, user
from resources.project import list_projects
from flask_jwt_extended import jwt_required
from flask_restful import Resource, reqparse


# Get admin account from environment
admin_account = os.environ.get('ADMIN_INIT_LOGIN')


def get_admin_user_id():
    user_detail = model.User.query.filter_by(login=admin_account).first()
    return user_detail.id


def check_subadmin(user_id):
    user = model.ProjectUserRole.query.filter_by(
        user_id=user_id,
        project_id=-1,
        role_id=7
        ).first()
    if user:
        return model.User.query.get(user_id).name
    else:
        raise apiError.user_not_found(user_id=user_id)


def get_admin_projects():
    response = list_projects(user_id=get_admin_user_id())[0]['data']['project_list']
    all_projects = [
        {
            'id': context['id'],
            'name': context['display']
        } for context in response
    ]
    return all_projects


def get_subadmin_projects(args):
    all_subadmin_projects = []
    subadmin_id_list = args['id'].split(',')
    for user_id in subadmin_id_list:
        projects = []
        user_name = check_subadmin(user_id)
        if user_name:
            response = model.ProjectUserRole.query.filter(
                model.ProjectUserRole.user_id == user_id,
                model.ProjectUserRole.project_id != -1
                ).all()
            if response:
                projects = [
                    {
                        'id': context.project_id,
                        'name': model.Project.query.get(context.project_id).display
                    } for context in response
                ]
            projects_detail = {
                'id': user_id,
                'name': user_name,
                'projects': projects
            }
            all_subadmin_projects.append(projects_detail)
    return all_subadmin_projects


def get_subadmin():
    subadmin = []
    user_id = model.ProjectUserRole.query.filter_by(
        project_id=-1,
        role_id=7
        ).with_entities(model.ProjectUserRole.user_id).all()
    user_id_list = list(sum(user_id, ()))
    response = model.User.query.filter(model.User.id.in_(user_id_list)).all()
    if response:
        subadmin = [
            {
                'id': context.id,
                'name': context.name
            } for context in response
        ]
    return subadmin


def set_permission(args):
    user_id = args['user_id']
    project_id = args['project_id']
    role_id = user.get_role_id(user_id)
    user_name = check_subadmin(user_id)
    if user_name:
        new_project_permission = model.ProjectUserRole(
            user_id=user_id,
            project_id=project_id,
            role_id=role_id
        )
        model.db.session.add(new_project_permission)
        model.db.session.commit()


def unset_permission(args):
    user_id = args['user_id']
    project_id = args['project_id']
    user_name = check_subadmin(user_id)
    if user_name:
        delete_project_permission = model.ProjectUserRole.query.filter_by(
            user_id=user_id,
            project_id=project_id
        )
        if delete_project_permission:
            delete_project_permission.delete()
            model.db.session.commit()
        else:
            raise apiError.project_not_found(project_id=project_id)


class AdminProjects(Resource):
    @jwt_required
    def get(self):
        all_projects = get_admin_projects()
        return util.success(all_projects)


class SubadminProjects(Resource):
    @jwt_required
    def get(self):
        parser = reqparse.RequestParser()
        parser.add_argument('id', type=str, required=True)
        args = parser.parse_args()
        all_subadmin_projects = get_subadmin_projects(args)
        return util.success(all_subadmin_projects)


class Subadmins(Resource):
    @jwt_required
    def get(self):
        all_subadmin = get_subadmin()
        return util.success(all_subadmin)


class SetPermission(Resource):
    @jwt_required
    def post(self):
        parser = reqparse.RequestParser()
        parser.add_argument('user_id', type=int)
        parser.add_argument('project_id', type=int)
        args = parser.parse_args()
        set_permission(args)
        return util.success()

    @jwt_required
    def delete(self):
        parser = reqparse.RequestParser()
        parser.add_argument('user_id', type=int)
        parser.add_argument('project_id', type=int)
        args = parser.parse_args()
        unset_permission(args)
        return util.success()
