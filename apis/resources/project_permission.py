from flask_jwt_extended import jwt_required
from flask_restful import Resource, reqparse

import config
import model
import util
from resources import apiError, user
from resources.project import get_project_list
from datetime import datetime
from model import db

# Get admin account from environment
admin_account = config.get('ADMIN_INIT_LOGIN')


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
        user_info = {
            'name': model.User.query.get(user_id).name,
            'login': model.User.query.get(user_id).login
        }
        return user_info
    else:
        raise apiError.user_not_found(user_id=user_id)


def get_admin_projects():
    data = get_project_list(user_id=get_admin_user_id(), role="simple")
    all_projects = [
        {
            'id': context['id'],
            'name': context['display']
        } for context in data
    ]
    return all_projects


def get_subadmin_projects(args):
    all_subadmin_projects = []
    subadmin_id_list = args['id'].split(',')
    for user_id in subadmin_id_list:
        projects = []
        user_info = check_subadmin(user_id)
        if user_info:
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
                'name': user_info['name'],
                'login': user_info['login'],
                'projects': projects
            }
            all_subadmin_projects.append(projects_detail)
    return all_subadmin_projects


def get_subadmin():
    subadmin = []
    user_id = model.ProjectUserRole.query.filter_by(
        project_id=-1,
        role_id=7
        ).with_entities(model.ProjectUserRole.user_id).subquery()
    response = model.User.query.filter(model.User.id.in_(user_id)).all()
    if response:
        subadmin = [
            {
                'id': context.id,
                'name': context.name,
                'login': context.login
            } for context in response
        ]
    return subadmin


def set_permission(args):
    user_id = args['user_id']
    project_id = args['project_id']
    role_id = user.get_role_id(user_id)
    user_info = check_subadmin(user_id)
    if user_info:
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
    user_info = check_subadmin(user_id)
    if user_info:
        delete_project_permission = model.ProjectUserRole.query.filter_by(
            user_id=user_id,
            project_id=project_id
        )
        if delete_project_permission:
            delete_project_permission.delete()
            model.db.session.commit()
        else:
            raise apiError.project_not_found(project_id=project_id)

def get_certain_issue_tracker():
    from resources.issue import get_issue_trackers
    trackers = get_issue_trackers()
    return {tracker['id']: tracker['name'] for tracker in trackers}


def get_project_issue_check(project_id):
    
    ret = {
        "enable": False,
        "need_fatherissue_trackers": []
    }
    project_issue_check = model.ProjectIssueCheck.query.filter_by(project_id=project_id).first()
    trackers = get_certain_issue_tracker()
    if project_issue_check is not None:
        ret["enable"] = True 
        ret["need_fatherissue_trackers"] = list(map(lambda x: {x: trackers[x]}, project_issue_check.need_fatherissue_trackers))
    return ret
    

def create_project_issue_check(project_id, args):
    row = model.ProjectIssueCheck(
        project_id=project_id,
        enable=True,
        need_fatherissue_trackers=args["need_fatherissue_trackers"],
        created_at=datetime.utcnow(),
        updated_at=datetime.utcnow(),
    )
    db.session.add(row)
    db.session.commit()


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
