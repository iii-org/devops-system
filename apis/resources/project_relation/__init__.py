import model
from flask_jwt_extended import jwt_required, get_jwt_identity
from flask_restful import Resource
import util
from datetime import datetime
from accessories import redmine_lib
from threading import Thread
from sqlalchemy.orm import joinedload
from resources import role
from flask_apispec import marshal_with, doc, use_kwargs
from flask_apispec.views import MethodResource
from . import route_model


def get_plan_id(project_id):
    row = model.ProjectPluginRelation.query.filter_by(
        project_id=project_id).first()
    if row:
        return row.plan_project_id
    else:
        return -1


def get_project_id(plan_id):
    row = model.ProjectPluginRelation.query.filter_by(
        plan_project_id=plan_id).first()
    if row:
        return row.project_id
    else:
        return -1


def get_all_fathers_project(project_id, father_id_list):
    parent_son_relations_object = model.ProjectParentSonRelation.query.filter_by(son_id=project_id).first()
    if parent_son_relations_object is None:
        return father_id_list
    parent_id = parent_son_relations_object.parent_id
    father_id_list.append(parent_id)
    return get_all_fathers_project(parent_id, father_id_list)


def get_all_sons_project(project_id, son_id_list):
    parent_son_relations_object = model.ProjectParentSonRelation.query.filter_by(parent_id=project_id).all()
    son_ids = [relation.son_id for relation in parent_son_relations_object]
    son_id_list += son_ids
    for id in son_ids:
        get_all_sons_project(id, son_id_list)
    return son_id_list

def is_user_in_project(project_id, force):
    if force:
        return True
    if get_jwt_identity()["role_id"] == 5:
        return True
    return model.ProjectUserRole.query.filter_by(project_id=project_id, user_id=get_jwt_identity()["user_id"]).first() is not None

def get_root_project_id(project_id, force=False):
    parent_son_relations_object = model.ProjectParentSonRelation.query.filter_by(son_id=project_id).first()
    if parent_son_relations_object is None or not is_user_in_project(parent_son_relations_object.parent_id, force):
        return project_id
    parent_id = parent_son_relations_object.parent_id
    return get_root_project_id(parent_id, force)

def project_has_child(project_id):
    return model.ProjectParentSonRelation.query.filter_by(parent_id=project_id).first() is not None

def project_has_parent(project_id):
    return model.ProjectParentSonRelation.query.filter_by(son_id=project_id).first() is not None
    
def get_relation_list(project_id, ret):
    son_project_ids = [relation.son_id for relation in model.ProjectParentSonRelation.query. \
        filter_by(parent_id=project_id).all()]
    son_pj_ids = []
    if son_project_ids != []:
        # Check user is project's member
        if get_jwt_identity()["role_id"] == 5:
            son_pj_ids = son_project_ids
        else:
            user_id = get_jwt_identity()["user_id"]
            son_pj_ids = [
                son_pj_id for son_pj_id in son_project_ids if model.ProjectUserRole.query. \
                    filter_by(user_id=user_id, project_id=son_pj_id).first() is not None]
        
        ret.append({
            "parent": project_id,
            "child": son_pj_ids
        })
    for pj_id in son_pj_ids:
        get_relation_list(pj_id, ret)
    return ret


def sync_project_relation():
    # Check current hour is same as regular running hour that user set.
    hours = int(model.SystemParameter.query.filter_by(name="sync_redmine_project_relation").one().value["hours"])
    if hours == 0:
        return
    default_sync_date = datetime.utcnow()
    current_hour = default_sync_date.hour
    project_relations = model.ProjectParentSonRelation.query.limit(1).all()
    if len(project_relations) == 0 and current_hour % hours != 0:
        return 
    
    latest_created_at = project_relations[0].created_at.hour
    current_hour = current_hour if current_hour > latest_created_at else current_hour + 24
    if (current_hour - latest_created_at) % hours != 0:
        return

    default_sync_date = default_sync_date.strftime("%Y-%m-%d %H:%M:%S")
    project_relations = []
    for project in model.Project.query.all():
        if project.id != -1:
            plan_object = redmine_lib.redmine.project.get(get_plan_id(project.id))
            if "parent" in dir(plan_object):
                project_relation = model.ProjectParentSonRelation(
                    parent_id=get_project_id(plan_object.parent.id), 
                    son_id=project.id,
                    created_at=default_sync_date
                )
                project_relations.append(project_relation)
    model.db.session.add_all(project_relations)
    model.db.session.commit()

    for project_relation in model.ProjectParentSonRelation.query.all():
        if str(project_relation.created_at) != default_sync_date: 
            model.db.session.delete(project_relation)
    model.db.session.commit()


def get_project_family_members_by_user_helper(project_id):
    if get_jwt_identity()["role_id"] == 5:
        return True
    user_id = get_jwt_identity()["user_id"]
    return model.ProjectUserRole.query.filter_by(project_id=project_id, user_id=user_id).first() is not None


def get_project_family_members_by_user(project_id):
    son_project_id_list = list(filter(get_project_family_members_by_user_helper, get_all_sons_project(project_id, [])))
    user_list = []
    for project_id in son_project_id_list:
        project_row = model.Project.query.options(
            joinedload(model.Project.user_role).
            joinedload(model.ProjectUserRole.user).
            joinedload(model.User.project_role)
        ).filter_by(id=project_id).one()
        for user in project_row.user_role:
            if user.role_id not in [role.BOT.id, role.ADMIN.id, role.QA.id] and not user.user.disabled \
                and user.user not in user_list:
                user_list.append(user)
        
    user_list.sort(key=lambda x: x.user_id, reverse=True)

    return [{
        "id": relation_row.user.id,
        "name": relation_row.user.name,
        "role_id": relation_row.role_id,
        "role_name": role.get_role_name(relation_row.role_id)
    } for relation_row in user_list]


@doc(tags=['Project Relation'],description="Check project has son project or not")
@marshal_with(route_model.CheckhasSonProjectResponse)
class CheckhasSonProject(MethodResource):
    @jwt_required
    def get(self, project_id):
        return {
            "has_child": project_has_child(project_id)
        }
    
@doc(tags=['Project Relation'],description="Gey root project_id")
@marshal_with(route_model.GetProjectRootIDResponse)
class GetProjectRootID(MethodResource):
    @jwt_required
    def get(self, project_id):
        return {"root_project_id": get_root_project_id(project_id)}


@doc(tags=['Project Relation'],description="Sync IIIDevops project's relationship with Redmine")
@marshal_with(util.CommonResponse)
class SyncProjectRelation(MethodResource):
    @jwt_required
    def post(self):
        Thread(target=sync_project_relation).start()
        return util.success()


@doc(tags=['Project Relation'],description="Get all sons' project members")
@marshal_with(route_model.GetProjectFamilymembersByUserResponse)
class GetProjectFamilymembersByUser(MethodResource):
    @jwt_required
    def get(self, project_id):
        return util.success(get_project_family_members_by_user(project_id))