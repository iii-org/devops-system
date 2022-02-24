from flask_apispec import marshal_with, doc
from flask_apispec.views import MethodResource
from flask_jwt_extended import jwt_required
from flask_restful import Resource
import util
from threading import Thread
from urls.project import router_model
from resources.project_relation import project_has_child, get_root_project_id, sync_project_relation, \
    get_project_family_members_by_user



##### Project Relation ######

@doc(tags=['Project Relation'],description="Check project has son project or not")
@marshal_with(router_model.CheckhasSonProjectResponse)
class CheckhasSonProjectV2(MethodResource):
    @jwt_required
    def get(self, project_id):
        return {
            "has_child": project_has_child(project_id)
        }
    
class CheckhasSonProject(Resource):
    @jwt_required
    def get(self, project_id):
        return {
            "has_child": project_has_child(project_id)
        }

@doc(tags=['Project Relation'],description="Gey root project_id")
@marshal_with(router_model.GetProjectRootIDResponse)
class GetProjectRootIDV2(MethodResource):
    @jwt_required
    def get(self, project_id):
        return {"root_project_id": get_root_project_id(project_id)}

class GetProjectRootID(Resource):
    @jwt_required
    def get(self, project_id):
        return {"root_project_id": get_root_project_id(project_id)}

@doc(tags=['Project Relation'],description="Sync IIIDevops project's relationship with Redmine")
@marshal_with(util.CommonResponse)
class SyncProjectRelationV2(MethodResource):
    @jwt_required
    def post(self):
        Thread(target=sync_project_relation).start()
        return util.success()

class SyncProjectRelation(Resource):
    @jwt_required
    def post(self):
        Thread(target=sync_project_relation).start()
        return util.success()

@doc(tags=['Project Relation'],description="Get all sons' project members")
@marshal_with(router_model.GetProjectFamilymembersByUserResponse)
class GetProjectFamilymembersByUserV2(MethodResource):
    @jwt_required
    def get(self, project_id):
        return util.success(get_project_family_members_by_user(project_id))

class GetProjectFamilymembersByUser(Resource):
    @jwt_required
    def get(self, project_id):
        return util.success(get_project_family_members_by_user(project_id))