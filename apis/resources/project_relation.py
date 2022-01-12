import model
from flask_jwt_extended import jwt_required
from flask_restful import Resource
import util



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

def get_root_project_id(project_id):
    parent_son_relations_object = model.ProjectParentSonRelation.query.filter_by(son_id=project_id).first()
    if parent_son_relations_object is None:
        return project_id
    parent_id = parent_son_relations_object.parent_id
    return get_root_project_id(parent_id)

def project_has_child(project_id):
    return model.ProjectParentSonRelation.query.filter_by(parent_id=project_id).first() is not None

def project_has_parent(project_id):
    return model.ProjectParentSonRelation.query.filter_by(son_id=project_id).first() is not None
    
def get_relation_list(project_id, ret):
    son_project_ids = [relation.son_id for relation in model.ProjectParentSonRelation.query. \
        filter_by(parent_id=project_id).all()]
    if son_project_ids != []:
        ret.append({
            "parent": project_id,
            "child": son_project_ids
        })
    for pj_id in son_project_ids:
        get_relation_list(pj_id, ret)
    return ret


class CheckhasSonProject(Resource):
    @jwt_required
    def get(self, project_id):
        return {
            "has_child": project_has_child(project_id)
        }
    
class GetProjectRootID(Resource):
    @jwt_required
    def get(self, project_id):
        return {"root_project_id": get_root_project_id(project_id)}
