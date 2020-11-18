from flask_jwt_extended import jwt_required, get_jwt_identity
from flask_restful import Resource, reqparse

import resources.apiError as apiError
import resources.project as project
import resources.user as user
import resources.util as util
from resources import role
from resources.redmine import redmine


def get_wiki_list_by_project(project_id):
    if util.is_dummy_project(project_id):
        return util.success({"wiki_pages": []})
    plan_id = project.get_plan_project_id(project_id)
    if plan_id < 0:
        return util.respond(404, "Error while getting wiki.",
                            error=apiError.project_not_found(project_id))
    wiki_list, status_code = redmine.rm_get_wiki_list(plan_id)
    if status_code == 200:
        return util.success(wiki_list.json())
    else:
        return util.respond(status_code, "Error when getting redmine wiki list.",
                            error=apiError.redmine_error(wiki_list))


def get_wiki_by_project(project_id, wiki_name):
    plan_id = project.get_plan_project_id(project_id)
    if plan_id < 0:
        return util.respond(404, "Error while getting wiki.",
                            error=apiError.project_not_found(project_id))
    wiki_list, status_code = redmine.rm_get_wiki(plan_id, wiki_name)
    if status_code == 200:
        wiki_detail = wiki_list.json()
        if 'author' in wiki_detail['wiki_page']:
            user_info = user.get_user_id_name_by_plan_user_id(wiki_detail['wiki_page']['author']['id'])
            if user_info is not None:
                wiki_detail['wiki_page']['author'] = {'id': user_info['id'], 'name': user_info['name']}
        return util.success(wiki_detail)
    else:
        return util.respond(status_code, "Error when getting redmine wiki.",
                            error=apiError.redmine_error(wiki_list))


def put_wiki_by_project(project_id, wiki_name, args, operator_id):
    plan_id = project.get_plan_project_id(project_id)
    if plan_id < 0:
        return util.respond(404, "Error while updating wiki.",
                            error=apiError.project_not_found(project_id))
    plan_operator_id = None
    if operator_id is not None:
        operator_plugin_relation = user.get_user_plugin_relation(user_id=operator_id)
        plan_operator_id = operator_plugin_relation['plan_user_id']
    wiki_list, status_code = redmine.rm_put_wiki(
        plan_id, wiki_name, args, plan_operator_id)
    if status_code == 204 or status_code == 201:
        return util.success()
    else:
        return util.respond(status_code, "Error when updating redmine wiki.",
                            error=apiError.redmine_error(wiki_list))


def delete_wiki_by_project(project_id, wiki_name):
    plan_id = project.get_plan_project_id(project_id)
    if plan_id < 0:
        return util.respond(404, "Error while deleting wiki.",
                            error=apiError.project_not_found(project_id))
    resp_wiki_list, status_code = redmine.rm_delete_wiki(
        plan_id, wiki_name)
    if status_code == 204:
        return util.success()
    else:
        return util.respond(status_code, "delete redmine wiki error",
                            error=apiError.redmine_error(resp_wiki_list))


# --------------------- Resources ---------------------
class ProjectWikiList(Resource):
    @jwt_required
    def get(self, project_id):
        role.require_in_project(project_id)
        return get_wiki_list_by_project(project_id)


class ProjectWiki(Resource):
    @jwt_required
    def get(self, project_id, wiki_name):
        role.require_in_project(project_id)
        return get_wiki_by_project(project_id, wiki_name)

    @jwt_required
    def put(self, project_id, wiki_name):
        role.require_in_project(project_id)
        parser = reqparse.RequestParser()
        parser.add_argument('wiki_text', type=str, required=True)
        args = parser.parse_args()
        return put_wiki_by_project(project_id, wiki_name, args, get_jwt_identity()['user_id'])

    @jwt_required
    def delete(self, project_id, wiki_name):
        role.require_in_project(project_id)
        return delete_wiki_by_project(project_id, wiki_name)
