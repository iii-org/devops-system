import logging

import config
from .user import User
import resources.apiError as apiError
from .project import ProjectResource
import resources.util as util

from resources.logger import logger


class Wiki(object):

    def __init__(self, redmine):
        self.redmine = redmine

    def get_wiki_list_by_project(self, project_id):
        if util.is_dummy_project(project_id):
            return util.success({"wiki_pages": []})
        project_plugin_relation = ProjectResource.get_project_plugin_relation(project_id)
        wiki_list, status_code = self.redmine.rm_get_wiki_list(
            project_plugin_relation['plan_project_id'])
        if status_code == 200:
            return {"message": "success", "data": wiki_list.json()}, 200
        else:
            return {"message": "get redmine wiki list error"}, 401

    def get_wiki_by_project(self, project_id, wiki_name):
        project_plugin_relation = ProjectResource.get_project_plugin_relation(project_id)
        wiki_list, status_code = self.redmine.rm_get_wiki(
            project_plugin_relation['plan_project_id'], wiki_name)
        if status_code == 200:
            return util.success(wiki_list.json())
        else:
            return util.respond(status_code, "Error when getting redmine wiki.",
                                error=apiError.redmine_error(wiki_list))

    def put_wiki_by_project(self, project_id, wiki_name, args, operator_id):
        project_plugin_relation = ProjectResource.get_project_plugin_relation(project_id)
        plan_operator_id = None
        if operator_id is not None:
            operator_plugin_relation = User.get_user_plugin_relation(user_id=operator_id)
            plan_operator_id = operator_plugin_relation['plan_user_id']
        wiki_list, status_code = self.redmine.rm_put_wiki(
            project_plugin_relation['plan_project_id'], wiki_name, args, plan_operator_id)
        if status_code == 204:
            return {"message": "update wiki success"}, 200
        elif status_code == 201:
            return {"message": "create wiki success"}, 200
        else:
            return {"message": "put redmine wiki error"}, 401

    def delete_wiki_by_project(self, project_id, wiki_name):
        project_plugin_relation = ProjectResource.get_project_plugin_relation(project_id)
        resp_wiki_list, status_code = self.redmine.rm_delete_wiki(
            project_plugin_relation['plan_project_id'],
            wiki_name)
        if status_code == 204:
            return util.success()
        else:
            return util.respond(401, "delete redmine wiki error",
                                error=apiError.redmine_error(resp_wiki_list))
