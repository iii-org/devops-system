from .redmine import Redmine
from .project import Project
from .util import util
from .auth import auth
import logging
import config

logger = logging.getLogger(config.get('LOGGER_NAME'))

class Wiki(object):
    
    def __init__(self, redmine):
        self.redmine = redmine
        
    def get_wiki_list_by_project(self, project_id):
        if util.is_dummy_project(project_id):
            return util.success({"wiki_pages": []})
        project_plugin_relation = Project.get_project_plugin_relation(
            logger, project_id)
        wiki_list, status_code = self.redmine.redmine_get_wiki_list(
            project_plugin_relation['plan_project_id'])
        if status_code == 200:
            return {"message": "success", "data": wiki_list.json()}, 200
        else:
            return {"message": "get redmine wiki list error"}, 401

    def get_wiki_by_project(self, project_id, wiki_name):
        project_plugin_relation = Project.get_project_plugin_relation(
            logger, project_id)
        wiki_list, status_code = self.redmine.redmine_get_wiki(
            project_plugin_relation['plan_project_id'],
            wiki_name)
        if status_code == 200:
            return {"message": "success", "data": wiki_list.json()}, 200
        else:
            return {"message": "get redmine wiki error"}, 401

    def put_wiki_by_project(self, project_id, wiki_name, args, operator_id):
        project_plugin_relation = Project.get_project_plugin_relation(
            logger, project_id)
        plan_operator_id = None
        if operator_id is not None:
            operator_plugin_relation = auth.get_user_plugin_relation(user_id=operator_id)
            plan_operator_id = operator_plugin_relation['plan_user_id']
        wiki_list, status_code = self.redmine.redmine_put_wiki(
            project_plugin_relation['plan_project_id'], wiki_name, args, plan_operator_id)
        if status_code == 204:
            return {"message": "update wiki success"}, 200
        elif status_code == 201:
            return {"message": "create wiki success"}, 200
        else:
            return {"message": "put redmine wiki error"}, 401

    def delete_wiki_by_project(self, project_id, wiki_name):
        project_plugin_relation = Project.get_project_plugin_relation(
            logger, project_id)
        wiki_list, status_code = self.redmine.redmine_delete_wiki(
            project_plugin_relation['plan_project_id'],
            wiki_name)
        if status_code == 204:
            return {"message": "success"}, 200
        else:
            return {"message": "delete redmine wiki error"}, 401