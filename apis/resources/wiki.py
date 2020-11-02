import logging

import config
from .redmine import Redmine
from .project import Project
from .util import util

logger = logging.getLogger(config.get('LOGGER_NAME'))


class Wiki(object):
    def __init__(self, redmine):
        self.redmine = redmine

    def get_wiki_list_by_project(self, logger, app, project_id):
        if util.is_dummy_project(project_id):
            return util.success({"wiki_pages": []})
        project_plugin_relation = Project.get_project_plugin_relation(
            logger, project_id)
        wiki_list, status_code = self.redmine.rm_get_wiki_list(
            project_plugin_relation['plan_project_id'])
        if status_code == 200:
            return {"message": "success", "data": wiki_list.json()}, 200
        else:
            return {"message": "get redmine wiki list error"}, 401

    def get_wiki_by_project(self, logger, app, project_id, wiki_name):
        project_plugin_relation = Project.get_project_plugin_relation(
            logger, project_id)
        wiki_list, status_code = self.redmine.rm_get_wiki(
            project_plugin_relation['plan_project_id'], wiki_name)
        if status_code == 200:
            return {"message": "success", "data": wiki_list.json()}, 200
        else:
            return {"message": "get redmine wiki error"}, 401

    def put_wiki_by_project(self, logger, app, project_id, wiki_name, args):
        project_plugin_relation = Project.get_project_plugin_relation(
            logger, project_id)
        redmine_key = Redmine.rm_refresh_key(self)
        wiki_list, status_code = Redmine.redmine_put_wiki(
            self, logger, app, project_plugin_relation['plan_project_id'],
            wiki_name, args)
        if status_code == 204:
            return {"message": "update wiki success"}, 200
        elif status_code == 201:
            return {"message": "create wiki success"}, 200
        else:
            return {"message": "put redmine wiki error"}, 401

    def delete_wiki_by_project(self, logger, app, project_id, wiki_name):
        project_plugin_relation = Project.get_project_plugin_relation(
            logger, project_id)
        redmine_key = Redmine.rm_refresh_key(self)
        wiki_list, status_code = Redmine.redmine_delete_wiki(
            self, logger, app, project_plugin_relation['plan_project_id'],
            wiki_name)
        logger.debug("wiki_list: {0}".format(wiki_list))
        if status_code == 204:
            return {"message": "success"}, 200
        else:
            return {"message": "delete redmine wiki error"}, 401