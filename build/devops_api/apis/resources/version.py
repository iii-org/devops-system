from .redmine import Redmine
from .project import Project
from .util import util
import json


class Version(object):

    EMPTY_VERSIONS = {"versions": [], "total_count": 0}

    def __init__(self, redmine):
        self.redmine = redmine

    def get_version_list_by_project(self, logger, app, project_id):
        if util.is_dummy_project(project_id):
            return util.success(Version.EMPTY_VERSIONS)
        project_plugin_relation = Project.get_project_plugin_relation(
            logger, project_id)
        if project_plugin_relation is not None:
            redmine_key = self.redmine.get_redmine_key(logger, app)
            version_list, statu_code = self.redmine.redmine_get_version_list(
                logger, app, project_plugin_relation['plan_project_id'])
            if statu_code == 200:
                return {"message": "success", "data": version_list.json()}, 200
            else:
                return {"message": "get redmine wiki list error"}, 401
        else:
            return {"message": "No project id %d found" % project_id}, 422

    def post_version_by_project(self, logger, app, project_id, message_args):
        project_plugin_relation = Project.get_project_plugin_relation(
            logger, project_id)
        if project_plugin_relation is not None:
            redmine_key = self.redmine.get_redmine_key(logger, app)
            version, statu_code = self.redmine.redmine_post_version(
                logger, app, project_plugin_relation['plan_project_id'],
                message_args)
            if statu_code == 204:
                return {
                    "message": "update Version success",
                    "data": version.json()
                }, 200
            elif statu_code == 201:
                return {
                    "message": "create Version success",
                    "data": version.json()
                }, 200
            else:
                return {
                    "message": "Create Rredmine Version error",
                    "data": {}
                }, statu_code

    def get_version_by_version_id(self, logger, app, project_id, version_id):
        redmine_key = self.redmine.get_redmine_key(logger, app)
        version, statu_code = self.redmine.redmine_get_version(
            logger, app, version_id)
        if statu_code == 200:
            return {"message": "success", "data": version.json()}, 200
        else:
            return {"message": "get redmine version  error", "data": {}}, statu_code

    def put_version_by_version_id(self, logger, app, project_id, version_id,
                                  args):
        redmine_key = self.redmine.get_redmine_key(logger, app)
        version, statu_code = self.redmine.redmine_put_version(
            logger, app, version_id, args)
        if statu_code == 204:
            return {"message": "update version success", "data": {}}, 200
        elif statu_code == 201:
            return {"message": "create version success", "data": {}}, 200
        else:
            return {"message": "put redmine version error"}, statu_code

    def delete_version_by_version_id(self, logger, app, project_id,
                                     version_id):
        redmine_key = self.redmine.get_redmine_key(logger, app)
        output, statu_code = self.redmine.redmine_delete_version(
            logger, app, version_id)
        logger.debug("Delete Redmine Version : {0}".format(output))
        if statu_code == 204:
            return {"message": "success", "data": {}}, 200
        else:
            return {"message": "delete redmine wiki error", "data": {}}, statu_code
