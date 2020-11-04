from .error import Error
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
            version_list, status_code = self.redmine.rm_get_version_list(
                project_plugin_relation['plan_project_id'])
            if status_code == 200:
                return {"message": "success", "data": version_list.json()}, 200
            else:
                return {"message": "get redmine wiki list error"}, 401
        else:
            return {"message": "No project id %d found" % project_id}, 422

    def post_version_by_project(self, logger, app, project_id, message_args):
        project_plugin_relation = Project.get_project_plugin_relation(
            logger, project_id)
        if project_plugin_relation is not None:
            version, status_code = self.redmine.rm_post_version(project_plugin_relation['plan_project_id'],
                                                                message_args)
            if status_code == 204:
                return {
                    "message": "update Version success",
                    "data": version.json()
                }, 200
            elif status_code == 201:
                return {
                    "message": "create Version success",
                    "data": version.json()
                }, 200
            else:
                return {
                    "message": "Create Redmine Version error",
                    "data": version.json()
                }, status_code

    def get_version_by_version_id(self, logger, app, project_id, version_id):
        version, status_code = self.redmine.rm_get_version(version_id)
        if status_code == 200:
            return util.success(version.json())
        else:
            return util.respond(status_code, "Error when getting version info.",
                                error=Error.redmine_error(version))

    def put_version_by_version_id(self, logger, app, project_id, version_id,
                                  args):
        version, status_code = self.redmine.rm_put_version(version_id, args)
        if status_code == 204:
            return {"message": "update version success", "data": {}}, 200
        elif status_code == 201:
            return {"message": "create version success", "data": {}}, 200
        else:
            return {"message": "put redmine version error"}, status_code

    def delete_version_by_version_id(self, logger, app, project_id,
                                     version_id):
        output, status_code = self.redmine.redmine_delete_version(version_id)
        if status_code == 204:
            return util.success()
        elif status_code == 404:
            return util.respond(200, "already deleted")
        else:
            return util.respond(status_code, "delete redmine wiki error",
                                error=Error.redmine_error(output))
