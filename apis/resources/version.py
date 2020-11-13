import logging

import config
import resources.apiError as apiError
import resources.util as util
from .project import ProjectResource

from resources.logger import logger


class Version(object):

    EMPTY_VERSIONS = {"versions": [], "total_count": 0}

    def __init__(self, redmine):
        self.redmine = redmine

    def get_version_list_by_project(self, project_id):
        if util.is_dummy_project(project_id):
            return util.success(Version.EMPTY_VERSIONS)
        project_plugin_relation = ProjectResource.get_project_plugin_relation(project_id)
        if project_plugin_relation is not None:
            version_list, status_code = self.redmine.rm_get_version_list(
                project_plugin_relation['plan_project_id'])
            if status_code == 200:
                return util.success(version_list.json())
            else:
                return util.respond(status_code, "Error while getting versions.",
                                    error=apiError.redmine_error(version_list))
        else:
            return util.respond(404, "Error while getting versions.",
                                error=apiError.project_not_found(project_id))

    def post_version_by_project(self, project_id, message_args):
        project_plugin_relation = ProjectResource.get_project_plugin_relation(project_id)
        if project_plugin_relation is not None:
            version, status_code = self.redmine.rm_post_version(project_plugin_relation['plan_project_id'],
                                                                message_args)
            if status_code == 204 or status_code == 201:
                return util.success(version.json())
            else:
                return util.respond(status_code, "Error while creating a new version.",
                                    error=apiError.redmine_error(version))

    def get_version_by_version_id(self, version_id):
        version, status_code = self.redmine.rm_get_version(version_id)
        if status_code == 200:
            return util.success(version.json())
        else:
            return util.respond(status_code, "Error when getting version info.",
                                error=apiError.redmine_error(version))

    def put_version_by_version_id(self, version_id, args):
        version, status_code = self.redmine.rm_put_version(version_id, args)
        if status_code == 204 or status_code == 201:
            return util.success()
        else:
            return util.respond(status_code, "Error when updating version info.",
                                error=apiError.redmine_error(version))

    def delete_version_by_version_id(self, version_id):
        output, status_code = self.redmine.rm_delete_version(version_id)
        if status_code == 204:
            return util.success()
        elif status_code == 404:
            return util.respond(200, "already deleted")
        else:
            return util.respond(status_code, "delete redmine wiki error",
                                error=apiError.redmine_error(output))
