import logging

from flask_jwt_extended import jwt_required, get_jwt_identity
from flask_restful import reqparse, Resource

import config
import resources.apiError as apiError
import resources.util as util
import resources.project as project
from resources import role
from resources.redmine import redmine

from resources.logger import logger

EMPTY_VERSIONS = {"versions": [], "total_count": 0}


def get_version_list_by_project(project_id):
    if util.is_dummy_project(project_id):
        return util.success(EMPTY_VERSIONS)
    plan_id = project.get_plan_project_id(project_id)
    if plan_id < 0:
        return util.respond(404, "Error while getting versions.",
                            error=apiError.project_not_found(project_id))
    version_list, status_code = redmine.rm_get_version_list(plan_id)
    if status_code == 200:
        return util.success(version_list.json())
    else:
        return util.respond(status_code, "Error while getting versions.",
                            error=apiError.redmine_error(version_list))


def post_version_by_project(project_id, message_args):
    plan_id = project.get_plan_project_id(project_id)
    if plan_id < 0:
        return util.respond(404, "Error while getting versions.",
                            error=apiError.project_not_found(project_id))
    version, status_code = redmine.rm_post_version(plan_id, message_args)
    if status_code == 204 or status_code == 201:
        return util.success(version.json())
    else:
        return util.respond(status_code, "Error while creating a new version.",
                            error=apiError.redmine_error(version))


def get_version_by_version_id(version_id):
    version, status_code = redmine.rm_get_version(version_id)
    if status_code == 200:
        return util.success(version.json())
    else:
        return util.respond(status_code, "Error when getting version info.",
                            error=apiError.redmine_error(version))


def put_version_by_version_id(version_id, args):
    version, status_code = redmine.rm_put_version(version_id, args)
    if status_code == 204 or status_code == 201:
        return util.success()
    else:
        return util.respond(status_code, "Error when updating version info.",
                            error=apiError.redmine_error(version))


def delete_version_by_version_id(version_id):
    output, status_code = redmine.rm_delete_version(version_id)
    if status_code == 204:
        return util.success()
    elif status_code == 404:
        return util.respond(200, "already deleted")
    else:
        return util.respond(status_code, "delete redmine wiki error",
                            error=apiError.redmine_error(output))


# --------------------- Resources ---------------------
# Get Project Version List
class ProjectVersionList(Resource):
    @jwt_required
    def get(self, project_id):
        role.require_in_project(project_id)
        return get_version_list_by_project(project_id)


class ProjectVersion(Resource):
    @jwt_required
    def post(self, project_id):
        role.require_in_project(project_id)
        root_parser = reqparse.RequestParser()
        root_parser.add_argument('version', type=dict, required=True)
        root_args = root_parser.parse_args()
        return post_version_by_project(project_id, root_args)

    @jwt_required
    def get(self, project_id, version_id):
        role.require_in_project(project_id)
        return get_version_by_version_id(version_id)

    @jwt_required
    def put(self, project_id, version_id):
        role.require_in_project(project_id)
        root_parser = reqparse.RequestParser()
        root_parser.add_argument('version', type=dict, required=True)
        root_args = root_parser.parse_args()
        return put_version_by_version_id(version_id, root_args)

    @jwt_required
    def delete(self, project_id, version_id):
        role.require_in_project(project_id)
        return delete_version_by_version_id(version_id)
