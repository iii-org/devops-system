from flask_jwt_extended import jwt_required
from flask_restful import reqparse, Resource
from sqlalchemy.orm.exc import NoResultFound

import resources.apiError as apiError
import resources.project as project
import util as util
from resources import role
from resources.redmine import redmine

EMPTY_VERSIONS = {"versions": [], "total_count": 0}


def get_version_list_by_project(project_id, status):
    if util.is_dummy_project(project_id):
        return util.success(EMPTY_VERSIONS)
    try:
        plan_id = project.get_plan_project_id(project_id)
    except NoResultFound:
        return util.respond(404, "Error while getting versions.",
                            error=apiError.project_not_found(project_id))
    version_list = redmine.rm_get_version_list(plan_id)
    if status is not None:
        statuses = status.split(',')
        version_list['versions'] = list(filter(
            lambda x: x.get('status') in statuses, version_list['versions']))
        version_list['total_count'] = len(version_list['versions'])
    version_list.get('versions').sort(key=__compare_date_string)
    return version_list


def __compare_date_string(a, b):
    if a.get('due_date', '') is None:
        return 1
    if b.get('due_date', '') is None:
        return -1
    if a.get('due_date', '') != b.get('due_date', ''):
        return a.get('due_date', '') < b.get('due_date', '')
    if a.get('updated_on', '') is None:
        return 1
    if b.get('updated_on', '') is None:
        return -1
    if a.get('updated_on', '') != b.get('updated_on', ''):
        return a.get('updated_on', '') < b.get('updated_on', '')


def post_version_by_project(project_id, message_args):
    try:
        plan_id = project.get_plan_project_id(project_id)
    except NoResultFound:
        return util.respond(404, "Error while getting versions.",
                            error=apiError.project_not_found(project_id))
    version = redmine.rm_post_version(plan_id, message_args)
    return util.success(version)


def get_version_by_version_id(version_id):
    version = redmine.rm_get_version(version_id)
    return util.success(version)


def put_version_by_version_id(version_id, args):
    redmine.rm_put_version(version_id, args)
    return util.success()


def delete_version_by_version_id(version_id):
    try:
        redmine.rm_delete_version(version_id)
    except apiError.DevOpsError as e:
        if e.status_code == 404:
            # Already deleted, let it go
            return util.respond(200, "already deleted")
        else:
            return util.respond(422, 'Unable to delete the version.',
                                error=apiError.redmine_unable_to_delete_version(version_id))
    return util.success()


# --------------------- Resources ---------------------
# Get Project Version List
class ProjectVersionList(Resource):
    @jwt_required
    def get(self, project_id):
        role.require_in_project(project_id)
        root_parser = reqparse.RequestParser()
        root_parser.add_argument('status', type=str)
        root_args = root_parser.parse_args()
        return util.success(get_version_list_by_project(project_id, root_args['status']))


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
