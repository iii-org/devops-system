# Module to store methods related to nexus database, i.e. the database used by API Server.
from sqlalchemy.orm.exc import NoResultFound

import model
from resources import apiError
from resources.apiError import DevOpsError


def get_project_plugin_relation(nexus_project_id):
    try:
        return model.ProjectPluginRelation.query.filter_by(project_id=nexus_project_id).one()
    except NoResultFound:
        raise DevOpsError(404, 'Error when getting project relations.',
                          error=apiError.project_not_found(nexus_project_id))


def nx_get_project_name(nexus_project_id):
    try:
        pjt = model.Project.query.filter_by(id=nexus_project_id).one()
    except NoResultFound:
        raise apiError.DevOpsError(404, 'Project not found.',
                                   error=apiError.project_not_found(nexus_project_id))
    return pjt.name


def get_user_plugin_relation(user_id=None, plan_user_id=None, gitlab_user_id=None):
    if plan_user_id is not None:
        try:
            return model.UserPluginRelation.query.filter_by(
                plan_user_id=plan_user_id).one()
        except NoResultFound:
            raise apiError.DevOpsError(
                404, 'User with redmine id {0} does not exist in redmine.'.format(plan_user_id),
                apiError.user_not_found(plan_user_id))
    elif gitlab_user_id is not None:
        try:
            return model.UserPluginRelation.query.filter_by(
                repository_user_id=gitlab_user_id).one()
        except NoResultFound:
            raise apiError.DevOpsError(
                404,
                'User with redmine id {0} does not exist in redmine.'.format(plan_user_id),
                apiError.user_not_found(plan_user_id))
    else:
        try:
            return model.UserPluginRelation.query.filter_by(
                user_id=user_id).one()
        except NoResultFound:
            raise apiError.DevOpsError(
                404, 'User id {0} does not exist.'.format(user_id),
                apiError.user_not_found(user_id))
