# Error code document at:
# https://github.com/iii-org/devops-system/wiki/ErrorCodes

from werkzeug.exceptions import HTTPException


def build(err_code, message, details=None):
    if details is None:
        return {'code': err_code, 'message': message}
    else:
        return {'code': err_code, 'message': message, 'details': details}


def error_3rd_party_api(service_name, response):
    if type(response) is str:
        resp_value = response
    else:
        try:
            resp_value = response.json()
        except Exception:
            resp_value = response.text
    return build(8001, '{0} responds error.'.format(service_name),
                 {'service_name': service_name, 'response': resp_value})


# Template errors
def template_not_found(template_id):
    return build(5001, 'Template not found.',
                 {'template_id': template_id})


def template_file_not_found(template_id, template_name):
    return build(5002, 'Can not get template file or folder.',
                 {'template_id': template_id, 'template_name': template_name})


# Project errors
def identifier_has_been_taken(identifier):
    return build(1001, 'Project identifier has been taken.', {'identifier': identifier})


def invalid_project_name(name):
    return build(1002, 'Project name may only contain lower cases, numbers, dash, '
                       'the heading and trailing character should be alphanumeric,'
                       'and should be 2 to 225 characters long.',
                 {'name': name})


def project_not_found(project_id=None):
    return build(1003, 'Project not found.', {'project_id': project_id})


def repository_id_not_found(repository_id=None):
    return build(1004, 'Gitlab project not found.', {'repository_id': repository_id})


def redmine_project_not_found(project_id=None):
    return build(1005, 'Redmine does not have this project.', {'project_id': project_id})


def redmine_unable_to_delete_version(version_id=None):
    return build(1006, 'Unable to delete the version.', {'version_id': version_id})


def redmine_unable_to_forced_closed_issues(issues=None):
    return build(1007, 'Unable to build the release.', {'issues': issues})


def release_unable_to_build(info=None):
    return build(1008, 'Unable to build the release.', info)


def invalid_plugin_name(plugin_name):
    return build(1009, 'Plugin Software not found.', {'plugin_name': plugin_name})


def invalid_project_content(key, value):
    return build(1010, 'Project {0} contain characters like & or <.'.format(key), {'{0}'.format(key): value})


def invalid_project_owner(owner_id=None):
    return build(1011, 'Project owner role must be PM.', {'owner_id': owner_id})


def invalid_fixed_version_id(fixed_version, fixed_version_status):
    return build(1012, 'Fixed version status is {0}.'.format(fixed_version_status),
                 {'fixed_version': fixed_version, 'fixed_version_status': fixed_version_status})


# User errors
def user_not_found(user_id):
    return build(2001, 'User not found.', {'user_id': user_id})


def invalid_user_name(name):
    return build(2002, 'User name may only contain a-z, A-Z, 0-9, dot, dash, underline, '
                       'the heading and trailing character should be alphanumeric,'
                       'and should be 2 to 60 characters long.',
                 {'name': name})


def invalid_user_password():
    return build(2003, 'User password may only contain a-z, A-Z, 0-9, '
                       '!@#$%^&*()_+|{}[]`~-=\'";:/?.>,<, '
                       'and should contain at least an upper case alphabet, '
                       'a lower case alphabet, and a digit, '
                       'and is 8 to 20 characters long.')


def wrong_password():
    return build(2004, 'Wrong password or username.')


def already_used():
    return build(2005, 'This username or email is already used.')


def already_in_project(user_id, project_id):
    return build(2006, 'This user is already in the project.',
                 {'user_id': user_id, 'project_id': project_id})


def is_project_owner_in_project(user_id, project_id):
    return build(2007, 'This user is project owner  in the project.',
                 {'user_id': user_id, 'project_id': project_id})


def user_from_ad(user_id):
    return build(2008, 'This user comes from ad server, normal user cannot modify.',
                 {'user_id': user_id})


def user_in_a_project(user_id):
    return build(2009, 'User is in a project, cannot change his role.',
                 {'user_id': user_id})


def ad_account_not_allow():
    return build(2010, 'User Account in AD is invalid in DevOps System')


def cluster_not_found(server_name):
    return build(2011, 'Clusters can not attach',
                 {'server_name': server_name})


def cluster_duplicated(server_name):
    return build(2012, 'Clusters is duplicate',
                 {'server_name': server_name})


# Permission errors
class NotAllowedError(HTTPException):
    pass


class NotInProjectError(HTTPException):
    pass


class NotUserHimselfError(HTTPException):
    pass


class NotProjectOwnerError(HTTPException):
    pass


# Redmine Issue/Wiki/... errors
def issue_not_found(issue_id):
    return build(4001, 'Issue not found.', {'issue_id': issue_id})


def issue_not_all_closed(version_ids):
    return build(4002, 'Issue in Versions not closed.', {'versions': version_ids})


def redmine_unable_to_relate(issue_id, issue_to_id):
    return build(4003, 'Issues {issue_id}, {issue_to_id} can not create relations.',
                 {'issue_ids': [issue_id, issue_to_id]})


# General errors
def no_detail():
    return build(7001, 'This error has no detailed information.')


def argument_error(arg_name):
    return build(7002, 'Argument {0} is incorrect.'.format(arg_name), {'arg': arg_name})


def resource_not_found():
    return build(7003, 'The indicated resource is not found.')


def path_not_found():
    return build(7004, 'The requested URL is not found on this server. Please check if the path is correct.')


def maximum_error(object, num):
    return build(7005, f'Maximum number of {object} is {num}.', {'object': object, 'num': num})


def redmine_argument_error(arg_name):
    return build(7006, f'Argument {arg_name} can not be alerted when children issue exist.')


# Third party service errors
def redmine_error(response):
    return error_3rd_party_api('Redmine', response)


def gitlab_error(response):
    return error_3rd_party_api('Gitlab', response)


# Internal errors
def uncaught_exception(exception):
    return build(9001, 'An uncaught exception has occurred.',
                 {'type': str(type(exception)), 'exception': str(exception)})


def invalid_code_path(detail_message):
    return build(9002, 'An invalid code path happens.', {'message': detail_message})


def db_error(detail_message):
    return build(9003, 'An unexpected database error has occurred.', {'message': detail_message})


def unknown_error():
    return build(9999, 'An unknown internal error has occurred.')


# Exception type errors, for errors those need to be aborted instantly rather than returning
# an error response.
custom_errors = {
    'NotAllowedError': {
        'error': build(3001, "Your role does not have the permission for this operation."),
        'status': 401
    },
    'NotInProjectError': {
        'error': build(3002, 'You need to be in the project for this operation.'),
        'status': 401
    },
    'NotUserHimselfError': {
        'error': build(3003, "You are not permitted to access another user's data."),
        'status': 401
    },
    'NotProjectOwnerError': {
        'error': build(3004, "Only PM can set it, please contact PM for assistance."),
        'status': 401
    }
}


# Exceptions wrapping method_type error information
class DevOpsError(Exception):
    def __init__(self, status_code, message, error=None):
        self.status_code = status_code
        self.message = message
        self.error_value = error

    def unpack_response(self):
        return self.error_value['details']['response']


class TemplateError(Exception):
    def __init__(self, status_code, message, error=None):
        self.status_code = status_code
        self.message = message
        self.error_value = error
