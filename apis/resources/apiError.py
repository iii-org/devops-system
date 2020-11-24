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


# Project errors
def identifier_has_been_token(identifier):
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


# Permission errors
class NotAllowedError(HTTPException):
    pass


class NotInProjectError(HTTPException):
    pass


class NotUserHimselfError(HTTPException):
    pass


# Redmine Issue/Wiki/... errors
def issue_not_found(issue_id):
    return build(4001, 'Issue not found.', {'issue_id': issue_id})


# General errors
def no_detail():
    return build(7001, 'This error has no detailed information.')


def argument_error(arg_name):
    return build(7002, 'Argument {0} is incorrect.'.format(arg_name), {'arg': arg_name})


# Third party service errors
def redmine_error(response):
    return error_3rd_party_api('Redmine', response)


def gitlab_error(response):
    return error_3rd_party_api('Gitlab', response)


# Internal errors
def uncaught_exception(exception):
    return build(9001, 'An uncaught exception has occurred.',
                 {'type': str(type(exception)), 'exception': str(exception)})


def unknown_method(method):
    return build(9002, 'A request with unknown method is made.', {'method': method})


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
    }
}


# Exceptions wrapping method_type error information
class DevOpsError(Exception):
    def __init__(self, status_code, message, error=None):
        self.status_code = status_code
        self.message = message
        self.error_value = error
