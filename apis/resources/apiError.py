def build(err_code, message, details=None):
    if details is None:
        return {'code': err_code, 'message': message}
    else:
        return {'code': err_code, 'message': message, 'details': details}


def error_3rd_party_api(err_code, api_name, response):
    if type(response) is str:
        return build(err_code, '{0} responds error.'.format(api_name), {'response': response})
    try:
        return build(err_code, '{0} responds error.'.format(api_name), {'response': response.json()})
    except Exception:
        return build(err_code, '{0} responds error.'.format(api_name), {'response': response.text})


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
# allowed_role is an array containing allowed role ids.
def not_allowed(user_name, allowed_role):
    return build(3001, "You don't have the permission for this operation, "
                       "or is a PM or RD but not in this project.",
                 {
                     user_name: user_name,
                     allowed_role: allowed_role
                 })


# Third party service errors
def redmine_error(response):
    return error_3rd_party_api(8001, 'Redmine', response)


def gitlab_error(response):
    return error_3rd_party_api(8002, 'Gitlab', response)


def rancher_error(response):
    return error_3rd_party_api(8003, 'Rancher', response)


# Internal errors
def uncaught_exception(exception):
    return build(9001, 'An exception occurs',
                 {'type': str(type(exception)), 'exception': str(exception)})


def unknown_method(method):
    return build(9002, 'A request with unknown method is made.', {'method': method})


def db_error(detail_message):
    return build(9003, 'An unexpected database error has occurred.', {'message': detail_message})


def unknown_error():
    return build(9999, 'An unknown error has occurred.')
