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


class Error:
    # Project errors
    @staticmethod
    def identifier_has_been_token(identifier):
        return build(1001, 'Project identifier has been taken.', {'identifier': identifier})

    @staticmethod
    def invalid_project_name(name):
        return build(1002, 'Project name may only contain lower cases, numbers, dash, '
                           'the heading and trailing character should be alphanumeric,'
                           'and should be 2 to 225 characters long.',
                     {'name': name})

    @staticmethod
    def project_not_found(project_id=None):
        return build(1003, 'Project not found.', {'project_id': project_id})

    @staticmethod
    def repository_id_not_found(repository_id=None):
        return build(1004, 'Gitlab project not found.', {'repository_id': repository_id})

    # User errors
    @staticmethod
    def user_not_found(user_id):
        return build(2001, 'User not found.', {'user_id': user_id})

    @staticmethod
    def invalid_user_name(name):
        return build(2002, 'User name may only contain a-z, A-Z, 0-9, dot, dash, underline, '
                           'the heading and trailing character should be alphanumeric,'
                           'and should be 2 to 60 characters long.',
                     {'name': name})

    @staticmethod
    def invalid_user_password():
        return build(2003, 'User password may only contain a-z, A-Z, 0-9, '
                           '!@#$%^&*()_+|{}[]`~-=\'";:/?.>,<, '
                           'and should contain at least an upper case alphabet, '
                           'a lower case alphabet, and a digit, '
                           'and is 8 to 20 characters long.')

    # Permission errors
    @staticmethod
    # allowed_role is an array containing allowed role ids.
    def not_allowed(user_name, allowed_role):
        return build(3001, "You don't have the permission for this operation, "
                           "or is a PM or RD but not in this project.",
                     {
                         user_name: user_name,
                         allowed_role: allowed_role
                     })

    # Third party service errors
    @staticmethod
    def redmine_error(response):
        return error_3rd_party_api(8001, 'Redmine', response)

    @staticmethod
    def gitlab_error(response):
        return error_3rd_party_api(8002, 'Gitlab', response)

    @staticmethod
    def rancher_error(response):
        return error_3rd_party_api(8003, 'Rancher', response)

    # Internal errors
    @staticmethod
    def uncaught_exception(exception):
        return build(9001, 'An exception occurs',
                     {'type': type(exception), 'exception': str(exception)})

    @staticmethod
    def unknown_method(method):
        return build(9002, 'A request with unknown method is made.', {'method': method})
