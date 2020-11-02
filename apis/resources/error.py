class Error:
    @staticmethod
    def build(err_code, message, details=None):
        if details is None:
            return {'code': err_code, 'message': message}
        else:
            return {'code': err_code, 'message': message, 'details': details}

    # Project errors
    @staticmethod
    def identifier_has_been_token(identifier):
        return Error.build(1001, 'Project identifier has been taken', {'identifier': identifier})

    @staticmethod
    def invalid_project_name(name):
        return Error.build(1002, 'Project name may only contain a-z, A-Z, 0-9, dash, '
                                 'the heading and trailing character should be alphanumeric,'
                                 'and should be 2 to 225 characters long.',
                           {'name': name})

    # User errors
    @staticmethod
    def user_not_found(user_id):
        return Error.build(2001, 'User is not found', {'user_id': user_id})

    @staticmethod
    def invalid_user_name(name):
        return Error.build(2002, 'User name may only contain a-z, A-Z, 0-9, dot, dash, underline, '
                                 'the heading and trailing character should be alphanumeric,'
                                 'and should be 2 to 60 characters long.',
                           {'name': name})

    @staticmethod
    def invalid_user_password():
        return Error.build(2003, 'User password may only contain a-z, A-Z, 0-9, '
                                 '!@#$%^&*()_+|{}[]`~-=\'";:/?.>,<, '
                                 'and should contain at least an upper case alphabet, '
                                 'a lower case alphabet, and a digit, '
                                 'and is 8 to 20 characters long.')

    # Third party service errors
    @staticmethod
    def redmine_error(response):
        return Error.build(8001, 'Redmine responds error', response)

    # Internal errors
    @staticmethod
    def unknown_method(method):
        return Error.build(9001, 'A request with unknown method is made', {'method': method})

