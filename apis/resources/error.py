class Error:

    @staticmethod
    def detail(error, details):
        error['details'] = details
        return error

    # Project errors
    @staticmethod
    def identifier_has_been_token(identifier):
        return {'code': 1001, 'message': 'Project identifier has been taken',
                'details': {'identifier': identifier}}

    # Third party service errors
    @staticmethod
    def redmine_error(response):
        return {'code': 8001, 'message': 'Redmine responds error',
                'details': response}

    # Internal errors
    @staticmethod
    def unknown_method(method):
        return {'code': 9001, 'message': 'A request with unknown method is made',
                'details': {'method': method}}

    # User errors
    @staticmethod
    def user_not_found(user_id):
        return {'code': 2001, 'message': 'User is not found', 'details': {'user_id': user_id}}