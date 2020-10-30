class Error:

    @staticmethod
    def detail(error, details):
        error['details'] = details
        return error

    # Project errors
    IDENTIFIER_HAS_BEEN_TAKEN = {'code': 1001, 'message': 'Project identifier has been taken'}
    # Third party service errors
    REDMINE_RESPONSE_ERROR = {'code': 8001, 'message': 'Redmine responds error'}
    # Internal errors
    UNKNOWN_METHOD = {'code': 9001, 'message': 'A request with unknown method is made'}

    # User errors
    @staticmethod
    def user_not_found(user_id):
        return {'code': 2001, 'message': 'User is not found', 'details': {'user_id': user_id}}