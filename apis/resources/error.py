class Error:

    @staticmethod
    def attach_details(error, details):
        error['details'] = details
        return error

    # Project errors
    IDENTIFIER_HAS_BEEN_TAKEN = {'code': 1001, 'message': 'Project identifier has been taken.'}
    # Third party service errors
    REDMINE_RESPONSE_ERROR = {'code': 2001, 'message': 'Redmine responds error.'}
    # Internal errors
    UNKNOWN_METHOD = {'code': 9001, 'message': 'A request with unknown method is made.'}
