class Error:

    @staticmethod
    def attach_details(error, details):
        error['details'] = details

    IDENTIFIER_HAS_BEEN_TAKEN = {'code': 1001, 'message': 'Project identifier has been taken.'}
    UNKNOWN_METHOD = {'code': 9001, 'message': 'A request with unknown method is made.'}
