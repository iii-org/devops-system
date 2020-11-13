import logging
from logging import handlers

from flask_jwt_extended import get_jwt_identity


class DevOpsFilter(logging.Filter):
    def filter(self, record):
        record.user_id = None
        record.user_name = None
        jwt = get_jwt_identity()
        print(jwt)
        if jwt is not None:
            record.user_id = jwt['user_id']
            record.user_name = jwt['user_account']
        return True


handler = handlers.TimedRotatingFileHandler(
    'devops-api.log', when='D', interval=1, backupCount=14)
handler.setFormatter(logging.Formatter(
    '%(asctime)s %(user_id)d %(user_name)s %(filename)s'
    ' [line:%(lineno)d] %(levelname)s %(message)s',
    '%Y %b %d, %a %H:%M:%S'))
logger = logging.getLogger('devops.api')
logger.addFilter(DevOpsFilter())
logger.setLevel(logging.DEBUG)
logger.addHandler(handler)
