from model import db, TableTestResult
from .util import util
import datetime
import logging

logger = logging.getLogger('devops.api')


class TestResult(object):
    headers = {'Content-Type': 'application/json'}

    def save(self, args):
        try:
            if 'branch' in args:
                branch = args['branch']
            else:
                branch = None
            cmd = db.insert(TableTestResult.stru_testResult).values(
                project_id=args['project_id'],
                total=args['total'],
                fail=args['fail'],
                branch=branch,
                report=args['report'],
                run_at=datetime.datetime.now()
            )
            util.callsqlalchemy(cmd, logger)
            return {"message": "success"}, 200
        except Exception as e:
            return {"message": e.__str__()}, 400
