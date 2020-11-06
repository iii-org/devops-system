from model import db, TableTestResult
from .util import Util
import datetime
import json
import logging, config

logger = logging.getLogger(config.get('LOGGER_NAME'))


class TestResult(object):

    def __init__(self):
        pass

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
            Util.call_sqlalchemy(cmd)
            return Util.success()
        except Exception as e:
            return Util.respond(400, e.__str__())

    def get_report(self, project_id):
        try:
            result = db.engine.execute(
                'SELECT report FROM test_results WHERE project_id={0} ORDER BY id DESC LIMIT 1'
                    .format(project_id))
            if result.rowcount == 0:
                return Util.respond(400, 'No postman report for this project.')
            report = result.fetchone()['report']
            if report is None:
                return Util.respond(400, 'No postman report for this project.')
            return Util.success(json.loads(report))
        except Exception as e:
            return Util.respond(400, e.__str__())
