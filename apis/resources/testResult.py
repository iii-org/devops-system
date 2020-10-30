from model import db, TableTestResult
from .util import util
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
            util.callsqlalchemy(cmd, logger)
            return util.success()
        except Exception as e:
            return util.respond(400, e.__str__())

    def get_report(self, project_id):
        try:
            result = db.engine.execute(
                'SELECT report FROM test_results WHERE project_id={0} ORDER BY id DESC LIMIT 1'
                    .format(project_id))
            if result.rowcount == 0:
                return util.respond(400, 'No postman report for this project.')
            report = result.fetchone()['report']
            if report is None:
                return util.respond(400, 'No postman report for this project.')
            return util.success(json.loads(report))
        except Exception as e:
            return util.respond(400, e.__str__())
