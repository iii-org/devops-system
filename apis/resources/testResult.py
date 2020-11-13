import config
import datetime
import json
import logging

from model import db, TableTestResult
import resources.apiError as apiError
import resources.util as util

from resources.logger import logger


def save(args):
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
        util.call_sqlalchemy(cmd)
        return util.success()
    except Exception as e:
        return util.respond(500, "Error when saving test results.",
                            error=apiError.uncaught_exception(e))


def get_report(project_id):
    try:
        result = db.engine.execute(
            'SELECT report FROM test_results WHERE project_id={0} ORDER BY id DESC LIMIT 1'
            .format(project_id))
        if result.rowcount == 0:
            return util.respond(404, 'No postman report for this project.')
        report = result.fetchone()['report']
        if report is None:
            return util.respond(404, 'No postman report for this project.')
        return util.success(json.loads(report))
    except Exception as e:
        return util.respond(500, "Error when saving test results.",
                            error=apiError.uncaught_exception(e))
