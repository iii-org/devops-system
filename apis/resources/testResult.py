from model import db
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
            db.engine.execute(
                "INSERT INTO public.test_results "
                "(project_id, total, fail, branch, report, run_at) VALUES ({0}, {1}, {2}, '{3}', '{4}', '{5}')"
                .format(
                    args['project_id'],
                    args['total'],
                    args['fail'],
                    branch,
                    args['report'],
                    datetime.datetime.now()
                ))
            return {"message": "success"}, 200
        except Exception as e:
            return {"message": "error", "data": e.__str__()}, 400
