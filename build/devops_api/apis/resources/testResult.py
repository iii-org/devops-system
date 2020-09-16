from model import db
import datetime
import logging

logger = logging.getLogger('devops.api')


class TestResult(object):
    headers = {'Content-Type': 'application/json'}

    def save(self, args):
        try:
            db.engine.execute(
                "INSERT INTO public.test_results "
                "(project_id, total, fail, run_at) VALUES ({0}, {1}, {2}, '{3}')"
                .format(
                    args['project_id'],
                    args['total'],
                    args['fail'],
                    datetime.datetime.now()
                ))
            return {"message": "success"}, 200
        except Exception as e:
            return {"message": "error", "data": e.__str__()}, 400
