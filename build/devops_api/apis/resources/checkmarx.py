from model import db
import datetime
import logging

logger = logging.getLogger('devops.api')


class CheckMarx(object):
    headers = {'Content-Type': 'application/json'}

    def postReport(self, logger, args):
        try:
            db.engine.execute(
                "INSERT INTO public.checkmarx "
                "(cm_project_id, repo_id, scan_id, report_id, run_at) "
                "VALUES ({0}, {1}, {2}, {3}, {4})"
                .format(
                    args['cm_project_id'],
                    args['repo_id'],
                    args['scan_id'],
                    args['report_id'],
                    datetime.datetime.now()
                ))
            return {"message": "success"}, 200
        except Exception as e:
            return {"message": "error", "data": e.__str__()}, 400
