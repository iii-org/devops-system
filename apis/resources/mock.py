from concurrent import futures
from threading import Thread

from flask import current_app
from flask_restful import Resource, reqparse

import util
from resources.gitlab import gitlab
from resources.redmine import redmine
from util import DevOpsThread


def mock_cm_status(status):
    if status == 1:
        return {"message": "success",
                "data": {
                    "test_results": {
                        "postman": {
                            "passed": 0,
                            "failed": 3,
                            "total": 3
                        },
                        "checkmarx": {
                            "message": "The scan is not completed yet.",
                            "status": 1
                        }
                    }
                }}, 200
    if status == 2:
        return {"message": "success",
                "data": {
                    "test_results": {
                        "postman": {
                            "passed": 0,
                            "failed": 3,
                            "total": 3
                        },
                        "checkmarx": {
                            "message": "The report is not ready yet.",
                            "status": 2,
                            "highSeverity": 0,
                            "mediumSeverity": 0,
                            "lowSeverity": 2,
                            "infoSeverity": 0,
                            "statisticsCalculationDate": "2020-11-24T15:06:19.283"
                        }
                    }
                }}, 200
    if status == 3:
        return {"message": "success",
                "data": {
                    "test_results": {
                        "postman": {
                            "passed": 0,
                            "failed": 3,
                            "total": 3
                        },
                        "checkmarx": {
                            "message": "success",
                            "status": 3,
                            "highSeverity": 0,
                            "mediumSeverity": 0,
                            "lowSeverity": 2,
                            "infoSeverity": 0,
                            "statisticsCalculationDate": "2020-11-24T10:49:33.07",
                            "run_at": "2020-11-24 10:47:53.165285",
                            "report_id": 5053
                        }
                    }
                }}, 200


def mock_sesame_get():
    return None


# ----------- Resources -----------

# noinspection PyMethodMayBeStatic
class MockTestResult(Resource):
    def get(self):
        parser = reqparse.RequestParser()
        parser.add_argument('cm_status', type=int)
        args = parser.parse_args()

        if 'cm_status' in args:
            return mock_cm_status(args['cm_status'])

        return util.respond(404, 'No suck muck.')


class MockSesame(Resource):
    def get(self):
        args = {
            'name': 'ro-test-token',
            'description': ''
        }
        ret = gitlab.gl_create_access_token(759)
        return ret
