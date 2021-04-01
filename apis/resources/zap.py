from datetime import datetime

from flask_jwt_extended import jwt_required
from flask_restful import Resource, reqparse

import model
import util
from resources import role


def zap_start_scan(args):
    new = model.Zap(
        project_name=args['project_name'],
        branch=args['branch'],
        commit_id=args['commit_id'],
        status='Scanning',
        result=None,
        full_log=None,
        run_at=datetime.now()
    )
    model.db.session.add(new)
    model.db.session.commit()
    return new.id


def zap_finish_scan(args):
    row = model.Zap.query.filter_by(
        id=args['test_id']
    ).one()
    row.status = 'Finished'
    row.result = args['result']
    row.full_log = args['full_log']
    model.db.session.add(row)
    model.db.session.commit()


# --------------------- Resources ---------------------
class Zap(Resource):
    @jwt_required
    def post(self):
        parser = reqparse.RequestParser()
        parser.add_argument('project_name', type=str)
        parser.add_argument('branch', type=str)
        parser.add_argument('commit_id', type=str)
        args = parser.parse_args()
        role.require_in_project(project_name=args['project_name'])
        id = zap_start_scan(args)
        return util.success({'test_id': id})

    @jwt_required
    def put(self):
        parser = reqparse.RequestParser()
        parser.add_argument('test_id', type=int)
        parser.add_argument('result', type=str)
        parser.add_argument('full_log', type=str)
        args = parser.parse_args()
        test_id = args['test_id']
        project_name = model.Zap.query.filter_by(id=test_id).one().project_name
        role.require_in_project(project_name=project_name)
        zap_finish_scan(args)
        return util.success()
