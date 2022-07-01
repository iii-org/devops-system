import json
from datetime import datetime, timedelta

from flask_jwt_extended import jwt_required
from flask_restful import Resource, reqparse
from sqlalchemy import desc

import model
import nexus
import util
from resources import role, gitlab


def zap_start_scan(args):
    # Abort previous scans of the same branch
    prev_scans = model.Zap.query.filter_by(
        project_name=args['project_name'],
        branch=args['branch']).all()
    for prev in prev_scans:
        if prev.status == 'Scanning':
            prev.status = 'Aborted'
    model.db.session.commit()

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
    row.finished_at = datetime.now()
    model.db.session.add(row)
    model.db.session.commit()


def zap_get_tests(project_id):
    project_name = nexus.nx_get_project(id=project_id).name
    rows = model.Zap.query.filter_by(project_name=project_name).all()
    ret = []
    for row in rows:
        ret.append(process_row(row, project_id))
    return ret


def zap_get_test_by_commit(project_id, commit_id):
    project_name = nexus.nx_get_project(id=project_id).name
    row = model.Zap.query.filter(
        model.Zap.project_name == project_name,
        model.Zap.commit_id.like(f'{commit_id}%')
    ).order_by(desc(model.Zap.id)).first()
    if row is not None:
        return process_row(row, project_id)
    else:
        return {}


def zap_get_latest_test(project_id):
    project_name = nexus.nx_get_project(id=project_id).name
    row = model.Zap.query.filter_by(
        project_name=project_name).order_by(desc(model.Zap.id)).first()
    if row is None:
        return {}
    ret = process_row(row, project_id)
    del ret['full_log']
    return ret


def zap_get_latest_full_log(project_name):
    row = model.Zap.query.filter_by(
        project_name=project_name).order_by(desc(model.Zap.id)).first()
    if row is None:
        return None
    return row.full_log


def process_row(row, project_id):
    # 12 hour timeout
    if row.status == 'Scanning' and \
        datetime.now() - row.run_at > timedelta(hours=12):
        row.status = 'Failed'
        model.db.session.commit()
    r = json.loads(str(row))
    r['issue_link'] = gitlab.commit_id_to_url(project_id, r['commit_id'])
    return r

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
        return util.success({'test_id': zap_start_scan(args)})

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

    @jwt_required
    def get(self, project_id):
        role.require_in_project(project_id=project_id)
        return util.success(zap_get_tests(project_id))
