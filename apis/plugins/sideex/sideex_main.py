import json
from datetime import datetime, timedelta

from flask_jwt_extended import jwt_required
from flask_restful import Resource, reqparse
from sqlalchemy import desc

import model
import nexus
import util
from resources import role, gitlab
from resources.test_generated_issue import tgi_feed_sideex


def sd_start_test(args):
    # Abort previous scans of the same branch
    prev_scans = model.Sideex.query.filter_by(
        project_name=args['project_name'],
        branch=args['branch']).all()
    for prev in prev_scans:
        if prev.status == 'Scanning':
            prev.status = 'Aborted'
    model.db.session.commit()

    new = model.Sideex(
        project_name=args['project_name'],
        branch=args['branch'],
        commit_id=args['commit_id'],
        status='Scanning',
        result=None,
        report=None,
        run_at=datetime.now()
    )
    model.db.session.add(new)
    model.db.session.commit()
    return new.id


def sd_finish_test(args):
    row = model.Sideex.query.filter_by(
        id=args['test_id']
    ).one()
    row.status = 'Finished'
    row.result = args['result']
    row.report = args['report']
    row.finished_at = datetime.now()
    model.db.session.add(row)
    model.db.session.commit()
    tgi_feed_sideex(row)

    # Clean up old reports
    rows = model.Sideex.query.filter(
        model.Sideex.project_name == row.project_name,
        model.Sideex.branch == row.branch,
        model.Sideex.report.isnot(None)
    ).order_by(desc(model.Sideex.id)).all()
    for index, row in enumerate(rows):
        if index < 5:
            continue
        row.report = None
        model.db.session.commit()


def sd_get_tests(project_id):
    project_name = nexus.nx_get_project(id=project_id).name
    rows = model.Sideex.query.filter_by(project_name=project_name).all()
    ret = []
    for row in rows:
        ret.append(process_row(row, project_id))
    return ret


def sd_get_test_by_commit(project_id, commit_id):
    project_name = nexus.nx_get_project(id=project_id).name
    row = model.Sideex.query.filter_by(project_name=project_name,
                                       commit_id=commit_id).first()
    if row is not None:
        return process_row(row, project_id)
    else:
        return {}


def sd_get_latest_test(project_id):
    project_name = nexus.nx_get_project(id=project_id).name
    row = model.Sideex.query.filter_by(
        project_name=project_name).order_by(desc(model.Sideex.id)).first()
    if row is None:
        return {}
    return process_row(row, project_id)


def process_row(row, project_id):
    # 12 hour timeout
    if row.status == 'Scanning' and \
        datetime.now() - row.run_at > timedelta(hours=1):
        row.status = 'Failed'
        model.db.session.commit()
    r = json.loads(str(row))
    r['issue_link'] = gitlab.commit_id_to_url(project_id, r['commit_id'])
    return r


def sd_get_report(test_id):
    row = model.Sideex.query.filter_by(id=test_id).one()
    return row.report


# --------------------- Resources ---------------------
class Sideex(Resource):
    @jwt_required
    def post(self):
        parser = reqparse.RequestParser()
        parser.add_argument('project_name', type=str)
        parser.add_argument('branch', type=str)
        parser.add_argument('commit_id', type=str)
        args = parser.parse_args()
        role.require_in_project(project_name=args['project_name'])
        return util.success({'test_id': sd_start_test(args)})

    @jwt_required
    def put(self):
        parser = reqparse.RequestParser()
        parser.add_argument('test_id', type=int)
        parser.add_argument('result', type=str)
        parser.add_argument('report', type=str)
        args = parser.parse_args()
        test_id = args['test_id']
        project_name = model.Sideex.query.filter_by(id=test_id).one().project_name
        role.require_in_project(project_name=project_name)
        sd_finish_test(args)
        return util.success()

    @jwt_required
    def get(self, project_id):
        role.require_in_project(project_id=project_id)
        return util.success(sd_get_tests(project_id))


class SideexReport(Resource):
    @jwt_required
    def get(self, test_id):
        project_name = model.Sideex.query.filter_by(id=test_id).one().project_name
        role.require_in_project(project_name=project_name)
        return util.success(sd_get_report(test_id))


# --------------------- API router ---------------------
def router(api):
    api.add_resource(Sideex, '/sideex', '/project/<sint:project_id>/sideex')
    api.add_resource(SideexReport, '/sideex_report/<int:test_id>')
