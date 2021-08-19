from flask_jwt_extended import jwt_required
from flask_restful import Resource, reqparse

import model
import resources.project as project
import resources.issue as issue

from resources.issue import NexusIssue
import util as util
from model import db, TraceOrder
import resources.apiError as apiError 
from resources.apiError import DevOpsError
from sqlalchemy.orm.exc import NoResultFound
from accessories import redmine_lib
from resources.redmine import redmine

'''
order_mapping
"Epic": 需求規格
"Audit": 合規需求
"Feature": 功能設計
"Bug": 程式錯誤
"Issue": 議題
"Change Request": 變更需求
"Risk": 風險管理
"Test Plan": 測試計畫
'''

def validate_order_value(order):
    validate_order_list = [
        {
            "condition": not all(x in ['Epic', 'Audit', 'Feature', 'Bug', 'Issue', 'Change Request', 'Risk', 'Test Plan'] for x in order), 
            "log": "Order's elements must be in ['Epic', 'Audit', 'Feature', 'Bug', 'Issue', 'Change Request', 'Risk', 'Test Plan']",
        },
        {"condition": len(order) != len(set(order)), "log": "Elements must not be duplicated"},
        {"condition": not len(order) <= 5, "log": "Numbers of order's elements must be in range [0, 5]"},
    ]
    for validate_order in validate_order_list:
        if validate_order["condition"]:
            raise DevOpsError(400, validate_order["log"],
                              error=apiError.argument_error('order'))

def get_trace_order_by_project(project_id):
    if util.is_dummy_project(project_id):
        return []
    try:
        project.get_plan_project_id(project_id)
    except NoResultFound:
        raise DevOpsError(404, "Error while getting trace_orders.",
                          error=apiError.project_not_found(project_id))
    rows = TraceOrder.query.filter_by(project_id=project_id).all()
    return {"trace_order_list": [
        {
            "id": row.id,
            "name": row.name,
            "order": row.order,
        } for row in rows
    ]}

def create_trace_order_by_project(project_id, args):
    order = args["order"]
    validate_order_value(order)

    new = TraceOrder(
        name=args["name"],
        order=order,
        project_id=project_id,
    )
    db.session.add(new)
    db.session.commit()
    return {"trace_order_id": new.id}

def update_trace_order(trace_order_id, args):
    trace_order = model.TraceOrder.query.get(trace_order_id)

    order = args.get("order")
    if order is not None:
        validate_order_value(order)
        trace_order.order = order

    trace_order.name = args.get("name", trace_order.name)
    db.session.commit()

# --------------------- Resources ---------------------
class ProjectTraceOrder(Resource):
    def get(self, project_id):
        return util.success(get_trace_order_by_project(project_id))

    @jwt_required
    def post(self, project_id):
        parser = reqparse.RequestParser()
        parser.add_argument('name', type=str, required=True)
        parser.add_argument('order', type=str, action='append', required=True)
        args = parser.parse_args()
        return util.success(create_trace_order_by_project(project_id, args))


class SingleTraceOrder(Resource):
    @jwt_required
    def patch(self, trace_order_id):
        parser = reqparse.RequestParser()
        parser.add_argument('name', type=str)
        parser.add_argument('order', type=str, action='append')
        args = parser.parse_args()
        args = {k: v for k, v in args.items() if v is not None}
        return util.success(update_trace_order(trace_order_id, args))

    @jwt_required
    def delete(self, trace_order_id):
        trace_order = TraceOrder.query.filter_by(id=trace_order_id).one()
        db.session.delete(trace_order)
        db.session.commit()
        return util.success()
