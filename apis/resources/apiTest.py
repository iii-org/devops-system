import ast
import datetime
import json

from flask_jwt_extended import jwt_required
from flask_restful import reqparse, Resource
from sqlalchemy import desc

import model
import util as util
from model import db
from resources import gitlab
from resources.apiError import DevOpsError

HTTP_TYPES = {"1": "request", "2": "response"}
HTTP_METHODS = {"1": "GET", "2": "POST", "3": "PUT", "4": "DELETE"}
HTTP_LOCATIONS = {"1": "header", "2": "body"}
TEST_CASE_TYPES = {1: "API"}


def deal_with_TestCaseObject(orm_row):
    output = {'id': orm_row.id,
              'name': orm_row.name,
              'project_id': orm_row.project_id,
              'issue_id': orm_row.issue_id,
              'type_id': orm_row.type_id,
              'type': TEST_CASE_TYPES[orm_row.type_id],
              'description': orm_row.description,
              'data': json.loads(orm_row.data),
              'update_at': util.date_to_str(orm_row.update_at),
              'create_at': util.date_to_str(orm_row.create_at)}
    return output


def deal_with_fetchall(data):
    output = []
    for row in data:
        output.append(deal_with_TestCaseObject(row))
    return output


def get_test_case_by_tc_id(testcase_id):
    row = model.TestCases.query.filter_by(id=testcase_id).filter(
        model.TestCases.disabled.isnot(True)).one()
    return deal_with_TestCaseObject(row)


# 將 TestCase 隱藏
def del_testcase_by_tc_id(testcase_id):
    t = model.TestCases.query.filter_by(id=testcase_id).filter(
        model.TestCases.disabled.isnot(True)).one()
    t.disabled = True
    t.update_at = datetime.datetime.now()
    db.session.commit()
    output = {'id': t.id, 'update_at': util.date_to_str(t.update_at)}
    return output


def modify_testCase_by_tc_id(testcase_id, args):
    t = model.TestCases.query.filter_by(id=testcase_id).one()
    t.data = json.dumps(ast.literal_eval(args['data']))
    t.name = args['name']
    t.description = args['description']
    t.type_id = args['type_id']
    t.update_at = datetime.datetime.now()
    db.session.commit()
    output = {'id': t.id, 'update_at': util.date_to_str(t.update_at)}
    return output


def get_testcase_by_column(args):
    if args['issue_id'] is not None:
        rows = model.TestCases.query.filter_by(
            issue_id=args['issue_id']).filter(
            model.TestCases.disabled.isnot(True)).order_by(model.Project.id).all()
    elif args['project_id'] is not None:
        rows = model.TestCases.query.filter_by(
            project_id=args['project_id']).filter(
            model.TestCases.disabled.isnot(True)).order_by(model.Project.id).all()
    else:
        return {}
    return deal_with_fetchall(rows)


def get_testcase_by_issue_id(issue_id):
    rows = model.TestCases.query.filter_by(issue_id=issue_id).filter(
        model.TestCases.disabled.isnot(True)
    ).all()
    return deal_with_fetchall(rows)


def get_testcase_by_project_id(project_id):
    rows = model.TestCases.query.filter_by(project_id=project_id).filter(
        model.TestCases.disabled.isnot(True)
    ).all()
    return deal_with_fetchall(rows)


def post_testcase_by_issue_id(issue_id, args):
    new = model.TestCases(
        issue_id=issue_id,
        project_id=args['project_id'],
        data=json.dumps(ast.literal_eval(args['data'])),
        name=args['name'],
        description=args['description'],
        type_id=args['type_id'],
        create_at=datetime.datetime.now(),
        update_at=datetime.datetime.now(),
        disabled=False
    )
    db.session.add(new)
    db.session.commit()
    return {'testCase_id': new.id}


def post_testcase_by_project_id(project_id, args):
    new = model.TestCases(
        project_id=project_id,
        data=json.dumps(ast.literal_eval(args['data'])),
        name=args['name'],
        description=args['description'],
        type_id=args['type_id'],
        create_at=datetime.datetime.now(),
        update_at=datetime.datetime.now(),
        disabled=False
    )
    db.session.add(new)
    db.session.commit()
    return {'testCase_id': new.id}


def get_api_method():
    output = []
    for key in HTTP_METHODS:
        output.append({"Http_Method_id": int(key), "name": HTTP_METHODS[key]})
    return output


def get_testcase_type_wrapped():
    output = []
    for key in TEST_CASE_TYPES:
        output.append({"test_case_type_id": int(key), "name": TEST_CASE_TYPES[key]})
    return output


def deal_with_TestItemObject(sql_row):
    output = {'id': sql_row.id, 'name': sql_row.name, 'project_id': sql_row.project_id,
              'issue_id': sql_row.issue_id, 'testCase_id': sql_row.test_case_id,
              'is_passed': sql_row.is_passed, 'update_at': util.date_to_str(sql_row.update_at),
              'create_at': util.date_to_str(sql_row.create_at)}
    return output


def get_testitem_by_ti_id(testitem_id):
    row = model.TestItems.query.filter_by(id=testitem_id).filter(
        model.TestItems.disabled.isnot(True)
    ).one()
    return deal_with_TestItemObject(row)


def del_testItem_by_ti_id(testitem_id):
    row = model.TestItems.query.filter_by(id=testitem_id).one()
    row.disabled = True
    row.update_at = datetime.datetime.now()
    db.session.commit()
    output = {'id': row.id, 'update_at': util.date_to_str(row.update_at)}
    return output


def modify_testItem_by_ti_id(testitem_id, args):
    t = model.TestItems.query.filter_by(id=testitem_id).one()
    t.name = args['name']
    t.is_passed = args['is_passed']
    t.update_at = datetime.datetime.now()
    db.session.commit()
    return {'id': t.id, 'update_at': util.date_to_str(t.update_at)}


def get_testItem_by_testCase_id(testcase_id):
    rows = model.TestItems.query.filter_by(test_case_id=testcase_id).filter(
        model.TestItems.disabled.isnot(True)
    ).all()
    output = []
    for row in rows:
        output.append(deal_with_TestItemObject(row))
    return output


def post_testitem_by_testcase_id(testcase_id, args):
    new = model.TestItems(
        test_case_id=testcase_id,
        project_id=args['project_id'],
        issue_id=args['issue_id'],
        name=args['name'],
        is_passed=args['is_passed'],
        create_at=datetime.datetime.now(),
        update_at=datetime.datetime.now(),
        disabled=False
    )
    db.session.add(new)
    db.session.commit()
    return {'testItem_id': new.id}


def get_testItem_by_issue_id(issue_id, order_column):
    rows = model.TestItems.query.filter_by(
        issue_id=issue_id).filter(model.TestItems.disabled.isnot(True)).order_by(order_column)
    output = []
    for row in rows:
        output.append(deal_with_TestItemObject(row))
    return output


def get_testItem_by_project_id(project_id, order_column):
    rows = model.TestItems.query.filter_by(
        project_id=project_id).filter(
        model.TestItems.disabled.isnot(True)).order_by(order_column)
    output = []
    for row in rows:
        output.append(deal_with_TestItemObject(row))
    return output


def get_testItem_by_Column(args, order_column=''):
    if not args['issue_id']:
        return get_testItem_by_issue_id(args['issue_id'], order_column)
    elif not args['project_id']:
        return get_testItem_by_project_id(args['project_id'], 'test_case_id')
    else:
        return {}


def deal_with_TestValueObject(sql_row):
    output = {'id': sql_row.id, 'project_id': sql_row.project_id, 'issue_id': sql_row.issue_id,
              'test_case_id': sql_row.test_case_id, 'test_item_id': sql_row.test_item_id,
              'type_id': sql_row.type_id, 'location_id': sql_row.location_id, 'key': sql_row.key,
              'value': sql_row.value, 'update_at': util.date_to_str(sql_row.update_at),
              'create_at': util.date_to_str(sql_row.create_at)}
    return output


def get_testValue_httpType():
    output = []
    for key in HTTP_TYPES:
        output.append({'type_id': int(key), "type_name": HTTP_TYPES[key]})
    return output


def get_testValue_httpLocation():
    output = []
    for key in HTTP_LOCATIONS:
        output.append({'location_id': int(key), "type_name": HTTP_LOCATIONS[key]})
    return output


def get_testValue_by_tv_id(value_id):
    row = model.TestValues.query.filter_by(id=value_id).filter(
        model.TestValues.disabled.isnot(True)
    ).one()
    return deal_with_TestValueObject(row)


def del_testValue_by_tv_id(value_id):
    row = model.TestValues.query.filter_by(id=value_id).filter(
        model.TestValues.disabled.isnot(True)).one()
    row.disabled = True
    row.update_at = datetime.datetime.now()
    db.session.commit()
    return {'id': row.id, 'update_at': util.date_to_str(row.update_at)}


def modify_test_value(value_id, args):
    v = model.TestValues.query.filter_by(id=value_id).one()
    v.key = args['key'],
    v.value = args['value'],
    v.type_id = args['type_id'],
    v.location_id = args['location_id'],
    v.update_at = datetime.datetime.now()
    db.session.commit()
    return {'id': v.id, 'update_at': util.date_to_str(v.update_at)}


def get_testValue_by_testItem_id(item_id, order_column='id'):
    rows = model.TestValues.query.filter_by(test_item_id=item_id).filter(
        model.TestValues.disabled.isnot(True)). \
        order_by(order_column).all()
    output = []
    for row in rows:
        output.append(deal_with_TestValueObject(row))
    return output


def post_testValue_by_testItem_id(item_id, args):
    new = model.TestValues(
        type_id=args['type_id'],
        key=args['key'],
        value=args['value'],
        location_id=args['location_id'],
        test_item_id=item_id,
        test_case_id=args['testCase_id'],
        issue_id=args['issue_id'],
        project_id=args['project_id'],
        disabled=False,
        create_at=datetime.datetime.now(),
        update_at=datetime.datetime.now(),
    )
    db.session.add(new)
    db.session.commit()
    return {'testValue_id': new.id}


def get_testValue_by_issue_id(issue_id, order_column=''):
    query = model.TestValues.query.filter_by(issue_id=issue_id).filter(
        model.TestValues.disabled.isnot(True))
    if order_column != '':
        query = query.order_by(order_column)
    rows = query.all()
    output = []
    for row in rows:
        output.append(deal_with_TestValueObject(row))
    return output


def get_testValue_by_project_id(project_id, order_column=''):
    query = model.TestValues.query.filter_by(project_id=project_id).filter(
        model.TestValues.disabled.isnot(True))
    if order_column != '':
        query = query.order_by(order_column)
    rows = query.all()
    output = []
    for row in rows:
        output.append(deal_with_TestValueObject(row))
    return output


def get_testValue_by_Column(args, order_column=''):
    if args['issue_id'] is not None:
        return get_testValue_by_issue_id(args['issue_id'], order_column)

    elif args['project_id'] is not None:
        return get_testValue_by_project_id(args['project_id'], order_column)
    else:
        return {}


def get_report(id):
    row = model.TestResults.query.filter_by(id=id).one()
    report = row.report
    if report is None or report == 'undefined':  # Yet runner complete or corrupted data by old runners
        return util.respond(204)
    return util.success(json.loads(report))


def list_results(project_id):
    rows = model.TestResults.query.filter_by(project_id=project_id).order_by(desc(
        model.TestResults.id)).all()
    ret = []
    for row in rows:
        scan = {
            'id': row.id,
            'branch': row.branch,
            'commit_id': row.commit_id[0:7],
            'commit_url': gitlab.commit_id_to_url(project_id, row.commit_id),
            'run_at': str(row.run_at)
        }
        if row.total is None:
            scan['success'] = None
            scan['failure'] = None
        else:
            scan['success'] = row.total - row.fail
            scan['failure'] = row.fail
        ret.append(scan)
    return ret


# --------------------- Resources ---------------------
class TestCaseByIssue(Resource):

    # 用issues ID 取得目前所有的目前測試案例
    @jwt_required
    def get(self, issue_id):
        output = get_testcase_by_issue_id(issue_id)
        return util.success(output)

    # 用issues ID 新建立測試案例
    @jwt_required
    def post(self, issue_id):
        parser = reqparse.RequestParser()
        parser.add_argument('project_id', type=int)
        parser.add_argument('name', type=str)
        parser.add_argument('data', type=str)
        parser.add_argument('type_id', type=int)
        parser.add_argument('description', type=str)
        args = parser.parse_args()
        output = post_testcase_by_issue_id(issue_id, args)
        return util.success(output)


class TestCaseByProject(Resource):

    # 用issues ID 取得目前所有的目前測試案例
    @jwt_required
    def get(self, project_id):
        output = get_testcase_by_project_id(project_id)
        return util.success(output)

    # 用issues ID 新建立測試案例
    @jwt_required
    def post(self, project_id):
        parser = reqparse.RequestParser()
        parser.add_argument('name', type=str)
        parser.add_argument('data', type=str)
        parser.add_argument('type_id', type=int)
        parser.add_argument('description', type=str)
        args = parser.parse_args()
        output = post_testcase_by_project_id(project_id, args)
        return util.success(output)


# noinspection PyPep8Naming
class TestCase(Resource):

    # 用testCase_id 取得目前測試案例
    @jwt_required
    def get(self, testCase_id):
        output = get_test_case_by_tc_id(testCase_id)
        return util.success(output)

    # 用testCase_id 刪除目前測試案例
    @jwt_required
    def delete(self, testCase_id):
        output = del_testcase_by_tc_id(testCase_id)
        return util.success(output)

    # 用testCase_id 更新目前測試案例
    @jwt_required
    def put(self, testCase_id):
        parser = reqparse.RequestParser()
        parser.add_argument('data')
        parser.add_argument('name', type=str)
        parser.add_argument('type_id', type=int)
        parser.add_argument('description', type=str)
        args = parser.parse_args()
        output = modify_testCase_by_tc_id(testCase_id, args)
        return util.success(output)


class GetTestCaseAPIMethod(Resource):
    @jwt_required
    def get(self):
        output = get_api_method()
        return util.success(output)


class GetTestCaseType(Resource):
    @jwt_required
    def get(self):
        output = get_testcase_type_wrapped()
        return util.success(output)


# noinspection PyPep8Naming
class TestItemByTestCase(Resource):

    # 用issues ID 取得目前所有的目前測試案例
    @jwt_required
    def get(self, testCase_id):
        output = get_testItem_by_testCase_id(testCase_id)
        return util.success(output)

    # 用issues ID 新建立測試案例
    @jwt_required
    def post(self, testCase_id):
        parser = reqparse.RequestParser()
        parser.add_argument('project_id', type=int)
        parser.add_argument('name', type=str)
        parser.add_argument('issue_id', type=int)
        parser.add_argument('is_passed', type=bool)
        args = parser.parse_args()
        output = post_testitem_by_testcase_id(testCase_id, args)
        return util.success(output)


class TestItem(Resource):

    # item_id 取得目前測試項目
    @jwt_required
    def get(self, item_id):
        output = get_testitem_by_ti_id(item_id)
        return util.success(output)

    # item_id 刪除目前測試項目
    @jwt_required
    def delete(self, item_id):
        output = del_testItem_by_ti_id(item_id)
        return util.success(output)

    # item_id 更新目前測試項目
    @jwt_required
    def put(self, item_id):
        parser = reqparse.RequestParser()
        parser.add_argument('name', type=str)
        parser.add_argument('is_passed', type=bool)
        args = parser.parse_args()
        output = modify_testItem_by_ti_id(item_id, args)
        return util.success(output)


class TestValueByTestItem(Resource):

    # 用issues ID 取得目前所有的目前測試案例
    @jwt_required
    def get(self, item_id):
        output = get_testValue_by_testItem_id(item_id)
        return util.success(output)

    # 用issues ID 新建立測試案例
    @jwt_required
    def post(self, item_id):
        parser = reqparse.RequestParser()
        parser.add_argument('project_id', type=int)
        parser.add_argument('issue_id', type=int)
        parser.add_argument('testCase_id', type=int)
        parser.add_argument('type_id', type=int)
        parser.add_argument('location_id', type=int)
        parser.add_argument('key', type=str)
        parser.add_argument('value', type=str)
        args = parser.parse_args()
        output = post_testValue_by_testItem_id(item_id, args)
        return util.success(output)


class GetTestValueLocation(Resource):
    @jwt_required
    def get(self):
        output = get_testValue_httpLocation()
        return util.success(output)


class GetTestValueType(Resource):
    @jwt_required
    def get(self):
        output = get_testValue_httpType()
        return util.success(output)


class TestValue(Resource):

    @jwt_required
    def get(self, value_id):
        output = get_testValue_by_tv_id(value_id)
        return util.success(output)

    @jwt_required
    def delete(self, value_id):
        output = del_testValue_by_tv_id(value_id)
        return util.success(output)

    @jwt_required
    def put(self, value_id):
        parser = reqparse.RequestParser()
        parser.add_argument('key', type=str)
        parser.add_argument('value', type=str)
        parser.add_argument('type_id', type=str)
        parser.add_argument('location_id', type=str)
        args = parser.parse_args()
        output = modify_test_value(value_id, args)
        return util.success(output)
