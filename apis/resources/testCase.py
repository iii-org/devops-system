from model import db, TableTestCase, TableCaseType, TableHttpMethod
from .util import Util
import json
import datetime
import logging
import ast

logger = logging.getLogger('devops.api')


def get_testcase_type():
    command = db.select([TableCaseType.stru_tcType])
    result = Util.call_sqlalchemy(command)
    ret_msgs = result.fetchall()
    case_type = {}
    for row in ret_msgs:
        case_type[row['id']] = row['name']
    return case_type


def deal_with_TestCaseObject(sql_row, case_type=''):
    if case_type == '':
        case_type = get_testcase_type()
    output = {'id': sql_row['id'], 'name': sql_row['name'], 'project_id': sql_row['project_id'],
              'issue_id': sql_row['issue_id'], 'type_id': sql_row['type_id'], 'type': case_type[sql_row['type_id']],
              'description': sql_row['description'], 'data': json.loads(sql_row['data']),
              'update_at': Util.date_to_str(sql_row['update_at']),
              'create_at': Util.date_to_str(sql_row['create_at'])}
    return output


def deal_with_fetchall(data, case_type=''):
    if case_type == '':
        case_type = get_testcase_type()
    output = []
    for row in data:
        output.append(deal_with_TestCaseObject(row, case_type))
    return output


class TestCase(object):
    httpMethod = {"1": "GET", "2": "POST", "3": "PUT", "4": "DELETE"}

    # 取得 TestCase  靠 test case id
    @staticmethod
    def get_test_case_by_tc_id(testcase_id):
        command = db.select([TableTestCase.stru_testCase]).where(db.and_(
            TableTestCase.stru_testCase.c.id == testcase_id, TableTestCase.stru_testCase.c.disabled is False))
        logger.debug("get_testCase_command: {0}".format(command))
        result = Util.call_sqlalchemy(command)
        row = result.fetchone()
        output = deal_with_TestCaseObject(row)
        return output

    # 將 TestCase 隱藏
    @staticmethod
    def del_testcase_by_tc_id(testcase_id):
        command = db.update(TableTestCase.stru_testCase).where(
            db.and_(TableTestCase.stru_testCase.c.id == testcase_id)).values(
            disabled=True,
            update_at=datetime.datetime.now()
        ).returning(TableTestCase.stru_testCase.c.update_at, TableTestCase.stru_testCase.c.id)
        logger.debug("update_testCase_command: {0}".format(command))
        result = Util.call_sqlalchemy(command)
        ret_msg = result.fetchone()
        output = {'id': ret_msg['id'], 'update_at': Util.date_to_str(ret_msg['update_at'])}
        return output

    # 修改 TestCase 內資訊
    @staticmethod
    def modify_testCase_by_tc_id(testcase_id, args):
        command = db.update(TableTestCase.stru_testCase).where(
            db.and_(TableTestCase.stru_testCase.c.id == testcase_id)).values(
            data=json.dumps(ast.literal_eval(args['data'])),
            name=args['name'],
            description=args['description'],
            type_id=args['type_id'],
            update_at=datetime.datetime.now()
        ).returning(TableTestCase.stru_testCase.c.update_at, TableTestCase.stru_testCase.c.id)
        logger.debug("update_testCase_command: {0}".format(command))
        result = Util.call_sqlalchemy(command)
        ret_msg = result.fetchone()
        output = {'id': ret_msg['id'], 'update_at': Util.date_to_str(ret_msg['update_at'])}
        return output

    @staticmethod
    def get_testcase_by_column(args):
        if args['issue_id'] is not None:
            command = db.select([TableTestCase.stru_testCase]).where(db.and_(
                TableTestCase.stru_testCase.c.issue_id == args['issue_id'],
                TableTestCase.stru_testCase.c.disabled is False)).order_by('project_id')
        elif args['project_id'] is not None:
            command = db.select([TableTestCase.stru_testCase]).where(db.and_(
                TableTestCase.stru_testCase.c.project_id == args['project_id'],
                TableTestCase.stru_testCase.c.disabled is False)).order_by('project_id')
        else:
            return {}
        result = Util.call_sqlalchemy(command)
        ret_msgs = result.fetchall()
        return deal_with_fetchall(ret_msgs)

    # 取得同Issue Id 內  TestCase 的所有資訊
    @staticmethod
    def get_testcase_by_issue_id(issue_id):
        command = db.select([TableTestCase.stru_testCase]).where(db.and_(
            TableTestCase.stru_testCase.c.issue_id == issue_id, TableTestCase.stru_testCase.c.disabled is False))
        logger.debug("get_testCase_command: {0}".format(command))
        result = Util.call_sqlalchemy(command)
        ret_msgs = result.fetchall()
        return deal_with_fetchall(ret_msgs)

    @staticmethod
    def get_testcase_by_project_id(project_id):
        command = db.select([TableTestCase.stru_testCase]).where(db.and_(
            TableTestCase.stru_testCase.c.project_id == project_id, TableTestCase.stru_testCase.c.disabled is False))
        logger.debug("get_testCase_command: {0}".format(command))
        result = Util.call_sqlalchemy(command)
        ret_msgs = result.fetchall()
        return deal_with_fetchall(ret_msgs)

    # 新增同Issue Id 內  parameters 的資訊
    @staticmethod
    def post_testcase_by_issue_id(issue_id, args):
        command = db.insert(TableTestCase.stru_testCase).values(
            issue_id=issue_id,
            project_id=args['project_id'],
            data=json.dumps(ast.literal_eval(args['data'])),
            name=args['name'],
            description=args['description'],
            type_id=args['type_id'],
            create_at=datetime.datetime.now(),
            update_at=datetime.datetime.now()
        )
        ret_msg = Util.call_sqlalchemy(command)
        return {'testCase_id': ret_msg.inserted_primary_key}

    # 新增同Project Id 內 TestCase 的資訊
    @staticmethod
    def post_testcase_by_project_id(project_id, args):
        command = db.insert(TableTestCase.stru_testCase).values(
            project_id=project_id,
            data=json.dumps(ast.literal_eval(args['data'])),
            name=args['name'],
            description=args['description'],
            type_id=args['type_id'],
            create_at=datetime.datetime.now(),
            update_at=datetime.datetime.now()
        )
        ret_msg = Util.call_sqlalchemy(command)
        return {'testCase_id': ret_msg.inserted_primary_key}

    @staticmethod
    def get_api_method():
        output = []
        for key in TestCase.httpMethod:
            output.append({"Http_Method_id": int(key), "name": TestCase.httpMethod[key]})
        return output

    @staticmethod
    def get_testcase_type():
        support_type = get_testcase_type()
        output = []
        for key in support_type:
            output.append({"test_case_type_id": int(key), "name": support_type[key]})
        return output
