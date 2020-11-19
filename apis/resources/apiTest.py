import ast
import datetime
import json

from flask_jwt_extended import jwt_required
from flask_restful import reqparse, Resource

import model
import resources.util as util
from model import db
from resources import apiError
from resources.logger import logger

HTTP_TYPES = {"1": "request", "2": "response"}
HTTP_METHODS = {"1": "GET", "2": "POST", "3": "PUT", "4": "DELETE"}
HTTP_LOCATIONS = {"1": "header", "2": "body"}
FLOW_TYPES = {"0": "Given", "1": "When", "2": "Then", "3": "But", "4": "And"}
PARAMETER_TYPES = {'1': '文字', '2': '英數字', '3': '英文字', '4': '數字'}


def deal_with_json_string(json_string):
    return json.dumps(json.loads(json_string), ensure_ascii=False, separators=(',', ':'))


def deal_with_ParametersObject(sql_row):
    output = {'id': sql_row.id,
              'name': sql_row.name,
              'parameter_type_id': sql_row.parameter_type_id
              }
    if sql_row.parameter_type_id in PARAMETER_TYPES:
        output['parameter_type'] = PARAMETER_TYPES[sql_row.parameter_type_id]
    else:
        output['parameter_type'] = 'None'
    output['description'] = sql_row.description
    output['limitation'] = sql_row.limitation
    output['length'] = sql_row.length
    output['update_at'] = sql_row.update_at.isoformat()
    output['create_at'] = sql_row.create_at.isoformat()
    return output


def get_parameters_by_param_id(parameters_id):
    row = model.Parameters.query.filter_by(id=parameters_id).first()
    output = deal_with_ParametersObject(row)
    return output


def del_parameters_by_param_id(parameters_id):
    row = model.Parameters.query.filter_by(id=parameters_id).first()
    row.disabled = True
    row.update_at = datetime.datetime.now()
    db.session.commit()
    return util.success()


def modify_parameters_by_param_id(parameters_id, args):
    row = model.Parameters.query.filter_by(id=parameters_id).first()
    row.update_at = datetime.datetime.now()
    row.parameter_type_id = args['parameter_type_id']
    row.name = args['name']
    row.description = args['description']
    row.limitation = args['limitation']
    row.length = args['length']
    return

    update_param_command = db.update(TableParameter.stru_param).where(
        db.and_(TableParameter.stru_param.c.id == parameters_id)).values(
    ).returning(TableParameter.stru_param.c.update_at)
    return util.call_sqlalchemy(update_param_command)


def get_parameters_by_issue_id(issue_id):
    get_param_command = db.select([TableParameter.stru_param]).where(
        db.and_(TableParameter.stru_param.c.issue_id == issue_id, TableParameter.stru_param.c.disabled == False))
    logger.debug("get_param_command: {0}".format(get_param_command))
    result = util.call_sqlalchemy(get_param_command)
    ret_msg = result.fetchall()
    output = []
    for row in ret_msg:
        output.append(deal_with_ParametersObject(row))
    return output


def post_parameters_by_issue_id(issue_id, args):
    insert_param_command = db.insert(TableParameter.stru_param).values(
        project_id=args['project_id'],
        issue_id=issue_id,
        parameter_type_id=args['parameter_type_id'],
        name=args['name'],
        description=args['description'],
        limitation=args['limitation'],
        length=args['length'],
        create_at=datetime.datetime.now(),
        update_at=datetime.datetime.now()
    )
    logger.debug("insert_user_command: {0}".format(insert_param_command))
    ret_msg = util.call_sqlalchemy(insert_param_command)
    return {'parameters_id': ret_msg.inserted_primary_key}


def get_parameter_types():
    output = []
    for key in PARAMETER_TYPES:
        temp = {"parameter_type_id": key, "name": PARAMETER_TYPES[key]}
        output.append(temp)
    return output


def get_flow_support_type():
    output = []
    for key in FLOW_TYPES:
        output.append({"flow_type_id": int(key), "name": FLOW_TYPES[key]})
    return output


def deal_with_flow_object(sql_row):
    return {'id': sql_row['id'],
            'project_id': sql_row['project_id'],
            'issue_id': sql_row['issue_id'],
            'requirement_id': sql_row['requirement_id'],
            'type_id': sql_row['type_id'],
            'name': sql_row['name'],
            'description': sql_row['description'],
            'serial_id': sql_row['serial_id'],
            'update_at': util.date_to_str(sql_row['update_at']),
            'create_at': util.date_to_str(sql_row['create_at'])
            }


# 取得 requirement 內的流程資訊
def get_flow_by_flow_id(flow_id):
    get_flow_command = db.select([
        TableFlow.stru_flow
    ]).where(db.and_(TableFlow.stru_flow.c.id == flow_id))
    logger.debug("get_flow_command: {0}".format(get_flow_command))
    result = util.call_sqlalchemy(get_flow_command)
    ret_msg = result.fetchone()
    return deal_with_flow_object(ret_msg)


# 將 requirement 隱藏
def disabled_flow_by_flow_id(flow_id):
    update_flow_command = db.update(TableFlow.stru_flow).where(
        db.and_(TableFlow.stru_flow.c.id == flow_id)).values(
        disabled=True,
        update_at=datetime.datetime.now())
    ret_msg = util.call_sqlalchemy(update_flow_command)
    return {'last_modified': ret_msg.last_updated_params()}


# 修改 requirement 內資訊
def modify_flow_by_flow_id(flow_id, args):
    update_flow_command = db.update(TableFlow.stru_flow).where(
        db.and_(TableFlow.stru_flow.c.id == flow_id)).values(
        type_id=args['type_id'],
        name=args['name'],
        description=args['description'],
        serial_id=args['serial_id'],
        update_at=datetime.datetime.now()
    ).returning(
        TableFlow.stru_flow.c.update_at)
    ret_msg = util.call_sqlalchemy(update_flow_command)
    return {'last_modified': ret_msg.last_updated_params()}


# 取得同Issue Id 內  requirements 的所有資訊
def get_flow_by_requirement_id(requirement_id):
    get_rqmt_command = db.select(
        [TableFlow.stru_flow]).where(
        db.and_(TableFlow.stru_flow.c.requirement_id == requirement_id,
                TableFlow.stru_flow.c.disabled == False))
    logger.debug("get_rqmt_command: {0}".format(get_rqmt_command))
    result = util.call_sqlalchemy(get_rqmt_command)
    ret_msgs = result.fetchall()
    output = []
    for ret_msg in ret_msgs:
        output.append(deal_with_flow_object(ret_msg))
    return output


# 新增同Issue Id 內  requirement 的資訊
def post_flow_by_requirement_id(issue_id, requirement_id, args):
    get_flow_command = db.select(
        [TableFlow.stru_flow.c.serial_id]).where(
        db.and_(TableFlow.stru_flow.c.requirement_id == requirement_id)).order_by(
        TableFlow.stru_flow.c.serial_id.asc())
    result = util.call_sqlalchemy(get_flow_command)
    flow_serial_ids = []
    if result is not None:
        ret_msgs = result.fetchall()
        for ret_msg in ret_msgs:
            flow_serial_ids.append(ret_msg['serial_id'])

    if not flow_serial_ids:
        serial_number = 1
    else:
        serial_number = max(flow_serial_ids) + 1
    insert_flow_command = db.insert(TableFlow.stru_flow).values(
        project_id=args['project_id'],
        issue_id=issue_id,
        requirement_id=requirement_id,
        type_id=args['type_id'],
        name=args['name'],
        description=args['description'],
        serial_id=serial_number,
        create_at=datetime.datetime.now(),
        update_at=datetime.datetime.now()
    )
    ret_msg = util.call_sqlalchemy(insert_flow_command)
    return {'flow_id': ret_msg.inserted_primary_key}


def _deal_with_json(json_string):
    return json.dumps(json.loads(json_string),
                      ensure_ascii=False,
                      separators=(',', ':'))


def check_requirement_by_issue_id(issue_id):
    get_rqmt_command = db.select(
        [TableRequirement.stru_rqmt.c.id]).where(
        db.and_(TableRequirement.stru_rqmt.c.issue_id == issue_id)).order_by(TableRequirement.stru_rqmt.c.id.asc())
    logger.debug("get_rqmt_command: {0}".format(get_rqmt_command))
    result = util.call_sqlalchemy(get_rqmt_command)
    ret_msg = result.fetchall()
    requirement_ids = []
    for ret_msg in ret_msg:
        requirement_ids.append(ret_msg['id'])

    return requirement_ids


# 取得 requirement 內的流程資訊

def get_requirement_by_rqmt_id(requirement_id):
    get_rqmt_command = db.select([
        TableRequirement.stru_rqmt.c.flow_info
    ]).where(db.and_(TableRequirement.stru_rqmt.c.id == requirement_id))
    logger.debug("get_rqmt_command: {0}".format(get_rqmt_command))
    result = util.call_sqlalchemy(get_rqmt_command)
    ret_msg = result.fetchone()
    output = json.loads(str(ret_msg['flow_info']))
    return {'flow_info': output}


# 將 requirement 隱藏

def del_requirement_by_rqmt_id(requirement_id):
    update_rqmt_command = db.update(TableRequirement.stru_rqmt).where(
        db.and_(TableRequirement.stru_rqmt.c.id == requirement_id)).values(
        disabled=True,
        update_at=datetime.datetime.now())
    logger.debug("insert_user_command: {0}".format(update_rqmt_command))
    return util.call_sqlalchemy(update_rqmt_command)


# 修改  requirement 內資訊

def modify_requirement_by_rqmt_id(requirement_id, args):
    update_rqmt_command = db.update(TableRequirement.stru_rqmt).where(
        db.and_(TableRequirement.stru_rqmt.c.id == requirement_id)).values(
        update_at=datetime.datetime.now(),
        flow_info=_deal_with_json(args['flow_info'])).returning(
        TableRequirement.stru_rqmt.c.update_at)
    return util.call_sqlalchemy(update_rqmt_command)


# 取得同Issue Id 內  requirements 的所有資訊

def get_requirements_by_issue_id(issue_id):
    get_rqmt_command = db.select(
        [TableRequirement.stru_rqmt.c.flow_info]).where(
        db.and_(TableRequirement.stru_rqmt.c.issue_id == issue_id,
                TableRequirement.stru_rqmt.c.disabled == False))
    logger.debug("get_rqmt_command: {0}".format(get_rqmt_command))
    result = util.call_sqlalchemy(get_rqmt_command)
    ret_msg = result.fetchall()
    i = 0
    output = {}
    for ret_msg in ret_msg:
        output[i] = json.loads(ret_msg['flow_info'])
        i = i + 1
    return {'flow_info': output}


# 新增同Issue Id 內  requirement 的資訊

def post_requirement_by_issue_id(issue_id, args):
    insert_rqmt_command = db.insert(TableRequirement.stru_rqmt).values(
        project_id=args['project_id'],
        issue_id=issue_id,
        # flow_info=self._deal_with_json(args['flow_info']),
        create_at=datetime.datetime.now(),
        update_at=datetime.datetime.now())
    logger.debug("insert_user_command: {0}".format(insert_rqmt_command))
    ret_msg = util.call_sqlalchemy(insert_rqmt_command)
    return {'requirement_id': ret_msg.inserted_primary_key}


# 取得同Issue Id 內  requirements 的所有資訊

def get_requirements_by_project_id(project_id):
    get_rqmt_command = db.select(
        [TableRequirement.stru_rqmt.c.flow_info]).where(
        db.and_(TableRequirement.stru_rqmt.c.project_id == project_id,
                TableRequirement.stru_rqmt.c.disabled == False))
    logger.debug("get_rqmt_command: {0}".format(get_rqmt_command))
    result = util.call_sqlalchemy(get_rqmt_command)
    ret_msg = result.fetchall()
    i = 0
    output = {}
    for ret_msg in ret_msg:
        output[i] = json.loads(ret_msg['flow_info'])
        i = i + 1
    return {'flow_info': output}


def get_testcase_type():
    command = db.select([TableCaseType.stru_tcType])
    result = util.call_sqlalchemy(command)
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
              'update_at': util.date_to_str(sql_row['update_at']),
              'create_at': util.date_to_str(sql_row['create_at'])}
    return output


def deal_with_fetchall(data, case_type=''):
    if case_type == '':
        case_type = get_testcase_type()
    output = []
    for row in data:
        output.append(deal_with_TestCaseObject(row, case_type))
    return output


def get_test_case_by_tc_id(testcase_id):
    command = db.select([TableTestCase.stru_testCase]).where(db.and_(
        TableTestCase.stru_testCase.c.id == testcase_id, TableTestCase.stru_testCase.c.disabled == False))
    logger.debug("get_testCase_command: {0}".format(command))
    result = util.call_sqlalchemy(command)
    row = result.fetchone()
    output = deal_with_TestCaseObject(row)
    return output


# 將 TestCase 隱藏
def del_testcase_by_tc_id(testcase_id):
    command = db.update(TableTestCase.stru_testCase).where(
        db.and_(TableTestCase.stru_testCase.c.id == testcase_id)).values(
        disabled=True,
        update_at=datetime.datetime.now()
    ).returning(TableTestCase.stru_testCase.c.update_at, TableTestCase.stru_testCase.c.id)
    logger.debug("update_testCase_command: {0}".format(command))
    result = util.call_sqlalchemy(command)
    ret_msg = result.fetchone()
    output = {'id': ret_msg['id'], 'update_at': util.date_to_str(ret_msg['update_at'])}
    return output


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
    result = util.call_sqlalchemy(command)
    ret_msg = result.fetchone()
    output = {'id': ret_msg['id'], 'update_at': util.date_to_str(ret_msg['update_at'])}
    return output


def get_testcase_by_column(args):
    if args['issue_id'] is not None:
        command = db.select([TableTestCase.stru_testCase]).where(db.and_(
            TableTestCase.stru_testCase.c.issue_id == args['issue_id'],
            TableTestCase.stru_testCase.c.disabled == False)).order_by('project_id')
    elif args['project_id'] is not None:
        command = db.select([TableTestCase.stru_testCase]).where(db.and_(
            TableTestCase.stru_testCase.c.project_id == args['project_id'],
            TableTestCase.stru_testCase.c.disabled == False)).order_by('project_id')
    else:
        return {}
    result = util.call_sqlalchemy(command)
    ret_msgs = result.fetchall()
    return deal_with_fetchall(ret_msgs)


def get_testcase_by_issue_id(issue_id):
    command = db.select([TableTestCase.stru_testCase]).where(db.and_(
        TableTestCase.stru_testCase.c.issue_id == issue_id, TableTestCase.stru_testCase.c.disabled == False))
    logger.debug("get_testCase_command: {0}".format(command))
    result = util.call_sqlalchemy(command)
    ret_msgs = result.fetchall()
    return deal_with_fetchall(ret_msgs)


def get_testcase_by_project_id(project_id):
    command = db.select([TableTestCase.stru_testCase]).where(db.and_(
        TableTestCase.stru_testCase.c.project_id == project_id, TableTestCase.stru_testCase.c.disabled == False))
    logger.debug("get_testCase_command: {0}".format(command))
    result = util.call_sqlalchemy(command)
    ret_msgs = result.fetchall()
    return deal_with_fetchall(ret_msgs)


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
    ret_msg = util.call_sqlalchemy(command)
    return {'testCase_id': ret_msg.inserted_primary_key}


# 新增同Project Id 內 TestCase 的資訊

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
    ret_msg = util.call_sqlalchemy(command)
    return {'testCase_id': ret_msg.inserted_primary_key}


def get_api_method():
    output = []
    for key in HTTP_METHODS:
        output.append({"Http_Method_id": int(key), "name": HTTP_METHODS[key]})
    return output


def get_testcase_type_wrapped():
    support_type = get_testcase_type()
    output = []
    for key in support_type:
        output.append({"test_case_type_id": int(key), "name": support_type[key]})
    return output


def deal_with_TestItemObject(sql_row):
    output = {'id': sql_row['id'], 'name': sql_row['name'], 'project_id': sql_row['project_id'],
              'issue_id': sql_row['issue_id'], 'testCase_id': sql_row['test_case_id'],
              'is_passed': sql_row['is_passed'], 'update_at': util.date_to_str(sql_row['update_at']),
              'create_at': util.date_to_str(sql_row['create_at'])}
    return output


def get_testitem_by_ti_id(testitem_id):
    command = db.select([TableTestItem.stru_testItem]).where(
        db.and_(
            TableTestItem.stru_testItem.c.id == testitem_id,
            TableTestItem.stru_testItem.c.disabled == False)
    )
    logger.debug("get_testItem_command: {0}".format(command))
    result = util.call_sqlalchemy(command)
    row = result.fetchone()
    output = deal_with_TestItemObject(row)
    return output


def del_testItem_by_ti_id(testitem_id):
    command = db.update(TableTestItem.stru_testItem).where(
        db.and_(TableTestItem.stru_testItem.c.id == testitem_id)).values(
        disabled=True,
        update_at=datetime.datetime.now()
    ).returning(
        TableTestItem.stru_testItem.c.update_at,
        TableTestItem.stru_testItem.c.id)
    logger.debug(
        "update_testItem_command: {0}".format(command))
    result = util.call_sqlalchemy(command)
    ret_msg = result.fetchone()
    output = {'id': ret_msg['id'], 'update_at': util.date_to_str(ret_msg['update_at'])}
    return output


def modify_testItem_by_ti_id(testitem_id, args):
    command = db.update(TableTestItem.stru_testItem).where(
        db.and_(TableTestItem.stru_testItem.c.id == testitem_id)).values(
        name=args['name'],
        is_passed=args['is_passed'],
        update_at=datetime.datetime.now()
    ).returning(
        TableTestItem.stru_testItem.c.update_at,
        TableTestItem.stru_testItem.c.id)
    result = util.call_sqlalchemy(command)
    ret_msg = result.fetchone()
    output = {'id': ret_msg['id'], 'update_at': util.date_to_str(ret_msg['update_at'])}
    return output


def get_testItem_by_testCase_id(testcase_id):
    command = db.select([TableTestItem.stru_testItem]).where(
        db.and_(
            TableTestItem.stru_testItem.c.test_case_id == testcase_id,
            TableTestItem.stru_testItem.c.disabled == False))
    result = util.call_sqlalchemy(command)
    ret_msgs = result.fetchall()
    output = []
    for row in ret_msgs:
        output.append(deal_with_TestItemObject(row))
    return output


def post_testitem_by_testcase_id(testcase_id, args):
    insert_ti_command = db.insert(TableTestItem.stru_testItem).values(
        test_case_id=testcase_id,
        project_id=args['project_id'],
        issue_id=args['issue_id'],
        name=args['name'],
        is_passed=args['is_passed'],
        create_at=datetime.datetime.now(),
        update_at=datetime.datetime.now()
    )
    ret_msg = util.call_sqlalchemy(insert_ti_command)
    return {'testItem_id': ret_msg.inserted_primary_key}


def get_testItem_by_issue_id(issue_id, order_column):
    command = db.select([TableTestItem.stru_testItem]).where(
        db.and_(
            TableTestItem.stru_testItem.c.issue_id == issue_id,
            TableTestItem.stru_testItem.c.disabled == False)).order_by(order_column)
    logger.debug("get_testItem_command: {0}".format(command))
    result = util.call_sqlalchemy(command)
    ret_msgs = result.fetchall()
    output = []
    for row in ret_msgs:
        output.append(deal_with_TestItemObject(row))
    return output


def get_testItem_by_project_id(project_id, order_column):
    command = db.select([TableTestItem.stru_testItem]).where(db.and_(
        TableTestItem.stru_testItem.c.project_id == project_id,
        TableTestItem.stru_testItem.c.disabled == False)).order_by(order_column)
    logger.debug("get_testItem_command: {0}".format(command))
    result = util.call_sqlalchemy(command)
    ret_msgs = result.fetchall()
    output = []
    for row in ret_msgs:
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
    output = {'id': sql_row['id'], 'project_id': sql_row['project_id'], 'issue_id': sql_row['issue_id'],
              'test_case_id': sql_row['test_case_id'], 'test_item_id': sql_row['test_item_id'],
              'type_id': sql_row['type_id'], 'location_id': sql_row['location_id'], 'key': sql_row['key'],
              'value': sql_row['value'], 'update_at': util.date_to_str(sql_row['update_at']),
              'create_at': util.date_to_str(sql_row['create_at'])}
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
    command = db.select([TableTestValue.stru_testValue]).where(db.and_(
        TableTestValue.stru_testValue.c.id == value_id, TableTestValue.stru_testValue.c.disabled == False))
    result = util.call_sqlalchemy(command)
    row = result.fetchone()
    output = deal_with_TestValueObject(row)
    return output


def del_testValue_by_tv_id(value_id):
    command = db.update(TableTestValue.stru_testValue).where(
        db.and_(TableTestValue.stru_testValue.c.id == value_id)).values(
        disabled=True,
        update_at=datetime.datetime.now()
    ).returning(TableTestValue.stru_testValue.c.update_at, TableTestValue.stru_testValue.c.id)
    result = util.call_sqlalchemy(command)
    ret_msg = result.fetchone()
    output = {'id': ret_msg['id'], 'update_at': util.date_to_str(ret_msg['update_at'])}
    return output


def modify(value_id, args):
    command = db.update(TableTestValue.stru_testValue).where(
        db.and_(TableTestValue.stru_testValue.c.id == value_id)).values(
        key=args['key'],
        value=args['value'],
        type_id=args['type_id'],
        location_id=args['location_id'],
        update_at=datetime.datetime.now()
    ).returning(TableTestValue.stru_testValue.c.update_at, TableTestValue.stru_testValue.c.id)
    result = util.call_sqlalchemy(command)
    ret_msg = result.fetchone()
    output = {'id': ret_msg['id'], 'update_at': util.date_to_str(ret_msg['update_at'])}
    return output


def get_testValue_by_testItem_id(item_id, order_column=''):
    if order_column == '':
        command = db.select([TableTestValue.stru_testValue]).where(db.and_(
            TableTestValue.stru_testValue.c.test_item_id == item_id,
            TableTestValue.stru_testValue.c.disabled == False))
    else:
        command = db.select([TableTestValue.stru_testValue]).where(db.and_(
            TableTestValue.stru_testValue.c.test_item_id == item_id,
            TableTestValue.stru_testValue.c.disabled == False)).order_by(order_column)
    logger.debug("get_testValue_command: {0}".format(command))
    result = util.call_sqlalchemy(command)
    ret_msgs = result.fetchall()
    output = []
    for row in ret_msgs:
        output.append(deal_with_TestValueObject(row))
    return output


def post_testValue_by_testItem_id(item_id, args):
    command = db.insert(TableTestValue.stru_testValue).values(
        type_id=args['type_id'],
        key=args['key'],
        value=args['value'],
        location_id=args['location_id'],
        test_item_id=item_id,
        test_case_id=args['testCase_id'],
        issue_id=args['issue_id'],
        project_id=args['project_id'],
        create_at=datetime.datetime.now(),
        update_at=datetime.datetime.now()
    )
    ret_msg = util.call_sqlalchemy(command)
    return {'testValue_id': ret_msg.inserted_primary_key}


def get_testValue_by_issue_id(issue_id, order_column=''):
    if order_column != '':
        command = db.select([TableTestValue.stru_testValue]).where(db.and_(
            TableTestValue.stru_testValue.c.issue_id == issue_id,
            TableTestValue.stru_testValue.c.disabled == False)).order_by(order_column)
    else:
        command = db.select([TableTestValue.stru_testValue]).where(db.and_(
            TableTestValue.stru_testValue.c.issue_id == issue_id,
            TableTestValue.stru_testValue.c.disabled == False))
    result = util.call_sqlalchemy(command)
    ret_msgs = result.fetchall()
    output = []
    for row in ret_msgs:
        output.append(deal_with_TestValueObject(row))
    return output


def get_testValue_by_project_id(project_id, order_column=''):
    command = db.select([TableTestValue.stru_testValue]).where(db.and_(
        TableTestValue.stru_testValue.c.project_id == project_id,
        TableTestValue.stru_testValue.c.disabled == False)).order_by(order_column)
    result = util.call_sqlalchemy(command)
    ret_msgs = result.fetchall()
    output = []
    for row in ret_msgs:
        output.append(deal_with_TestValueObject(row))
    return output


def get_testValue_by_Column(args, order_column=''):
    if args['issue_id'] is not None:
        return get_testValue_by_issue_id(args['issue_id'], order_column)

    elif args['project_id'] is not None:
        return get_testValue_by_project_id(args['project_id'], order_column)
    else:
        return {}


def save_test_result(args):
    try:
        if 'branch' in args:
            branch = args['branch']
        else:
            branch = None
        cmd = db.insert(TableTestResult.stru_testResult).values(
            project_id=args['project_id'],
            total=args['total'],
            fail=args['fail'],
            branch=branch,
            report=args['report'],
            run_at=datetime.datetime.now()
        )
        util.call_sqlalchemy(cmd)
        return util.success()
    except Exception as e:
        return util.respond(500, "Error when saving test results.",
                            error=apiError.uncaught_exception(e))


def get_report(project_id):
    try:
        result = db.engine.execute(
            'SELECT report FROM test_results WHERE project_id={0} ORDER BY id DESC LIMIT 1'.format(
                project_id))
        if result.rowcount == 0:
            return util.respond(404, 'No postman report for this project.')
        report = result.fetchone()['report']
        if report is None:
            return util.respond(404, 'No postman report for this project.')
        return util.success(json.loads(report))
    except Exception as e:
        return util.respond(500, "Error when saving test results.",
                            error=apiError.uncaught_exception(e))


# --------------------- Resources ---------------------
class RequirementByIssue(Resource):

    # 用issues ID 取得目前所有的需求清單
    @jwt_required
    def get(self, issue_id):
        output = get_requirements_by_issue_id(issue_id)
        return util.success(output)

    # 用issues ID 新建立需求清單
    @jwt_required
    def post(self, issue_id):
        parser = reqparse.RequestParser()
        parser.add_argument('project_id', type=int)
        # parser.add_argument('flow_info', type=str)
        args = parser.parse_args()
        output = post_requirement_by_issue_id(issue_id, args)
        return util.success(output)


class Requirement(Resource):

    # 用requirement_id 取得目前需求流程
    @jwt_required
    def get(self, requirement_id):
        # temp = get_jwt_identity()
        output = get_requirement_by_rqmt_id(requirement_id)
        return util.success(output)

    # 用requirement_id 刪除目前需求流程
    @jwt_required
    def delete(self, requirement_id):
        del_requirement_by_rqmt_id(requirement_id)
        return util.success()

    # 用requirement_id 更新目前需求流程
    @jwt_required
    def put(self, requirement_id):
        parser = reqparse.RequestParser()
        parser.add_argument('flow_info', type=str)
        args = parser.parse_args()
        modify_requirement_by_rqmt_id(requirement_id, args)
        return util.success()


class GetFlowType(Resource):
    @jwt_required
    def get(self):
        output = get_flow_support_type()
        return util.success(output)


class FlowByIssue(Resource):

    # 用issues ID 取得目前所有的需求清單
    @jwt_required
    def get(self, issue_id):
        requirement_ids = check_requirement_by_issue_id(issue_id)
        if not requirement_ids:
            return util.success()
        output = []
        for requirement_id in requirement_ids:
            result = get_flow_by_requirement_id(requirement_id)
            if len(result) > 0:
                output.append({
                    'requirement_id': requirement_id,
                    'flow_data': result
                })
        return util.success(output)

    # 用issues ID 新建立需求清單
    @jwt_required
    def post(self, issue_id):
        parser = reqparse.RequestParser()
        parser.add_argument('project_id', type=int)
        parser.add_argument('type_id', type=int)
        parser.add_argument('name', type=str)
        parser.add_argument('description', type=str)
        args = parser.parse_args()
        check = check_requirement_by_issue_id(issue_id)
        if not check:
            requirements = post_requirement_by_issue_id(issue_id, args)
            requirement_id = requirements['requirement_id'][0]
        else:
            requirement_id = check[0]

        output = post_flow_by_requirement_id(int(issue_id), requirement_id, args)
        return util.success(output, has_date_etc=True)


class Flow(Resource):

    # 用requirement_id 取得目前需求流程
    @jwt_required
    def get(self, flow_id):
        output = get_flow_by_flow_id(flow_id)
        return util.success(output)

    # 用requirement_id 刪除目前需求流程
    @jwt_required
    def delete(self, flow_id):
        output = disabled_flow_by_flow_id(flow_id)
        return util.success(output, has_date_etc=True)

    # 用requirement_id 更新目前需求流程
    @jwt_required
    def put(self, flow_id):
        parser = reqparse.RequestParser()
        parser.add_argument('serial_id', type=int)
        parser.add_argument('type_id', type=int)
        parser.add_argument('name', type=str)
        parser.add_argument('description', type=str)
        args = parser.parse_args()
        output = modify_flow_by_flow_id(flow_id, args)
        return util.success(output, has_date_etc=True)


class ParameterType(Resource):
    @jwt_required
    def get(self):
        output = get_parameter_types()
        return util.success(output)


class ParameterByIssue(Resource):

    # 用issues ID 取得目前所有的需求清單
    @jwt_required
    def get(self, issue_id):
        output = get_parameters_by_issue_id(issue_id)
        return util.success(output)

    # 用issues ID 新建立需求清單
    @jwt_required
    def post(self, issue_id):
        parser = reqparse.RequestParser()
        parser.add_argument('project_id', type=int)
        parser.add_argument('parameter_type_id', type=int)
        parser.add_argument('name', type=str)
        parser.add_argument('description', type=str)
        parser.add_argument('limitation', type=str)
        parser.add_argument('length', type=int)
        args = parser.parse_args()
        output = post_parameters_by_issue_id(issue_id, args)
        return util.success(output)


class Parameter(Resource):

    # 用requirement_id 取得目前需求流程
    @jwt_required
    def get(self, parameter_id):
        output = get_parameters_by_param_id(parameter_id)
        return util.success(output)

    # 用requirement_id 刪除目前需求流程
    @jwt_required
    def delete(self, parameter_id):
        output = del_parameters_by_param_id(parameter_id)
        return util.success(output)

    # 用requirement_id 更新目前需求流程
    @jwt_required
    def put(self, parameter_id):
        parser = reqparse.RequestParser()
        parser.add_argument('parameter_type_id', type=int)
        parser.add_argument('name', type=str)
        parser.add_argument('description', type=str)
        parser.add_argument('limitation', type=str)
        parser.add_argument('length', type=int)
        args = parser.parse_args()
        output = modify_parameters_by_param_id(parameter_id, args)
        return util.success(output)


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
        print(parser)
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
        output = modify(value_id, args)
        return util.success(output)
