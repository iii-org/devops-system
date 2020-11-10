import datetime
import logging

import resources.util as util
from model import db, TableTestValue

logger = logging.getLogger('devops.api')

httpType = {"1": "request", "2": "response"}
httpMethod = {"1": "GET", "2": "POST", "3": "PUT", "4": "DELETE"}
httpLocation = {"1": "header", "2": "body"}


def deal_with_TestValueObject(sql_row):
    output = {'id': sql_row['id'], 'project_id': sql_row['project_id'], 'issue_id': sql_row['issue_id'],
              'test_case_id': sql_row['test_case_id'], 'test_item_id': sql_row['test_item_id'],
              'type_id': sql_row['type_id'], 'location_id': sql_row['location_id'], 'key': sql_row['key'],
              'value': sql_row['value'], 'update_at': util.date_to_str(sql_row['update_at']),
              'create_at': util.date_to_str(sql_row['create_at'])}
    return output


def get_testValue_httpType():
    output = []
    for key in httpType:
        output.append({'type_id': int(key), "type_name": httpType[key]})
    return output


def get_testValue_httpLocation():
    output = []
    for key in httpLocation:
        output.append({'location_id': int(key), "type_name": httpLocation[key]})
    return output


def get_testValue_by_tv_id(value_id):
    command = db.select([TableTestValue.stru_testValue]).where(db.and_(
        TableTestValue.stru_testValue.c.id == value_id, TableTestValue.stru_testValue.c.disabled is False))
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
            TableTestValue.stru_testValue.c.disabled is False))
    else:
        command = db.select([TableTestValue.stru_testValue]).where(db.and_(
            TableTestValue.stru_testValue.c.test_item_id == item_id,
            TableTestValue.stru_testValue.c.disabled is False)).order_by(order_column)
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
            TableTestValue.stru_testValue.c.disabled is False)).order_by(order_column)
    else:
        command = db.select([TableTestValue.stru_testValue]).where(db.and_(
            TableTestValue.stru_testValue.c.issue_id == issue_id,
            TableTestValue.stru_testValue.c.disabled is False))
    result = util.call_sqlalchemy(command)
    ret_msgs = result.fetchall()
    output = []
    for row in ret_msgs:
        output.append(deal_with_TestValueObject(row))
    return output


def get_testValue_by_project_id(project_id, order_column=''):
    command = db.select([TableTestValue.stru_testValue]).where(db.and_(
        TableTestValue.stru_testValue.c.project_id == project_id,
        TableTestValue.stru_testValue.c.disabled is False)).order_by(order_column)
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



