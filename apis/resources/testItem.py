from model import db, TableTestItem
import resources.util as util
import datetime
import logging

logger = logging.getLogger('devops.api')


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
