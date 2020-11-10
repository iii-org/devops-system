import datetime
import logging

import config
from model import db, TableFlow
import resources.util as util

logger = logging.getLogger(config.get('LOGGER_NAME'))
flow_type = {"0": "Given", "1": "When", "2": "Then", "3": "But", "4": "And"}


def get_flow_support_type():
    output = []
    for key in flow_type:
        output.append({"flow_type_id": int(key), "name": flow_type[key]})
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
                TableFlow.stru_flow.c.disabled is False))
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
    logger.debug("insert_user_command: {0}".format(insert_flow_command))
    ret_msg = util.call_sqlalchemy(insert_flow_command)
    return {'flow_id': ret_msg.inserted_primary_key}
