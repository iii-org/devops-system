import datetime
import json
import logging

import config
from .util import Util
from model import db, TableRequirement

logger = logging.getLogger(config.get('LOGGER_NAME'))


def _deal_with_json(json_string):
    return json.dumps(json.loads(json_string),
                      ensure_ascii=False,
                      separators=(',', ':'))


class Requirement(object):
    headers = {'Content-Type': 'application/json'}

    @staticmethod
    def check_requirement_by_issue_id(issue_id):
        get_rqmt_command = db.select(
            [TableRequirement.stru_rqmt.c.id]).where(
            db.and_(TableRequirement.stru_rqmt.c.issue_id == issue_id)).order_by(TableRequirement.stru_rqmt.c.id.asc())
        logger.debug("get_rqmt_command: {0}".format(get_rqmt_command))
        result = Util.call_sqlalchemy(get_rqmt_command)
        ret_msg = result.fetchall()
        requirement_ids = []
        for ret_msg in ret_msg:
            requirement_ids.append(ret_msg['id'])

        return requirement_ids

    # 取得 requirement 內的流程資訊
    @staticmethod
    def get_requirement_by_rqmt_id(requirement_id):
        get_rqmt_command = db.select([
            TableRequirement.stru_rqmt.c.flow_info
        ]).where(db.and_(TableRequirement.stru_rqmt.c.id == requirement_id))
        logger.debug("get_rqmt_command: {0}".format(get_rqmt_command))
        result = Util.call_sqlalchemy(get_rqmt_command)
        ret_msg = result.fetchone()
        output = json.loads(str(ret_msg['flow_info']))
        return {'flow_info': output}

    # 將 requirement 隱藏
    @staticmethod
    def del_requirement_by_rqmt_id(requirement_id):
        update_rqmt_command = db.update(TableRequirement.stru_rqmt).where(
            db.and_(TableRequirement.stru_rqmt.c.id == requirement_id)).values(
            disabled=True,
            update_at=datetime.datetime.now())
        logger.debug("insert_user_command: {0}".format(update_rqmt_command))
        return Util.call_sqlalchemy(update_rqmt_command)

    # 修改  requirement 內資訊
    @staticmethod
    def modify_requirement_by_rqmt_id(requirement_id, args):
        update_rqmt_command = db.update(TableRequirement.stru_rqmt).where(
            db.and_(TableRequirement.stru_rqmt.c.id == requirement_id)).values(
            update_at=datetime.datetime.now(),
            flow_info=_deal_with_json(args['flow_info'])).returning(
            TableRequirement.stru_rqmt.c.update_at)
        logger.debug("insert_user_command: {0}".format(update_rqmt_command))
        return Util.call_sqlalchemy(update_rqmt_command)

    # 取得同Issue Id 內  requirements 的所有資訊
    @staticmethod
    def get_requirements_by_issue_id(issue_id):
        get_rqmt_command = db.select(
            [TableRequirement.stru_rqmt.c.flow_info]).where(
            db.and_(TableRequirement.stru_rqmt.c.issue_id == issue_id,
                    TableRequirement.stru_rqmt.c.disabled is False))
        logger.debug("get_rqmt_command: {0}".format(get_rqmt_command))
        result = Util.call_sqlalchemy(get_rqmt_command)
        ret_msg = result.fetchall()
        i = 0
        output = {}
        for ret_msg in ret_msg:
            output[i] = json.loads(ret_msg['flow_info'])
            i = i + 1
        return {'flow_info': output}

    # 新增同Issue Id 內  requirement 的資訊
    @staticmethod
    def post_requirement_by_issue_id(issue_id, args):
        insert_rqmt_command = db.insert(TableRequirement.stru_rqmt).values(
            project_id=args['project_id'],
            issue_id=issue_id,
            # flow_info=self._deal_with_json(args['flow_info']),
            create_at=datetime.datetime.now(),
            update_at=datetime.datetime.now())
        logger.debug("insert_user_command: {0}".format(insert_rqmt_command))
        ret_msg = Util.call_sqlalchemy(insert_rqmt_command)
        print(ret_msg)
        return {'requirement_id': ret_msg.inserted_primary_key}

    # 取得同Issue Id 內  requirements 的所有資訊
    @staticmethod
    def get_requirements_by_project_id(project_id):
        get_rqmt_command = db.select(
            [TableRequirement.stru_rqmt.c.flow_info]).where(
            db.and_(TableRequirement.stru_rqmt.c.project_id == project_id,
                    TableRequirement.stru_rqmt.c.disabled is False))
        logger.debug("get_rqmt_command: {0}".format(get_rqmt_command))
        result = Util.call_sqlalchemy(get_rqmt_command)
        ret_msg = result.fetchall()
        i = 0
        output = {}
        for ret_msg in ret_msg:
            output[i] = json.loads(ret_msg['flow_info'])
            i = i + 1
        return {'flow_info': output}
