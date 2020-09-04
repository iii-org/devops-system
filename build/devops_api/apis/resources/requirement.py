import datetime
import json
from .util import util
from model import db, TableRequirement


class Requirement(object):
    headers = {'Content-Type': 'application/json'}

    def _deal_with_json(self, jsonSting):
        return json.dumps(json.loads(jsonSting),
                          ensure_ascii=False,
                          separators=(',', ':'))



    def get_requirement_by_Column(self, logger, args, user_id,orderColumn=''):
        output = {}
        if(args['issue_id'] != None):
            return  self.get_requirements_by_issue_id(logger,args['issue_id'],user_id)

        elif (args['project_id'] != None):
            return self.get_requirements_by_project_id(logger,args['project_id'],user_id)
        else:
            return {}

    def check_requirement_by_issue_id(self, logger, issue_id):
        get_rqmt_command = db.select(
            [TableRequirement.stru_rqmt.c.id]).where(
                db.and_(TableRequirement.stru_rqmt.c.issue_id == issue_id)).order_by(TableRequirement.stru_rqmt.c.id.asc())
        logger.debug("get_rqmt_command: {0}".format(get_rqmt_command))
        result = util.callsqlalchemy(self, get_rqmt_command, logger)
        reMessages = result.fetchall()
        requirement_ids = []
        for reMessage in reMessages:
            requirement_ids.append(reMessage['id'])

        return requirement_ids

    
    # 取得 requirement 內的流程資訊
    def get_requirement_by_rqmt_id(self, logger, requirement_id, user_id):

        get_rqmt_command = db.select([
            TableRequirement.stru_rqmt.c.flow_info
        ]).where(db.and_(TableRequirement.stru_rqmt.c.id == requirement_id))
        logger.debug("get_rqmt_command: {0}".format(get_rqmt_command))
        result = util.callsqlalchemy(self, get_rqmt_command, logger)
        reMessage = result.fetchone()
        output = json.loads(str(reMessage['flow_info']))
        return {'flow_info': output}

    # 將 requirement 隱藏

    def del_requirement_by_rqmt_id(self, logger, requirement_id, user_id):

        update_rqmt_command = db.update(TableRequirement.stru_rqmt).where(
            db.and_(TableRequirement.stru_rqmt.c.id == requirement_id)).values(
                disabled=True,
                update_at=datetime.datetime.now())
        logger.debug("insert_user_command: {0}".format(update_rqmt_command))
        reMessage = util.callsqlalchemy(self, update_rqmt_command, logger)

    # 修改  requirement 內資訊
    def modify_requirement_by_rqmt_id(self, logger, requirement_id, args,
                                      user_id):

        update_rqmt_command = db.update(TableRequirement.stru_rqmt).where(
            db.and_(TableRequirement.stru_rqmt.c.id == requirement_id)).values(
                update_at=datetime.datetime.now(),
                flow_info=self._deal_with_json(args['flow_info'])).returning(
                    TableRequirement.stru_rqmt.c.update_at)
        logger.debug("insert_user_command: {0}".format(update_rqmt_command))
        reMessage = util.callsqlalchemy(self, update_rqmt_command, logger)

    # 取得同Issue Id 內  requirements 的所有資訊
    def get_requirements_by_issue_id(self, logger, issue_id, user_id):
        get_rqmt_command = db.select(
            [TableRequirement.stru_rqmt.c.flow_info]).where(
                db.and_(TableRequirement.stru_rqmt.c.issue_id == issue_id,
                        TableRequirement.stru_rqmt.c.disabled == False))
        logger.debug("get_rqmt_command: {0}".format(get_rqmt_command))
        result = util.callsqlalchemy(self, get_rqmt_command, logger)
        reMessages = result.fetchall()
        i = 0
        output = {}
        for reMessage in reMessages:
            output[i] = json.loads(reMessage['flow_info'])
            i = i + 1
        return {'flow_info': output}

    # 新增同Issue Id 內  requirement 的資訊
    def post_requirement_by_issue_id(self, logger, issue_id, args, user_id):

        insert_rqmt_command = db.insert(TableRequirement.stru_rqmt).values(
            project_id=args['project_id'],
            issue_id=issue_id,
            # flow_info=self._deal_with_json(args['flow_info']),
            create_at=datetime.datetime.now(),
            update_at=datetime.datetime.now())
        logger.debug("insert_user_command: {0}".format(insert_rqmt_command))
        reMessage = util.callsqlalchemy(self, insert_rqmt_command, logger)
        print(reMessage)
        return {'requirement_id': reMessage.inserted_primary_key}
    

    # 取得同Issue Id 內  requirements 的所有資訊
    def get_requirements_by_project_id(self, logger, project_id, user_id):
        get_rqmt_command = db.select(
            [TableRequirement.stru_rqmt.c.flow_info]).where(
                db.and_(TableRequirement.stru_rqmt.c.project_id == project_id,
                        TableRequirement.stru_rqmt.c.disabled == False))
        logger.debug("get_rqmt_command: {0}".format(get_rqmt_command))
        result = util.callsqlalchemy(self, get_rqmt_command, logger)
        reMessages = result.fetchall()
        i = 0
        output = {}
        for reMessage in reMessages:
            output[i] = json.loads(reMessage['flow_info'])
            i = i + 1
        return {'flow_info': output}
