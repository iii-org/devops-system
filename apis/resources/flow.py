import datetime
import json
from .util import Util
from model import db, TableFlow


class Flow(object):
    headers = {'Content-Type': 'application/json'}
    flow_type = {"0": "Given", "1": "When","2": "Then","3": "But","4": "And" }

    def _deal_with_json(self, jsonSting):
        return json.dumps(json.loads(jsonSting),
                          ensure_ascii=False,
                          separators=(',', ':'))


    def get_flow_support_type (self):
        output = []
        for key in self.flow_type:
            output.append({"flow_type_id": int(key), "name": self.flow_type[key]})
        return output

    def _deal_with_FlowObject(self, sqlRow, caseType=''):
        output = {}
        output['id'] = sqlRow['id']        
        output['project_id'] = sqlRow['project_id']
        output['issue_id'] = sqlRow['issue_id']
        output['requirement_id'] = sqlRow['requirement_id']
        output['type_id'] = sqlRow['type_id']        
        output['name'] = sqlRow['name']
        output['description'] = sqlRow['description']
        output['serial_id'] = sqlRow['serial_id']
        output['update_at'] = Util.date_to_str(sqlRow['update_at'])
        output['create_at'] = Util.date_to_str(sqlRow['create_at'])
        return output




    
    # 取得 requirement 內的流程資訊


    def get_flow_by_flow_id(self, logger, flow_id, user_id):

        get_flow_command = db.select([
            TableFlow.stru_flow
        ]).where(db.and_(TableFlow.stru_flow.c.id == flow_id))
        logger.debug("get_flow_command: {0}".format(get_flow_command))
        result = Util.call_sqlalchemy(get_flow_command)
        reMessage = result.fetchone()
        # output = json.loads(str(reMessage['flow_info']))
        return self._deal_with_FlowObject(reMessage)

    # 將 requirement 隱藏

    def disabled_flow_by_flow_id(self, logger, flow_id, user_id):

        update_flow_command = db.update(TableFlow.stru_flow).where(
            db.and_(TableFlow.stru_flow.c.id == flow_id)).values(
                disabled=True,
                update_at=datetime.datetime.now())
        logger.debug("update_flow_command: {0}".format(update_flow_command))
        reMessage = Util.call_sqlalchemy(update_flow_command)
        return {'last_modified': reMessage.last_updated_params()}
    # 修改  requirement 內資訊
    def modify_flow_by_flow_id(self, logger, flow_id, args,
                                      user_id):
        update_flow_command = db.update(TableFlow.stru_flow).where(
            db.and_(TableFlow.stru_flow.c.id == flow_id)).values(
                type_id = args['type_id'],
                name = args['name'],
                description = args['description'],
                serial_id = args['serial_id'],
                update_at=datetime.datetime.now()
                ).returning(
                    TableFlow.stru_flow.c.update_at)
        logger.debug("update_flow_command: {0}".format(update_flow_command))
        reMessage = Util.call_sqlalchemy(update_flow_command)
        return {'last_modified': reMessage.last_updated_params()}
        

    # 取得同Issue Id 內  requirements 的所有資訊

    def get_flow_by_requirement_id(self, logger,  requirement_id, user_id):
        get_rqmt_command = db.select(
            [TableFlow.stru_flow]).where(
                db.and_(TableFlow.stru_flow.c.requirement_id == requirement_id,
                        TableFlow.stru_flow.c.disabled == False))
        logger.debug("get_rqmt_command: {0}".format(get_rqmt_command))
        result = Util.call_sqlalchemy(get_rqmt_command)
        reMessages = result.fetchall()
        output = []
        for reMessage in reMessages:
            output.append(self._deal_with_FlowObject(reMessage))
        return output

    # 新增同Issue Id 內  requirement 的資訊
    def post_flow_by_requirement_id(self, logger, issue_id, requirement_id, args, user_id):
        serialNumber = 0 
        get_flow_command = db.select(
            [TableFlow.stru_flow.c.serial_id]).where(
                db.and_(TableFlow.stru_flow.c.requirement_id == requirement_id)).order_by(TableFlow.stru_flow.c.serial_id.asc())
        result = Util.call_sqlalchemy(get_flow_command)
        flow_serial_ids = []
        if result != None:
            reMessages = result.fetchall()            
            for reMessage in reMessages:
                flow_serial_ids.append(reMessage['serial_id']) 
       
        if not flow_serial_ids:
            serialNumber = 1 
        else:
            serialNumber = max(flow_serial_ids)+ 1
        insert_flow_command = db.insert(TableFlow.stru_flow).values(
            project_id=args['project_id'],
            issue_id=issue_id,
            requirement_id = requirement_id,
            type_id = args['type_id'],
            name = args['name'],
            description = args['description'],
            serial_id = serialNumber,
            create_at=datetime.datetime.now(),
            update_at=datetime.datetime.now()
            )
        logger.debug("insert_user_command: {0}".format(insert_flow_command))
        reMessage = Util.call_sqlalchemy(insert_flow_command)
        return {'flow_id': reMessage.inserted_primary_key}
    

    # 取得同Issue Id 內  requirements 的所有資訊
    # def get_requirements_by_project_id(self, logger, project_id, user_id):
    #     get_rqmt_command = db.select(
    #         [TableFlow.stru_flow.c.flow_info]).where(
    #             db.and_(TableFlow.stru_flow.c.project_id == project_id,
    #                     TableFlow.stru_flow.c.disabled == False))
    #     logger.debug("get_rqmt_command: {0}".format(get_rqmt_command))
    #     result = util.callsqlalchemy(self, get_rqmt_command, logger)
    #     reMessages = result.fetchall()
    #     i = 0
    #     output = {}
    #     for reMessage in reMessages:
    #         output[i] = json.loads(reMessage['flow_info'])
    #         i = i + 1
    #     return {'flow_info': output}
