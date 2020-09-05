import logging
logger = logging.getLogger('devops.api')
import datetime
import json
from .util import util
from model import db, TableParameter, TableParameterType


class Parameter(object):
    headers = {'Content-Type': 'application/json'}

    def _get_paramType(self):
        get_paramType_command = db.select([TableParameterType.stru_paramType])
        logger.debug("get_paramType_command: {0}".format(get_paramType_command))
        result = util.callsqlalchemy(self, get_paramType_command, logger)
        reMessages = result.fetchall()
        paramType  = {}
        for row in reMessages:
            paramType[row['id']] = row['type']
        return paramType

    def _deal_with_jsonString(self, jsonSting):
        return json.dumps(json.loads(jsonSting), ensure_ascii=False, separators=(',', ':'))
    
    def _deal_with_ParametersObject(self, sqlRow,paramType = ''):
        if paramType == '':
            paramType = self._get_paramType()
        output={}
        output['name'] = sqlRow['name']
        output['parameter_type_id'] = sqlRow['parameter_type_id']
        if sqlRow['parameter_type_id'] in paramType:
            output['parameter_type'] = paramType[sqlRow['parameter_type_id']]
        else:
            output['parameter_type'] = 'None'
        output['description'] = sqlRow['description']
        output['limitation'] = sqlRow['limitation']
        output['length'] = sqlRow['length']
        output['update_at'] =sqlRow['update_at'].isoformat()
        output['create_at'] = sqlRow['create_at'].isoformat()
        return output


    # 取得 parameters  靠 parameters id 
    def get_parameters_by_param_id(self, logger, parameters_id, user_id):

        get_param_command = db.select([TableParameter.stru_param]).where(db.and_(TableParameter.stru_param.c.id==parameters_id))
        logger.debug("get_param_command: {0}".format(get_param_command))
        result = util.callsqlalchemy(self, get_param_command, logger)
        row = result.fetchone()
        output = self._deal_with_ParametersObject(row)
        return  output

        # 將 parameters 隱藏
    def del_parameters_by_param_id(self, logger, parameters_id, user_id):

        update_param_command = db.update(TableParameter.stru_param).where(db.and_(TableParameter.stru_param.c.id==parameters_id)).values(
            disabled=True,
            update_at=datetime.datetime.now())
        logger.debug("insert_user_command: {0}".format(update_param_command))
        result = util.callsqlalchemy(self, update_param_command, logger)
        # reMessage = result.fetchall()
        # print(reMessage)
        # return {'123'}

        # 修改  parameters 內資訊
    def modify_parameters_by_param_id(self, logger, parameters_id, args, user_id):

        update_param_command = db.update(TableParameter.stru_param).where(db.and_(TableParameter.stru_param.c.id==parameters_id)).values(
            update_at=datetime.datetime.now(),
            parameter_type_id=args['parameter_type_id'], 
            name=args['name'],
            description=args['description'],
            limitation=args['limitation'],
            length=args['length']
            ).returning(TableParameter.stru_param.c.update_at)
        logger.debug("insert_user_command: {0}".format(update_param_command))
        result = util.callsqlalchemy(self, update_param_command, logger)
        # reMessage = result.fetchone()
        # print(reMessage)
    

        # 取得同Issue Id 內  parameterss 的所有資訊
    def get_parameterss_by_issue_id(self, logger, issue_id, user_id):

        get_param_command = db.select([TableParameter.stru_param]).where(db.and_(TableParameter.stru_param.c.issue_id==issue_id,TableParameter.stru_param.c.disabled==False))
        logger.debug("get_param_command: {0}".format(get_param_command))
        result = util.callsqlalchemy(self, get_param_command, logger)
        reMessages = result.fetchall()
        i = 0
        output = []
        paramType = self._get_paramType()
        for row in reMessages:
            output.append(self._deal_with_ParametersObject(row, paramType))
        return output

        # 新增同Issue Id 內  parameters 的資訊
    def post_parameters_by_issue_id(self, logger,  issue_id, args, user_id):

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
        reMessage = util.callsqlalchemy(self, insert_param_command, logger)
        return {'parameters_id': reMessage.inserted_primary_key}

    def get_parameter_types(self):
        paraType = self._get_paramType()
        output = []
        for key in paraType:
            temp = {"parameter_type_id": key, "name": paraType[key]}
            output.append(temp)
        return output
