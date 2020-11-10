import logging
import datetime
import json
from .util import Util
from model import db, TableParameter, TableParameterType

logger = logging.getLogger('devops.api')


def get_param_type():
    get_param_type_command = db.select([TableParameterType.stru_paramType])
    logger.debug("get_param_type_command: {0}".format(get_param_type_command))
    result = Util.call_sqlalchemy(get_param_type_command)
    ret_msg = result.fetchall()
    param_type = {}
    for row in ret_msg:
        param_type[row['id']] = row['type']
    return param_type


def deal_with_json_string(json_string):
    return json.dumps(json.loads(json_string), ensure_ascii=False, separators=(',', ':'))


def deal_with_ParametersObject(sql_row, param_type=''):
    if param_type == '':
        param_type = get_param_type()
    output = {'id': sql_row['id'],
              'name': sql_row['name'],
              'parameter_type_id': sql_row['parameter_type_id']
              }
    if sql_row['parameter_type_id'] in param_type:
        output['parameter_type'] = param_type[sql_row['parameter_type_id']]
    else:
        output['parameter_type'] = 'None'
    output['description'] = sql_row['description']
    output['limitation'] = sql_row['limitation']
    output['length'] = sql_row['length']
    output['update_at'] = sql_row['update_at'].isoformat()
    output['create_at'] = sql_row['create_at'].isoformat()
    return output


class Parameter(object):
    headers = {'Content-Type': 'application/json'}

    # 取得 parameters  靠 parameters id
    @staticmethod
    def get_parameters_by_param_id(parameters_id):
        get_param_command = db.select([TableParameter.stru_param]).where(
            db.and_(TableParameter.stru_param.c.id == parameters_id))
        logger.debug("get_param_command: {0}".format(get_param_command))
        result = Util.call_sqlalchemy(get_param_command)
        row = result.fetchone()
        output = deal_with_ParametersObject(row)
        return output

        # 將 parameters 隱藏

    def del_parameters_by_param_id(self, logger, parameters_id, user_id):

        update_param_command = db.update(TableParameter.stru_param).where(
            db.and_(TableParameter.stru_param.c.id == parameters_id)).values(
            disabled=True,
            update_at=datetime.datetime.now())
        logger.debug("insert_user_command: {0}".format(update_param_command))
        result = Util.call_sqlalchemy(update_param_command)
        return {}
        # reMessage = result.fetchall()
        # print(reMessage)
        # return {'123'}

        # 修改  parameters 內資訊

    def modify_parameters_by_param_id(self, logger, parameters_id, args, user_id):

        update_param_command = db.update(TableParameter.stru_param).where(
            db.and_(TableParameter.stru_param.c.id == parameters_id)).values(
            update_at=datetime.datetime.now(),
            parameter_type_id=args['parameter_type_id'],
            name=args['name'],
            description=args['description'],
            limitation=args['limitation'],
            length=args['length']
        ).returning(TableParameter.stru_param.c.update_at)
        logger.debug("insert_user_command: {0}".format(update_param_command))
        result = Util.call_sqlalchemy(update_param_command)
        # reMessage = result.fetchone()
        # print(reMessage)

        # 取得同Issue Id 內  parameterss 的所有資訊

    def get_parameterss_by_issue_id(self, logger, issue_id, user_id):

        get_param_command = db.select([TableParameter.stru_param]).where(
            db.and_(TableParameter.stru_param.c.issue_id == issue_id, TableParameter.stru_param.c.disabled == False))
        logger.debug("get_param_command: {0}".format(get_param_command))
        result = Util.call_sqlalchemy(get_param_command)
        ret_msg = result.fetchall()
        i = 0
        output = []
        param_type = get_param_type()
        for row in ret_msg:
            output.append(deal_with_ParametersObject(row, param_type))
        return output

        # 新增同Issue Id 內  parameters 的資訊

    def post_parameters_by_issue_id(self, logger, issue_id, args, user_id):

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
        reMessage = Util.call_sqlalchemy(insert_param_command)
        return {'parameters_id': reMessage.inserted_primary_key}

    def get_parameter_types(self):
        paraType = get_param_type()
        output = []
        for key in paraType:
            temp = {"parameter_type_id": key, "name": paraType[key]}
            output.append(temp)
        return output
