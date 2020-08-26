from model import db, TableTestValue, TableCaseType, TableHttpMethod
from .util import util
import json
import datetime
import logging
logger = logging.getLogger('devops.api')


class TestValue(object):
    headers = {'Content-Type': 'application/json'}
    httpType = {"1": "request", "2": "response"}
    httpMethod = {"1": "GET", "2": "POST", "3": "PUT", "4":"DELETE" }
    httpLocation = {"1": "header", "2":"body"}


   

    def _deal_with_TestValueObject(self, sqlRow):
        output = {}
        output['id'] = sqlRow['id']
        output['project_id'] = sqlRow['project_id']
        output['issue_id'] = sqlRow['issue_id']
        output['test_case_id'] = sqlRow['test_case_id']
        output['test_item_id'] = sqlRow['test_item_id']
        output['type_id'] = sqlRow['type_id']
        output['location_id'] = sqlRow['location_id']
        output['key'] = sqlRow['key']
        output['value'] = sqlRow['value']
        output['update_at'] = util.dateToStr(self, sqlRow['update_at'])
        output['create_at'] = util.dateToStr(self, sqlRow['create_at'])
        return output

    # 取得 TestItem  靠 test case id
    def get_testValue_by_tv_id(self, logger, testItem_id, user_id):
        get_testValue_command = db.select([TableTestValue.stru_testValue]).where(db.and_(
            TableTestValue.stru_testValue.c.id == testItem_id, TableTestValue.stru_testValue.c.disabled == False))
        logger.debug("get_testValue_command: {0}".format(get_testValue_command))
        result = util.callsqlalchemy(self, get_testValue_command, logger)
        row = result.fetchone()
        output = self._deal_with_TestValueObject(row)
        return output

    # 將 TestItem 隱藏
    def del_testValue_by_tv_id(self, logger, testValue_id, user_id):

        update_testValue_command = db.update(TableTestValue.stru_testValue).where(db.and_(TableTestValue.stru_testValue.c.id == testValue_id)).values(
            disabled=True,
            update_at=datetime.datetime.now()
        ).returning(TableTestValue.stru_testValue.c.update_at,TableTestValue.stru_testValue.c.id)
        logger.debug("update_testValue_command: {0}".format(update_testValue_command))
        result = util.callsqlalchemy(self, update_testValue_command, logger)
        reMessage = result.fetchone()
        output = {}
        output['id'] = reMessage['id']
        output['update_at'] = util.dateToStr(self,reMessage['update_at'])
        return output
        # return '123'

    # 修改 TestItem 內資訊
    def modify_testValue_by_ti_id(self, logger, testValue_id, args, user_id):
        # print(type(args['is_passed']))
        print(args)
        update_testValue_command = db.update(TableTestValue.stru_testValue).where(db.and_(TableTestValue.stru_testValue.c.id == testValue_id)).values(
            key=args['key'],
            value=args['value'],   
            type_id=args['type_id'],
            location_id=args['location_id'],           
            update_at=datetime.datetime.now()
        ).returning(TableTestValue.stru_testValue.c.update_at,TableTestValue.stru_testValue.c.id)
        print(update_testValue_command)
        logger.debug("update_testValue_command: {0}".format(update_testValue_command))
        result = util.callsqlalchemy(self, update_testValue_command, logger)
        reMessage = result.fetchone()
        output = {}
        output['id'] = reMessage['id']
        output['update_at'] = util.dateToStr(self,reMessage['update_at'])
        return output

    # 取得同Issue Id 內  TestItem 的所有資訊
    def get_testValue_by_testItem_id(self, logger, testItem_id, user_id):
        get_testValue_command = db.select([TableTestValue.stru_testValue]).where(db.and_(
            TableTestValue.stru_testValue.c.test_item_id == testItem_id, TableTestValue.stru_testValue.c.disabled == False))
        logger.debug("get_testValue_command: {0}".format(get_testValue_command))
        result = util.callsqlalchemy(self, get_testValue_command, logger)
        reMessages = result.fetchall()
        i = 0
        output = {}
        for row in reMessages:
            output[i] = self._deal_with_TestValueObject(row)
            i = i+1
        return output

        # 新增同Issue Id 內  parameters 的資訊
    def post_testValue_by_testItem_id(self, logger,  testItem_id, args, user_id):
        print(args)
        print(testItem_id)
        insert_testValue_command = db.insert(TableTestValue.stru_testValue).values(
            type_id=args['type_id'],
            key=args['key'],
            value=args['value'],
            location_id=args['location_id'],
            test_item_id=testItem_id,
            test_case_id=args['testCase_id'],
            issue_id=args['issue_id'],
            project_id=args['project_id'],
            create_at=datetime.datetime.now(),
            update_at=datetime.datetime.now()
        )
        print(insert_testValue_command)
        logger.debug("insert_testValue_command: {0}".format(insert_testValue_command))
        reMessage = util.callsqlalchemy(self, insert_testValue_command, logger)
        print(reMessage)
        return {'testValue_id': reMessage.inserted_primary_key}
        # return '123'

