from model import db, TableTestItem, TableCaseType, TableHttpMethod
from .util import util
import json
import datetime
import logging
logger = logging.getLogger('devops.api')


class TestItem(object):
    headers = {'Content-Type': 'application/json'}


   

    def _deal_with_TestItemObject(self, sqlRow):
        output = {}
        output['id'] = sqlRow['id']
        output['name'] = sqlRow['name']
        output['project_id'] = sqlRow['project_id']
        output['issue_id'] = sqlRow['issue_id']
        output['is_passed'] = sqlRow['is_passed']
        output['update_at'] = util.dateToStr(self, sqlRow['update_at'])
        output['create_at'] = util.dateToStr(self, sqlRow['create_at'])
        return output

    # 取得 TestItem  靠 test case id
    def get_testItem_by_ti_id(self, logger, testItem_id, user_id):
        get_testItem_command = db.select([TableTestItem.stru_testItem]).where(db.and_(
            TableTestItem.stru_testItem.c.id == testItem_id, TableTestItem.stru_testItem.c.disabled == False))
        # get_param_command = db.select([TableParameter.stru_param]).where(db.and_(TableParameter.stru_param.c.id==parameters_id))
        logger.debug("get_testItem_command: {0}".format(get_testItem_command))
        result = util.callsqlalchemy(self, get_testItem_command, logger)
        row = result.fetchone()
        output = self._deal_with_TestItemObject(row)
        return output

    # 將 TestItem 隱藏
    def del_testItem_by_ti_id(self, logger, testItem_id, user_id):

        update_testItem_command = db.update(TableTestItem.stru_testItem).where(db.and_(TableTestItem.stru_testItem.c.id == testItem_id)).values(
            disabled=True,
            update_at=datetime.datetime.now()
        ).returning(TableTestItem.stru_testItem.c.update_at,TableTestItem.stru_testItem.c.id)
        logger.debug("update_testItem_command: {0}".format(update_testItem_command))
        result = util.callsqlalchemy(self, update_testItem_command, logger)
        reMessage = result.fetchone()
        output = {}
        output['id'] = reMessage['id']
        output['update_at'] = util.dateToStr(self,reMessage['update_at'])
        return output
        # return '123'

    # 修改 TestItem 內資訊
    def modify_testItem_by_ti_id(self, logger, testItem_id, args, user_id):
        # print(type(args['is_passed']))
        # print(bool(distutils.util.strtobool(args['is_passed'])))
        update_testItem_command = db.update(TableTestItem.stru_testItem).where(db.and_(TableTestItem.stru_testItem.c.id == testItem_id)).values(
            name=args['name'],
            is_passed=args['is_passed'],           
            update_at=datetime.datetime.now()
        ).returning(TableTestItem.stru_testItem.c.update_at,TableTestItem.stru_testItem.c.id)
        print(update_testItem_command)
        logger.debug("update_testItem_command: {0}".format(update_testItem_command))
        result = util.callsqlalchemy(self, update_testItem_command, logger)
        reMessage = result.fetchone()
        output = {}
        output['id'] = reMessage['id']
        output['update_at'] = util.dateToStr(self,reMessage['update_at'])
        return output

    # 取得同Issue Id 內  TestItem 的所有資訊
    def get_testItem_by_testCase_id(self, logger, testCase_id, user_id):
        get_testItem_command = db.select([TableTestItem.stru_testItem]).where(db.and_(
            TableTestItem.stru_testItem.c.test_case_id == testCase_id, TableTestItem.stru_testItem.c.disabled == False))
        logger.debug("get_testItem_command: {0}".format(get_testItem_command))
        result = util.callsqlalchemy(self, get_testItem_command, logger)
        reMessages = result.fetchall()
        i = 0
        output = {}
        for row in reMessages:
            output[i] = self._deal_with_TestItemObject(row)
            i = i+1
        return output

        # 新增同Issue Id 內  parameters 的資訊
    def post_testItem_by_testCase_id(self, logger,  testCase_id, args, user_id):
        insert_testItem_command = db.insert(TableTestItem.stru_testItem).values(
            test_case_id=testCase_id,
            project_id=args['project_id'],
            issue_id=args['issue_id'],
            name=args['name'],
            is_passed= args['is_passed'],
            create_at=datetime.datetime.now(),
            update_at=datetime.datetime.now()
        )
        logger.debug("insert_testItem_command: {0}".format(
            insert_testItem_command))
        reMessage = util.callsqlalchemy(self, insert_testItem_command, logger)
        return {'testItem_id': reMessage.inserted_primary_key}
        # return '123'

