from model import db, TableTestCase, TableCaseType, TableHttpMethod
from .util import util
import json
import datetime
import logging
logger = logging.getLogger('devops.api')


class TestCase(object):
    headers = {'Content-Type': 'application/json'}
    httpMethod = {"1": "GET", "2": "POST", "3": "PUT", "4":"DELETE" }


    # def _get_httpRequestMethod(self):
    #     # get_httpMethod_command = db.select(
    #     #     [TableHttpMethod.stru_httpMethod])
    #     # logger.debug("get_httpMethod_command: {0}".format(
    #     #     get_httpMethod_command))
    #     # result = util.callsqlalchemy(self, get_httpMethod_command, logger)
    #     # reMessages = result.fetchall()
    #     # httpMethod = {}
    #     # for row in reMessages:
    #     #     httpMethod[row['id']] = row['type']

    #     return httpMsethod

    def _get_testCasetType(self):
        get_testCaseType_command = db.select([TableCaseType.stru_tcType])
        logger.debug("get_testCaseType_command: {0}".format(
            get_testCaseType_command))
        result = util.callsqlalchemy(self, get_testCaseType_command, logger)
        reMessages = result.fetchall()
        caseType = {}
        for row in reMessages:
            caseType[row['id']] = row['name']
        return caseType

    def _analysis_input_case_data(self, data):

        output = data

        return output

    def _deal_with_TestCaseObject(self, sqlRow, caseType=''):
        if caseType == '':
            caseType = self._get_testCasetType()
        output = {}
        output['id'] = sqlRow['id']
        output['name'] = sqlRow['name']
        output['project_id'] = sqlRow['project_id']
        output['issue_id'] = sqlRow['issue_id']
        output['type_id'] = sqlRow['type_id']
        output['type'] = caseType[sqlRow['type_id']]
        output['description'] = sqlRow['description']
        output['data'] = json.loads(sqlRow['data'])
        output['update_at'] = util.dateToStr(self, sqlRow['update_at'])
        output['create_at'] = util.dateToStr(self, sqlRow['create_at'])
        return output

   

    # 取得 TestCase  靠 test case id
    def get_testCase_by_tc_id(self, logger, testCase_id, user_id):
        get_testCase_command = db.select([TableTestCase.stru_testCase]).where(db.and_(
            TableTestCase.stru_testCase.c.id == testCase_id, TableTestCase.stru_testCase.c.disabled == False))
        # get_param_command = db.select([TableParameter.stru_param]).where(db.and_(TableParameter.stru_param.c.id==parameters_id))
        logger.debug("get_testCase_command: {0}".format(get_testCase_command))
        result = util.callsqlalchemy(self, get_testCase_command, logger)
        row = result.fetchone()
        output = self._deal_with_TestCaseObject(row)
        return output

    # 將 TestCase 隱藏
    def del_testCase_by_tc_id(self, logger, testCase_id, user_id):

        update_testCase_command = db.update(TableTestCase.stru_testCase).where(db.and_(TableTestCase.stru_testCase.c.id == testCase_id)).values(
            disabled=True,
            update_at=datetime.datetime.now()
        ).returning(TableTestCase.stru_testCase.c.update_at,TableTestCase.stru_testCase.c.id)
        logger.debug("update_testCase_command: {0}".format(update_testCase_command))
        result = util.callsqlalchemy(self, update_testCase_command, logger)
        reMessage = result.fetchone()
        output = {}
        output['id'] = reMessage['id']
        output['update_at'] = util.dateToStr(self,reMessage['update_at'])
        return output

    # 修改 TestCase 內資訊
    def modify_testCase_by_tc_id(self, logger, testCase_id, args, user_id):

        update_testCase_command = db.update(TableTestCase.stru_testCase).where(db.and_(TableTestCase.stru_testCase.c.id == testCase_id)).values(
            data=util.jsonToStr(self, self._analysis_input_case_data(
                json.loads(args['data']))),
            name=args['name'],
            description=args['description'],
            type_id=args['type_id'],            
            update_at=datetime.datetime.now()
        ).returning(TableTestCase.stru_testCase.c.update_at,TableTestCase.stru_testCase.c.id)
        logger.debug("update_testCase_command: {0}".format(update_testCase_command))
        result = util.callsqlalchemy(self, update_testCase_command, logger)
        reMessage = result.fetchone()
        output = {}
        output['id'] = reMessage['id']
        output['update_at'] = util.dateToStr(self,reMessage['update_at'])
        return output

    # 取得同Issue Id 內  TestCase 的所有資訊
    def get_testCase_by_issue_id(self, logger, issue_id, user_id):
        caseType = self._get_testCasetType()
        get_testCase_command = db.select([TableTestCase.stru_testCase]).where(db.and_(
            TableTestCase.stru_testCase.c.issue_id == issue_id, TableTestCase.stru_testCase.c.disabled == False))
        logger.debug("get_testCase_command: {0}".format(get_testCase_command))
        result = util.callsqlalchemy(self, get_testCase_command, logger)
        reMessages = result.fetchall()
        i = 0
        output = {}
        for row in reMessages:
            output[i] = {}
            output[i] = self._deal_with_TestCaseObject(row, caseType)
            i = i+1
        return output

        # 新增同Issue Id 內  parameters 的資訊
    def post_testCase_by_issue_id(self, logger,  issue_id, args, user_id):
        insert_testCase_command = db.insert(TableTestCase.stru_testCase).values(
            issue_id=issue_id,
            project_id=args['project_id'],
            data=util.jsonToStr(self, self._analysis_input_case_data(
                json.loads(args['data']))),
            name=args['name'],
            description=args['description'],
            type_id=args['type_id'],
            create_at=datetime.datetime.now(),
            update_at=datetime.datetime.now()
        )
        logger.debug("insert_testCase_command: {0}".format(
            insert_testCase_command))
        reMessage = util.callsqlalchemy(self, insert_testCase_command, logger)
        return {'testCase_id': reMessage.inserted_primary_key}

    def get_api_method(self, logger, user_id):
        return self.httpMethod

    def get_testCase_type(self, logger, user_id):
        return self._get_testCasetType()
