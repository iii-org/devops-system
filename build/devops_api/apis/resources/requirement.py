import yaml
import json

from model import db

class Requirement(object):
    headers = {'Content-Type': 'application/json'}

    def requirement_by_rqmt_id(self, requirement_id,user_id):
        print('Requirement ID is :' + str(requirement_id))
        print('User ID is :'+ str(user_id))
        # requirement_flow = [
        #     {
        #         'type': "GIVEN",
	    #         'name': "設定帳號",
	    #         'description': "設定帳號參數"
        #     },
        #     {
        #         'type': "GIVEN",
	    #         'name': "設定密碼",
	    #         'description': "設定帳號參數"
        #     },
        #     {
        #         'type': "WHEN",
	    #         'name': "登入",
	    #         'description': "呼叫登入API"
        #     },
        #     {
        #         'type': "THEN",
	    #         'name': "成功登入",
	    #         'description': "可以取得登入TOKEN"
        #     },
        # ]
        # print(json.dumps(requirement_flow,ensure_ascii=False))
        # print()
        output = {'data': 'value'}
        return output
    
