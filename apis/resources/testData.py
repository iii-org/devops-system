
from model import db, TableTestCase, TableCaseType, TableHttpMethod, TableRequirement
from .util import util

from .redmine import Redmine
from .testCase import TestCase
from .testItem import TestItem
from .testValue import TestValue


import json
import datetime
import logging



class TestData(object):

    def analysis_testData(self,logger, data,user_id):
        output = {}
        i = 0 
        for key in data['testCase']:
            print(key)
            temp = {}
            temp ['name'] = data['testCase'][key]['name']
            temp ['description'] = data['testCase'][key]['description']
            output[i] = temp
            i = i =1

        return output
