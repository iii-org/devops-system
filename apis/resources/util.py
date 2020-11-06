#!/usr/bin/python
import json
import subprocess

import requests
import sqlalchemy
import time

from flask_restful import reqparse
from sqlalchemy import orm

from model import db
from resources.error import Error


class Util(object):
    def __init__(self):
        pass

    @staticmethod
    def call_sqlalchemy(command):
        return db.engine.execute(command)

    def callpostapi(self, url, parameter, logger, headers):
        try:
            logger.info("post url {0}".format(url))
            # logger.info("post parameter {0}".format(parameter))
            if headers is not None:
                callapi = requests.post(url,
                                        data=json.dumps(parameter),
                                        headers=headers,
                                        verify=False)
            else:
                callapi = requests.post(url,
                                        data=json.dumps(parameter),
                                        verify=False)
            # logger.info("Post api parameter is : {0}".format(parameter))
            logger.info("Post api status code is : {0}".format(
                callapi.status_code))
            # logger.debug("Post api waste time: {0}".format(
            #    callapi.elapsed.total_seconds()))
            # logger.info("Post api message is : {0}".format(callapi.text))
            return callapi

        except Exception as e:
            logger.build_error("callpostapi error : {0}".format(e))
            return e

    def callputapi(self, url, parameter, logger, headers):
        try:
            logger.info("url {0}".format(url))
            # logger.info("parameter {0}".format(parameter))

            if headers is not None:
                callapi = requests.put(url,
                                       data=parameter,
                                       headers=headers,
                                       verify=False)
            else:
                callapi = requests.put(url, data=parameter, verify=False)
            logger.info("Put api status code is : {0}".format(
                callapi.status_code))
            # logger.debug("Put api message is : {0}".format(callapi.text))
            return callapi

        except Exception as e:
            logger.build_error("callpostapi error : {0}".format(e))
            return e

    def callgetapi(self, url, logger, headers):
        try:
            if headers is not None:
                callapi = requests.get(url, headers=headers, verify=False)
            else:
                callapi = requests.get(url, verify=False)
            logger.info("get api headers is : {0}".format(headers))
            logger.info("get api status code is : {0}".format(
                callapi.status_code))
            # logger.debug("get api message is : {0}".format(callapi.text))
            return callapi

        except Exception as e:
            logger.build_error("callgetapi error : {0}".format(e))
            return e

    def calldeleteapi(self, url, logger, headers):
        try:
            if headers is not None:
                callapi = requests.delete(url, headers=headers, verify=False)
            else:
                callapi = requests.delete(url, verify=False)
            logger.info("delete api headers is : {0}".format(headers))
            logger.info("delete api status code is : {0}".format(
                callapi.status_code))
            # logger.debug("delete api message is : {0}".format(callapi.text))
            return callapi

        except Exception as e:
            logger.build_error("calldeleteapi error : {0}".format(e))
            return e

    @staticmethod
    def date_to_str(data):
        if data is not None:
            return data.isoformat()
        else:
            return None

    @staticmethod
    def is_dummy_project(project_id):
        if type(project_id == str):
            return int(project_id) == -1
        else:
            return project_id == -1

    @staticmethod
    # Return 200 and success message, can with data.
    # If you need to return 201, 204 or other success, use util#respond.
    def success(data=None):
        if data is None:
            return {'message': 'success'}, 200
        else:
            return {'message': 'success', 'data': data}, 200

    @staticmethod
    def respond(status_code, message=None, data=None, error=None):
        if message is None:
            return None, status_code
        message_obj = {'message': message}
        if data is not None:
            if type(data) is dict:
                message_obj['data'] = data
            else:
                try:
                    message_obj['data'] = json.loads(data)
                except ValueError or TypeError:
                    message_obj['data'] = data
        if error is not None:
            message_obj['error'] = error
        return message_obj, status_code

    @staticmethod
    def respond_request_style(status_code, message=None, data=None, error=None):
        ret = Util.respond(status_code, message, data, error)
        ret[0]['status_code'] = ret[1]
        return ret[0]

    @staticmethod
    def tick(last_time):
        now = time.time()
        print('%f seconds elapsed.' % (now - last_time))
        return now

    @staticmethod
    def api_request(method, url, headers=None, params=None, data=None):
        if method.upper() == 'GET':
            return requests.get(url, headers=headers, params=params, verify=False)
        elif method.upper() == 'POST':
            if type(data) is dict or type(data) is reqparse.Namespace:
                if 'Content-Type' not in headers:
                    headers['Content-Type'] = 'application/json'
                return requests.post(url, data=json.dumps(data), params=params,
                                     headers=headers, verify=False)
            else:
                return requests.post(url, data=data, params=params,
                                     headers=headers, verify=False)
        elif method.upper() == 'PUT':
            return requests.put(url, data=json.dumps(data), params=params,
                                headers=headers, verify=False)
        elif method.upper() == 'DELETE':
            return requests.delete(url, headers=headers, params=params, verify=False)
        else:
            return Util.respond_request_style(
                500, 'Error while request {0} {1}'.format(method, url),
                error=Error.unknown_method(method))
