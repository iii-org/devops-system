#!/usr/bin/python
import json, os
import subprocess
import sqlalchemy
from sqlalchemy import orm
import requests

from model import db


class util(object):
    def __init__(self):
        pass

    def util_subProc(self, cmd):
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True)
        output = proc.stdout.read()
        return output

    def util_subProc_noshell(self, cmd):
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=False)
        output = proc.stdout.read()
        return output

    def read_conf_file(self, file_location):
        imageDetails = {}
        with open(file_location) as f:
            for line in f.readlines():
                if "#" not in line and "=" in line:
                    imageDetails[line.split("=")[0].strip(None)] = line.split(
                        "=")[1].strip(None)
        return imageDetails

    def read_source_file(self, file_location):
        imageDetails = {}
        with open(file_location) as f:
            for line in f.readlines():
                if "#" not in line and "=" in line:
                    imageDetails[line.split("=")[0].replace(
                        "export", "").replace(
                            "_",
                            "").strip(None)] = line.split("=")[1].strip(None)
        return imageDetails

    def callSQL(self, command, conf, logger):
        reMessage = None
        try:
            Session = orm.sessionmaker(bind=db.engine)
            session = Session()
            commandText = sqlalchemy.text(command)
            reMessage = session.execute(commandText)
            session.close()
        except Exception as e:
            logger.error("Call SQL Fail messages: {0}".format(e))

        return reMessage

    @staticmethod
    def callsqlalchemy(command, logger):
        reMessage = None

        DBSession = orm.sessionmaker(bind=db.engine)
        session = DBSession()
        try:
            reMessage = session.execute(command)
            #logger.info("Call SQL successful messages: {0}".format(type(reMessage)))
            session.commit()
            session.close()
            return reMessage
        except Exception as error:
            session.rollback()
            logger.error("Call SQL Fail messages: {0}".format(str(error)))

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
            #logger.debug("Post api waste time: {0}".format(
            #    callapi.elapsed.total_seconds()))
            # logger.info("Post api message is : {0}".format(callapi.text))
            return callapi

        except Exception as e:
            logger.error("callpostapi error : {0}".format(e))
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
            logger.error("callpostapi error : {0}".format(e))
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
            logger.error("callgetapi error : {0}".format(e))
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
            logger.error("calldeleteapi error : {0}".format(e))
            return e

    def jsonToStr(self,data):
        return json.dumps(data, ensure_ascii=False, separators=(',', ':'))

    def dateToStr(self, data):
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
    def success(data):
        return {'message': 'success', 'data': data}, 200

    @staticmethod
    def respond(status_code, message, data=None):
        message_obj = {'message': message}
        if data is not None:
            try:
                message_obj['data'] = json.loads(data)
            except ValueError:
                message_obj['data'] = data
        return message_obj, status_code
