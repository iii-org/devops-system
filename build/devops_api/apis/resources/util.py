#!/usr/bin/python
import json
import subprocess
import sqlalchemy
from sqlalchemy import orm
import requests

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
                    imageDetails[line.split("=")[0].strip(
                        None)] = line.split("=")[1].strip(None)
        return imageDetails

    def read_source_file(self, file_location):
        imageDetails = {}
        with open(file_location) as f:
            for line in f.readlines():
                if "#" not in line and "=" in line:
                    imageDetails[line.split("=")[0].replace("export", "").replace("_", "").strip(
                        None)] = line.split("=")[1].strip(None)
        return imageDetails

    def callSQL(self, command, conf, logger):
        reMessage = None
        try:
            engine = sqlalchemy.create_engine(conf["connection"])
            Session = orm.sessionmaker(bind=engine)
            session = Session()
            commandText = sqlalchemy.text(command)
            reMessage = session.execute(commandText)
            session.close()
        except Exception as e:
            logger.error("Call SQL Fail messages: {0}".format(e))

        return reMessage

    def callsqlalchemy(self, command, connection_string, logger):
        reMessage = None
        try:
            engine = sqlalchemy.create_engine(connection_string)
            DBSession = orm.sessionmaker(bind=engine)
            session = DBSession()
            reMessage = session.execute(command)
            session.commit()
            session.close()
            return reMessage
        except Exception as e:
            logger.error("Call SQL Fail messages: {0}".format(e))
            return e.message

    def callpostapi(self, url, parameter, logger, headers):
        try:
            logger.info("post url {0}".format(url))
            logger.info("post parameter {0}".format(parameter))
            if headers is not None:
                callapi = requests.post(url, data=json.dumps(parameter), headers=headers, verify=False)
            else:
                callapi = requests.post(url, data=json.dumps(parameter), verify=False)
            logger.info("Post api parameter is : {0}".format(parameter))
            logger.info("Post api status code is : {0}".format(callapi.status_code))
            logger.info("Post api waste time: {0}".format(callapi.elapsed.total_seconds()))
            logger.info("Post api message is : {0}".format(callapi.text))
            return callapi

        except Exception as e:
            logger.error("callpostapi error : {0}".format(e))
            return e

    def callputapi(self, url, parameter, logger, headers):
        try:
            logger.info("url {0}".format(url))
            logger.info("parameter {0}".format(parameter))

            if headers is not None:
                callapi = requests.put(url, data=parameter, headers=headers, verify=False)
            else:
                callapi = requests.put(url, data=parameter, verify=False)
            logger.info("Put api status code is : {0}".format(callapi.status_code))
            logger.debug("Put api message is : {0}".format(callapi.text))
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
            logger.info("get api status code is : {0}".format(callapi.status_code))
            logger.debug("get api message is : {0}".format(callapi.text))
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
            logger.info("delete api status code is : {0}".format(callapi.status_code))
            logger.debug("delete api message is : {0}".format(callapi.text))
            return callapi

        except Exception as e:
            logger.error("calldeleteapi error : {0}".format(e))
            return e
