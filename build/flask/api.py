from flask import Flask
from flask import Response
from flask import jsonify
from flask import request as flask_req
import logging
from logging import handlers

import api.util as util
import api.auth as auth

app = Flask(__name__)

@app.route("/")
def index():
    return jsonify({"message": "DevOps api is working"})

@app.route("/gitrepository", methods=['GET'])
def gitRepository():
    headers = {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer {0}'.format(au.get_token(logger))
    }
    if flask_req.method == 'GET':
        url = "https://10.50.1.55/v3/projects/c-7bl58:p-wxgdj/sourcecoderepositories"

        output = ut.callgetapi(url, logger, headers)
        return jsonify(output.json()['data'])

@app.route("/hookproject", methods=['GET', 'POST'])
def DevOpsCreateAPI():
    headers = {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer {0}'.format(au.get_token(logger))
    }
    if flask_req.method == 'GET':
        # get hook project list
        return "Hook porject api is working"
    elif flask_req.method == 'POST':
        url = "https://10.50.1.55/v3/projects/c-7bl58:p-wxgdj/pipelines"
        parameter = {
            "name": "devops-flask",
            "namespaceId": None,
            "projectId": None,
            "repositoryUrl": "http://10.50.0.20/root/devops-flask",
            "triggerWebhookPr": False,
            "triggerWebhookPush": True,
            "triggerWebhookTag": False
        }
        output = ut.callpostapi(url, parameter, logger, headers)
        return output.text
    else:
        return "API method not POST or GET"

if __name__ == "__main__":
    handler = handlers.TimedRotatingFileHandler(
        'devops-api.log', when='D'\
            , interval=1, backupCount=14)
    handler.setFormatter(logging.Formatter(
        '%(asctime)s %(filename)s [line:%(lineno)d] %(levelname)s %(message)s'\
            , '%Y %b %d, %a %H:%M:%S'))
    logger = logging.getLogger('devops.api')
    logger.setLevel(logging.DEBUG)
    logger.addHandler(handler)
    ut = util.util()
    au = auth.auth()
    app.run(host='0.0.0.0', port=10009)
    logger.info("API_IP: {0}".format(API_IP))
