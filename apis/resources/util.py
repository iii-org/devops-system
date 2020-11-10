import json
import time

import requests
from flask_restful import reqparse

from model import db
from resources.error import Error


def call_sqlalchemy(command):
    return db.engine.execute(command)


def date_to_str(data):
    if data is not None:
        return data.isoformat()
    else:
        return None


def is_dummy_project(project_id):
    if type(project_id == str):
        return int(project_id) == -1
    else:
        return project_id == -1


# Return 200 and success message, can with data.
# If you need to return 201, 204 or other success, use #respond.
def success(data=None):
    if data is None:
        return {'message': 'success'}, 200
    else:
        return {'message': 'success', 'data': data}, 200


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


def respond_request_style(status_code, message=None, data=None, error=None):
    ret = respond(status_code, message, data, error)
    ret[0]['status_code'] = ret[1]
    return ret[0]


def tick(last_time):
    now = time.time()
    print('%f seconds elapsed.' % (now - last_time))
    return now


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
        return respond_request_style(
            500, 'Error while request {0} {1}'.format(method, url),
            error=error.unknown_method(method))
