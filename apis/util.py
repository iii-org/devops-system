import json
import time
from datetime import datetime

import requests
from flask_restful import reqparse

import resources.apiError as apiError


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
# If the data may contain date or other non-JSON-serializable objects, turn has_date_etc True.
# If you need to return 201, 204 or other success, use #respond.
def success(data=None, has_date_etc=False):
    if data is None:
        return {'message': 'success'}, 200
    else:
        if has_date_etc:
            return {'message': 'success',
                    'data': json.loads(json.dumps(data, cls=DateEncoder))}, 200
        else:
            return {'message': 'success', 'data': data}, 200


def respond(status_code, message=None, data=None, error=None):
    if message is None:
        return None, status_code
    message_obj = {'message': message}
    if data is not None:
        if type(data) is dict:
            message_obj['data'] = json.loads(json.dumps(data, cls=DateEncoder))
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


def respond_uncaught_exception(exception, message='An uncaught exception occurs:'):
    return respond(500, message,
                   error=apiError.uncaught_exception(exception))


class DateEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, datetime):
            return str(obj)
        else:
            return json.JSONEncoder.default(self, obj)


ticker = 0


def reset_ticker():
    global ticker
    ticker = time.time()


def tick(message=''):
    global ticker
    now = time.time()
    print('%f seconds elapsed. [%s]' % (now - ticker, message))
    ticker = now


def api_request(method, url, headers=None, params=None, data=None, auth=None):
    body = data
    if type(data) is dict or type(data) is reqparse.Namespace:
        if 'Content-Type' not in headers:
            headers['Content-Type'] = 'application/json'
        if headers['Content-Type'] == 'application/json' and body is not None:
            body = json.dumps(data)

    if method.upper() == 'GET':
        return requests.get(url, headers=headers, params=params, verify=False, auth=auth)
    elif method.upper() == 'POST':
        return requests.post(url, data=body, params=params,
                             headers=headers, verify=False, auth=auth)
    elif method.upper() == 'PUT':
        return requests.put(url, data=body, params=params,
                            headers=headers, verify=False, auth=auth)
    elif method.upper() == 'DELETE':
        return requests.delete(url, headers=headers, params=params, verify=False, auth=auth)
    else:
        return respond_request_style(
            500, 'Error while request {0} {1}'.format(method, url),
            error=apiError.unknown_method(method))


def encode_k8s_sa(name):
    ret = ''
    for c in name:
        if 'a' <= c <= 'z' or '1' <= c <= '9' or c == '-' or c == '.':
            ret += c
        elif 'A' <= c <= 'Z':
            ret += c.lower() + '0'
        elif c == '0':
            ret += '00'
        elif c == '_':
            ret += '-0'
    return ret


def merge_zero(c):
    if c == '0':
        return '0'
    elif c == '-':
        return '_'
    else:
        return c.upper()


def decode_k8s_sa(string):
    ret = ''
    i = 0
    while i < len(string):
        c = string[i]
        if i == len(string) - 1:
            ret += c
            i += 1
            continue
        n = string[i + 1]
        if n == '0':
            nn = i + 2
            zero_count = 1
            while nn < len(string):
                if string[nn] == '0':
                    nn += 1
                    zero_count += 1
                else:
                    break
            if zero_count % 2 == 1:
                ret += merge_zero(c)
                i += 2
                zero_count -= 1
            else:
                ret += c
                i += 1
            for _ in range(0, int(zero_count / 2)):
                ret += '0'
                i += 2
        else:
            ret += c
            i += 1
    return ret
