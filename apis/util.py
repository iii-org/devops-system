import json
import os
import random
import string
import time
from datetime import datetime
from threading import Thread

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


def tick(message='', init=False):
    global ticker
    now = time.time()
    if init:
        if message:
            print(message)
        ticker = now
        return
    elapsed = now - ticker
    print('%f seconds elapsed. [%s]' % (elapsed, message))
    ticker = now
    return elapsed


def timeit(method):
    def timed(*args, **kw):
        ts = time.time()
        ret = method(*args, **kw)
        te = time.time()
        print(f'{method.__name__} %2.2f ms' % ((te - ts) * 1000))
        return ret

    return timed


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
            error=apiError.invalid_code_path('Only GET/PUT/POST/DELETE is allowed, but'
                                             '{0} provided.'.format(method)))


def enable_k8s_proxy():
    try:
        os.system("kubectl proxy &")
    except:
        pass


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


def get_random_alphanumeric_string(letters_count_each, digits_count):
    sample_str = ''.join((random.choice(string.ascii_lowercase) for _ in range(letters_count_each)))
    sample_str += ''.join((random.choice(string.ascii_uppercase) for _ in range(letters_count_each)))
    sample_str += ''.join((random.choice(string.digits) for _ in range(digits_count)))

    # Convert string to list and shuffle it to mix letters and digits
    sample_list = list(sample_str)
    random.shuffle(sample_list)
    final_string = ''.join(sample_list)
    return final_string


class DevOpsThread(Thread):
    def __init__(self, group=None, target=None, name=None, args=(), kwargs=None):
        if kwargs is None:
            kwargs = {}
        Thread.__init__(self, group, target, name, args, kwargs)
        self._return = None
        self.error = None

    def run(self):
        if self._target is not None:
            try:
                self._return = self._target(*self._args, **self._kwargs)
            except Exception as e:
                self.error = e

    def join_(self, *args):
        Thread.join(self, *args)
        if self.error:
            raise self.error
        return self._return


class ServiceBatchOpHelper:
    def __init__(self, services, targets, service_args):
        self.services = services
        self.targets = targets
        self.service_args = service_args
        self.errors = {}
        self.outputs = {}

    def run(self):
        threads = {}
        for service in self.services:
            self.errors[service] = None
            threads[service] = DevOpsThread(target=self.targets[service],
                                            args=self.service_args[service])
            threads[service].start()

        for service in self.services:
            try:
                self.outputs[service] = threads[service].join_()
            except Exception as e:
                self.errors[service] = e
