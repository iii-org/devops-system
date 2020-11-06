import json
import logging
from urllib.parse import urlparse
from .util import util

from flask import jsonify

logger = logging.getLogger('devops.api')


class Cicd(object):
    def __init__(self, app, pjt, iss, tc, ti, tv):
        self.app = app
        self.pjt = pjt
        self.iss = iss
        self.tc = tc
        self.ti = ti
        self.tv = tv

    def export_to_postman(self, project_id, target, jwt_identity):
        status = self.pjt.verify_project_user(logger, project_id, jwt_identity['user_id'])
        if not (status or jwt_identity['role_id'] == 5):
            return {'message': 'Don\'t have authorization to access issue list on project: {0}'
                    .format(project_id)}, 401
        output = {
            'info': {
                'name':
                    'Project id %s' % project_id,
                'schema':
                    'https://schema.getpostman.com/json/collection/v2.1.0/collection.json'
            },
            'item': []
        }

        cases = self.tc.get_testCase_by_project_id(logger, project_id, jwt_identity['user_id'])
        for case in cases:
            case_id = case['id']
            method = case['data']['method']
            path = case['data']['url']
            url = urlparse(target + path)
            items = self.ti.get_testItem_by_testCase_id(logger, case_id, jwt_identity['user_id'])
            for item in items:
                item_id = item['id']
                o_item = {'name': '{0}-{1}'.format(case_id, item_id)}
                values = []
                part_values = self.tv.get_testValue_by_testItem_id(
                    logger, item_id, jwt_identity['user_id'])
                for value in part_values:
                    values.append(value)

                try:
                    scheme = url.scheme
                    if scheme == b'':
                        scheme = ''
                    o_request = {
                        'method': method,
                        'url': {
                            'protocol': scheme,
                            'port': url.port
                        },
                        'header': []
                    }
                except ValueError:
                    return util.respond(400, 'url is malformed', {
                        'case_id': case_id,
                        'item_id': item_id,
                        'url': url
                    })

                if bool(url.hostname):
                    o_request['url']['host'] = url.hostname.split('.')
                if len(url.path) > 0:
                    o_request['url']['path'] = url.path[1:].split('/')
                o_request_body = []
                o_execs = []

                for value in values:
                    type_id = value['type_id']
                    location_id = value['location_id']
                    if type_id == 1:
                        if location_id == 1:
                            header = {}
                            if value['key'] == 'token':
                                header['key'] = 'Authorization'
                                header['value'] = 'Bearer %s' % value['value']
                                header['type'] = 'text'
                            else:
                                header['key'] = value['key']
                                header['value'] = value['value']
                            o_request['header'].append(header)
                        elif location_id == 2:
                            o_request_body.append({
                                'key': value['key'],
                                'value': value['value']
                            })
                        else:
                            pass
                    elif type_id == 2:
                        if location_id == 1:
                            pass
                        elif location_id == 2:
                            negative = ''
                            if not item['is_passed']:
                                negative = '.not'
                            o_execs.append(
                                'pm.test("value #{0}", function () {{ '
                                'pm.expect(pm.response.json().{1}).to.be{2}.eql("{3}");}});'.format(
                                    value['id'], value['key'], negative, value['value']))
                    else:
                        pass

                if bool(o_request_body):
                    o_request['body'] = {
                        'mode': 'formdata',
                        'formdata': o_request_body
                    }
                if bool(o_request):
                    o_item['request'] = o_request
                if len(o_execs) > 0:
                    o_item['event'] = [{
                        'listen': 'test',
                        'script': {
                            'type': 'text/javascript',
                            'exec': o_execs
                        }
                    }]
                output['item'].append(o_item)

        return jsonify({'message': 'success', 'data': json.dumps(output)})
