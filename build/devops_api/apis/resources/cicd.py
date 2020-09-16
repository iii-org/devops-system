from urllib.parse import urlparse
from flask import jsonify
from .issue import Issue
from .project import Project
from .testCase import TestCase
from .testItem import TestItem
from .testValue import TestValue
import logging

logger = logging.getLogger('devops.api')


class Cicd(object):
    def __init__(self, app):
        self.pjt = Project(app)
        self.iss = Issue()
        self.tc = TestCase()
        self.ti = TestItem()
        self.tv = TestValue()

    def export_to_postman(self, app, project_id, target, jwt_identity):
        status = self.pjt.verify_project_user(logger, project_id, jwt_identity)
        if not status:
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
        args = {}
        issues, status_code = self.iss.get_issue_by_project(logger, app, project_id,
                                                       args)
        cases = []
        for issue in issues['data']:
            issue_id = issue['id']
            part_cases = self.tc.get_testCase_by_issue_id(logger, issue_id, jwt_identity)
            for case in part_cases:
                cases.append(case)

        for case in cases:
            case_id = case['id']
            method = case['data']['method']
            url = urlparse(target)
            items = self.ti.get_testItem_by_testCase_id(logger, case_id, jwt_identity)
            for item in items:
                item_id = item['id']
                o_item = {'name': '%s #%s' % (case['name'], item_id)}
                values = []
                part_values = self.tv.get_testValue_by_testItem_id(
                    logger, item_id, jwt_identity)
                for value in part_values:
                    values.append(value)

                o_request = {
                    'method': method,
                    'url': {
                        'protocol': url.scheme,
                        'port': url.port
                    },
                    'header': []
                }
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
                            o_execs.append(
                                'pm.test("value #%d", function () { '
                                'pm.expect(pm.response.json().%s).to.be.eql("%s");});'
                                % (value['id'], value['key'], value['value']))
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

        return jsonify({'message': 'success', 'data': output})