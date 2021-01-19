from urllib.parse import urlparse

from flask_jwt_extended import jwt_required
from flask_restful import Resource, reqparse

import util as util
from resources import apiTest, role


# noinspection PyTypeChecker
def export_to_postman(project_id, target):
    output = {
        'info': {
            'name':
                'Project id %s' % project_id,
            'schema':
                'https://schema.getpostman.com/json/collection/v2.1.0/collection.json'
        },
        'item': []
    }

    cases = apiTest.get_testcase_by_project_id(project_id)
    for case in cases:
        case_id = case['id']
        method = case['data']['method']
        path = case['data']['url']
        url = urlparse(target + path)
        items = apiTest.get_testItem_by_testCase_id(case_id)
        for item in items:
            item_id = item['id']
            o_item = {'name': '{0}-{1}'.format(case_id, item_id)}
            values = []
            part_values = apiTest.get_testValue_by_testItem_id(item_id)
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

    return util.success(output)


# --------------------- Resources ---------------------
class ExportToPostman(Resource):
    @jwt_required
    def get(self, project_id):
        role.require_in_project(project_id, "You don't have permission to create collection.")
        parser = reqparse.RequestParser()
        parser.add_argument('target', type=str, required=True)
        args = parser.parse_args()
        target = args['target']
        return export_to_postman(project_id, target)


class PostmanResults(Resource):
    @jwt_required
    def get(self, project_id):
        return util.success(apiTest.list_results(project_id))


class PostmanReport(Resource):
    @jwt_required
    def get(self, project_id):
        parser = reqparse.RequestParser()
        parser.add_argument('commit_id', type=str, required=False)
        args = parser.parse_args()
        return apiTest.get_report(project_id, args['commit_id'])

    @jwt_required
    def post(self):
        parser = reqparse.RequestParser()
        parser.add_argument('project_id', type=int, required=True)
        parser.add_argument('total', type=int, required=True)
        parser.add_argument('fail', type=int, required=True)
        parser.add_argument('branch', type=str, required=True)
        parser.add_argument('commit_id', type=str, required=True)
        parser.add_argument('report', type=str, required=True)
        args = parser.parse_args()
        role.require_in_project(project_id=args['project_id'])
        output = apiTest.save_test_result(args)
        return output
