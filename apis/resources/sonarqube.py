import requests
from flask_jwt_extended import jwt_required
from flask_restful import Resource, reqparse
from requests.auth import HTTPBasicAuth
from sqlalchemy import desc

import config
import model
import util
from model import db
from resources import role, apiError
# ------------- Internal API methods -------------
from resources.logger import logger

METRICS = 'quality_gate_details,alert_status,bugs,reliability_rating,'
'vulnerabilities,security_hotspots,security_rating,'
'sqale_index,code_smells,sqale_rating,coverage,duplicated_blocks,'
'duplicated_lines_density'


def __api_request(method, path, headers=None, params=None, data=None):
    if headers is None:
        headers = {}
    if params is None:
        params = {}
    if 'Content-Type' not in headers:
        headers['Content-Type'] = 'application/json'

    url = f"{config.get('SONARQUBE_INTERNAL_BASE_URL')}{path}"
    output = util.api_request(method, url, headers, params, data,
                              auth=HTTPBasicAuth(config.get('SONARQUBE_ADMIN_TOKEN'), ''))

    logger.info(f"SonarQube api {method} {url}, params={params.__str__()}, body={data},"
                f" response={output.status_code} {output.text}")
    if int(output.status_code / 100) != 2:
        raise apiError.DevOpsError(
            output.status_code,
            'Got non-2xx response from SonarQube.',
            apiError.error_3rd_party_api('SonarQube', output))
    return output


def __api_get(path, params=None, headers=None):
    return __api_request('GET', path, params=params, headers=headers)


def __api_post(path, params=None, headers=None, data=None, ):
    return __api_request('POST', path, headers=headers, data=data, params=params)


# ------------- Regular methods -------------
def sq_create_user(args):
    return __api_post(f'/users/create?login={args["login"]}&name={args["name"]}'
                      f'&password={args["password"]}')


def sq_deactivate_user(user_login):
    return __api_post(f'/users/deactivate?login={user_login}')


def sq_create_project(project_name, display):
    return __api_post(f'/projects/create?name={display}&project={project_name}'
                      f'&visibility=private')


def sq_delete_project(project_name):
    return __api_post(f'/projects/delete?project={project_name}')


def sq_add_member(project_name, user_login):
    return __api_post(f'/permissions/add_user?login={user_login}'
                      f'&projectKey={project_name}&permission=codeviewer')


def sq_remove_member(project_name, user_login):
    return __api_post(f'/permissions/remove_user?login={user_login}'
                      f'&projectKey={project_name}&permission=user')


def sq_create_access_token(login):
    params = {
        'login': login,
        'name': 'iiidevops-bot'
    }
    return __api_post('/user_tokens/generate', params=params).json()['token']


# def sq_get_measures(project_name):
#     params = {
#         'metricKeys': 'quality_gate_details,alert_status,bugs,new_bugs,reliability_rating,new_reliability_rating,'
#                       'vulnerabilities,new_vulnerabilities,security_hotspots,new_security_hotspots,security_rating,'
#                       'new_security_rating,sqale_index,new_technical_debt,code_smells,new_code_smells,sqale_rating,'
#                       'new_maintainability_rating,coverage,new_coverage,duplicated_blocks,new_duplicated_blocks,'
#                       'duplicated_lines_density,new_duplicated_lines_density,new_lines',
#         'componentKey': project_name
#     }
#     return __api_get('/api/measures/component', params).json()['measures']

def sq_load_measures(project_name):
    # First get data in db
    rows = model.Sonarqube.query.filter(project_name=project_name).\
        order_by(desc(model.Sonarqube.date)).all()
    params = {
        'component': project_name,
        'metrics': METRICS
    }
    data = __api_get(f'/api/measures/search_history', params).json()
    pass


# --------------------- Resources ---------------------
class SonarScan(Resource):
    @jwt_required
    def post(self, project_name):
        parser = reqparse.RequestParser()
        parser.add_argument('branch', type=str, required=True)
        parser.add_argument('commit_id', type=str, required=True)
        args = parser.parse_args()
        return None
        # return create_scan(args)
