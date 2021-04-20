import json

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

SONARQUBE_DATE_FORMAT = '%Y-%m-%dT%H:%M:%S+0000'
METRICS = ('alert_status,bugs,reliability_rating,vulnerabilities,security_hotspots'
           ',security_rating,sqale_index,code_smells,sqale_rating,coverage'
           ',duplicated_blocks,duplicated_lines_density')
PAGE_SIZE = 1000


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
    __api_post(f'/permissions/add_user?login={user_login}'
               f'&projectKey={project_name}&permission=user')
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


def sq_update_password(login, new_password):
    params = {
        'login': login,
        'password': new_password
    }
    return __api_post('/users/change_password', params=params)


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
    # Final output
    ret = {}
    # First get data in db
    rows = model.Sonarqube.query.filter_by(project_name=project_name). \
        order_by(desc(model.Sonarqube.date)).all()
    latest = None
    if len(rows) > 0:
        latest = rows[0].date.strftime(SONARQUBE_DATE_FORMAT)
    for row in rows:
        ret[row.date.strftime(SONARQUBE_DATE_FORMAT)] = json.loads(row.measures)

    # Get new data and extract into return dict
    params = {
        'p': 1,
        'ps': PAGE_SIZE,
        'component': project_name,
        'metrics': METRICS
    }
    if latest is not None:
        params['from'] = latest
    fetch = {}
    while True:
        data = __api_get(f'/measures/search_history', params).json()
        for measure in data['measures']:
            metric = measure['metric']
            history = measure['history']
            for h in history:
                date = h['date']
                if 'value' in h:
                    value = h['value']
                else:
                    value = ''
                if date not in fetch:
                    fetch[date] = {}
                fetch[date][metric] = value
        if len(data) < PAGE_SIZE:
            break
        params['p'] = params['p'] + 1

    # Get branch and commit id information
    params = {'project': project_name}
    if latest is not None:
        params['from'] = latest
    res = __api_get('/project_analyses/search', params).json()
    for ana in res['analyses']:
        date = ana['date']
        git_info = ana['projectVersion'].split(':')
        if len(git_info) != 2:
            del fetch[date]
            continue
        branch = git_info[0]
        commit_id = git_info[1]
        fetch[date]['branch'] = branch
        fetch[date]['commit_id'] = commit_id

    # Write new data into db
    for (date, measures) in fetch.items():
        if date == latest:
            continue
        new = model.Sonarqube(project_name=project_name, date=date,
                              measures=json.dumps(measures))
        db.session.add(new)
        db.session.commit()
    ret.update(fetch)
    return ret


# --------------------- Resources ---------------------
class SonarqubeHistory(Resource):
    @jwt_required
    def get(self, project_name):
        return util.success({
            'link': f'{config.get("SONARQUBE_EXTERNAL_BASE_URL")}/dashboard?id={project_name}',
            'history': sq_load_measures(project_name)
        })
