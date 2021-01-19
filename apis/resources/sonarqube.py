import requests
from flask_jwt_extended import jwt_required
from flask_restful import Resource
from requests.auth import HTTPBasicAuth

import config
import util
from model import db
from resources import role, apiError
# ------------- Internal API methods -------------
from resources.logger import logger


def __api_request(method, path, headers=None, params=None, data=None):
    if headers is None:
        headers = {}
    if params is None:
        params = {}
    if 'Content-Type' not in headers:
        headers['Content-Type'] = 'application/json'

    url = f"{config.get('SONARQUBE_BASE_URL')}{path}"
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


def sq_create_project(args):
    return __api_post(f'/projects/create?name={args["display"]}&project={args["name"]}'
                      f'&visibility=private')


def sq_delete_project(project_name):
    return __api_post(f'/projects/delete?project={project_name}')


def sq_add_member(project_name, user_login):
    return __api_post(f'/permissions/add_user?login={user_login}'
                      f'&projectKey={project_name}&permission=codeviewer')


def sq_remove_member(project_name, user_login):
    return __api_post(f'/permissions/remove_user?login={user_login}'
                      f'&projectKey={project_name}&permission=user')


def get_sonar_report(project_id):
    result = db.engine.execute(
        "SELECT name FROM public.projects WHERE id = '{0}'".format(project_id))
    project_name = result.fetchone()[0]
    result.close()
    url = ("http://{0}/api/measures/component?"
           "component={1}&metricKeys=bugs,vulnerabilities,security_hotspots,code_smells,"
           "coverage,duplicated_blocks,sqale_index,duplicated_lines_density,reliability_rating,"
           "security_rating,security_review_rating,sqale_rating,security_hotspots_reviewed,"
           "lines_to_cover").format(
        config.get("SONAR_IP_PORT"), project_name)
    output = requests.get(url, headers={'Content-Type': 'application/json'}, verify=False)
    if output.status_code == 200:
        data_list = output.json()["component"]["measures"]
        reliability = []
        security = []
        security_review = []
        maintainability = []
        coverage = []
        duplications = []

        for data in data_list:
            if data["metric"] == "bugs":
                reliability.append({
                    "metric": "Bugs",
                    "value": data["value"]
                })
            if data["metric"] == "reliability_rating":
                reliability.append({
                    "metric": "Rating",
                    "value": data["value"]
                })

            if data["metric"] == "vulnerabilities":
                security.append({
                    "metric": "Vulnerabilities",
                    "value": data["value"]
                })
            if data["metric"] == "security_rating":
                security.append({
                    "metric": "Rating",
                    "value": data["value"]
                })

            if data["metric"] == "security_hotspots":
                security_review.append({
                    "metric": "Security Hotspots",
                    "value": data["value"]
                })
            if data["metric"] == "security_hotspots_reviewed":
                security_review.append({
                    "metric": "Reviewed",
                    "value": data["value"]
                })
            if data["metric"] == "security_review_rating":
                security_review.append({
                    "metric": "Rating",
                    "value": data["value"]
                })

            if data["metric"] == "sqale_index":
                maintainability.append({
                    "metric": "Debt",
                    "value": data["value"]
                })
            if data["metric"] == "code_smells":
                maintainability.append({
                    "metric": "Code Smells",
                    "value": data["value"]
                })
            if data["metric"] == "sqale_rating":
                maintainability.append({
                    "metric": "Rating",
                    "value": data["value"]
                })

            if data["metric"] == "coverage":
                coverage.append({
                    "metric": "Coverage",
                    "value": data["value"]
                })
            if data["metric"] == "lines_to_cover":
                coverage.append({
                    "metric": "Lines to cover",
                    "value": data["value"]
                })

            if data["metric"] == "duplicated_lines_density":
                duplications.append({
                    "metric": "Duplications",
                    "value": data["value"]
                })
            if data["metric"] == "duplicated_blocks":
                duplications.append({
                    "metric": "Duplicated Blocks",
                    "value": data["value"]
                })

        return {
                   "message": "success",
                   "data": {
                       "Reliability": reliability,
                       "Security": security,
                       "Security Review": security_review,
                       "Maintainability": maintainability,
                       "Coverage": coverage,
                       "Duplications": duplications
                   }
               }, 200
    else:
        error_msg_list = []
        for error in output.json()["errors"]:
            error_msg_list.append(error["msg"])
        return {"message": {"errors": error_msg_list}}, output.status_code


# --------------------- Resources ---------------------
class SonarReport(Resource):
    @jwt_required
    def get(self, project_id):
        role.require_pm()
        return get_sonar_report(project_id)
