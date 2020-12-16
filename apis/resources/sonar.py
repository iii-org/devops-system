import requests
from flask_jwt_extended import jwt_required
from flask_restful import Resource

import config
from model import db
from resources import role


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
