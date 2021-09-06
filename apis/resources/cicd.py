from flask_jwt_extended import jwt_required
from flask_restful import Resource

import model
import util
from plugins.checkmarx import CheckMarx
from plugins.sideex import sd_get_test_by_commit
from plugins.sonarqube import sq_get_history_by_commit
from plugins.webinspect import wi_get_scan_by_commit
from plugins.zap import zap_get_test_by_commit
from resources import apiTest, role


def check_plugin_software_open(row, project_id, commit_id):
    if row.name == 'postman':
        return {'postman': apiTest.get_results_by_commit(project_id, commit_id)}
    elif row.name == 'checkmarx':
        return {'checkmarx': CheckMarx.get_scan(project_id, commit_id)}
    elif row.name == 'sideex':
        return {'sideex': sd_get_test_by_commit(project_id, commit_id)}
    elif row.name == 'sonarqube':
        return {'sonarqube': sq_get_history_by_commit(project_id, commit_id)}
    elif row.name == 'webinspect':
        return {'webinspect': wi_get_scan_by_commit(project_id, commit_id)}
    elif row.name == 'zap':
        return {'zap': zap_get_test_by_commit(project_id, commit_id)}



def get_commit_summary(project_id, commit_id):
    output = {}
    rows = model.PluginSoftware.query.filter_by(disabled=False).all()
    for row in rows:
        result = check_plugin_software_open(row, project_id, commit_id)
        if result is not None:
            output.update(result)
    return output


# ---------------- Resources ----------------
class CommitCicdSummary(Resource):
    @jwt_required
    def get(self, project_id, commit_id):
        role.require_pm()
        role.require_in_project(project_id)
        return util.success(get_commit_summary(project_id, commit_id))
