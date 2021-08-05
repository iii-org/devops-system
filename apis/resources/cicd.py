from flask_jwt_extended import jwt_required
from flask_restful import Resource

import util
from plugins.checkmarx import CheckMarx
from plugins.sideex import sd_get_test_by_commit
from plugins.webinspect import wi_get_scan_by_commit
from plugins.zap import zap_get_test_by_commit
from resources import apiTest, role


def get_commit_summary(project_id, commit_id):
    return {
        'postman': apiTest.get_results_by_commit(project_id, commit_id),
        'checkmarx': CheckMarx.get_scan(project_id, commit_id),
        'sideex': sd_get_test_by_commit(project_id, commit_id),
        'webinspect': wi_get_scan_by_commit(project_id, commit_id),
        'zap': zap_get_test_by_commit(project_id, commit_id)
    }


    # f'{config.get("SONARQUBE_EXTERNAL_BASE_URL")}/dashboard?id={project_name}'
# ---------------- Resources ----------------
class CommitCicdSummary(Resource):
    @jwt_required
    def get(self, project_id, commit_id):
        role.require_pm()
        role.require_in_project(project_id)
        return util.success(get_commit_summary(project_id, commit_id))
