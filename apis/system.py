import os
import json
import requests

from flask_restful import Resource
import util
import config
import model
import resources.apiError as apiError
import resources.kubernetesClient as kubernetesClient


class SystemInfoReport(Resource):
    def put(self):
        version_center_url = "https://version-center.iiidevops.org"
        deployer_node_ip = config.get('DEPLOYER_NODE_IP')
        if deployer_node_ip is None:
            # get the k8s cluster the oldest node ip
            deployer_node_ip = kubernetesClient.get_the_oldest_node()[0]
        output_str, error_str = util.ssh_to_node_by_key("~/deploy-devops/bin/get-sysinfo.pl", deployer_node_ip)
        if not error_str:
            # Sent system data to devops version center
            row = model.NexusVersion.query.first()
            output_str = json.loads(output_str)
            r = requests.post(f'{version_center_url}/login', params={'uuid': row.deployment_uuid})
            if r.status_code >= 200 and r.status_code < 300:
                headers = {"Authorization": f"Bearer {json.loads(r.text)['data']['access_token']}",
                           'Content-Type': 'application/json'}
                r = requests.post(f'{version_center_url}/report_info', headers=headers,
                                  params={'uuid': row.deployment_uuid}, data=json.dumps(output_str))
                return util.success()
            else:
                raise apiError.DevOpsError(503, "Can not get version-center token")
        else:
            raise apiError.DevOpsError(503, "Can not get deployer server response from ssh")
        

# noinspection PyMethodMayBeStatic
class SystemGitCommitID(Resource):
    def get(self):
        git_commit_id = ""
        git_tag = ""
        git_date = ""
        if os.path.exists("git_commit"):
            with open("git_commit") as f:
                git_commit_id = f.read().splitlines()[0]
        if os.path.exists("git_tag"):
            with open("git_tag") as f:
                git_tag = f.read().splitlines()[0]
        if os.path.exists("git_date"):
            with open("git_date") as f:
                git_date = f.read().splitlines()[0]
        return util.success({"git_commit_id": git_commit_id, "git_tag": git_tag, "git_date": git_date})
