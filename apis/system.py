import json
import os

import requests
from flask_restful import Resource
from sqlalchemy.sql import and_
from sqlalchemy.orm.attributes import flag_modified

import config
import model
import nexus
import resources.apiError as apiError
import resources.kubernetesClient as kubernetesClient
import util
from model import (NotificationMessage, NotificationMessageRecipient, Project,
                   ProjectPluginRelation, UserPluginRelation, db)
from resources.gitlab import gitlab
from resources.notification_message import (close_notification_message,
                                            create_notification_message)


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


class send_merge_request_notification(Resource):
    def get(self):
        '''
        Get all gitlab project ids
        Call gitlab get merge request information
        send notification to assignees
        '''
        pj_rows = db.session.query(Project, ProjectPluginRelation).join(
            ProjectPluginRelation, and_(Project.is_lock == False,
                                        Project.id == ProjectPluginRelation.project_id
                                        )).all()
        for pj_row in pj_rows:
            if pj_row[1]:
                pj = gitlab.gl.projects.get(pj_row[1].git_repository_id)
                if pj:
                    p_branches = pj.protectedbranches.list()
                    mr_objs = pj.mergerequests.list(all=True)
                    if mr_objs:
                        for mr_obj in mr_objs:
                            if mr_obj.state == 'opened':
                                if len(mr_obj.assignees) == 0:
                                    for pj_member in pj.members.list(all=True):
                                        filter_and_send_notification(pj_member, mr_obj, p_branches)
                                else:
                                    for assignee in mr_obj.assignees:
                                        assignee_member = pj.members.get(assignee['id'])
                                        if verify_user_can_merge_into_this_branch(assignee_member, mr_obj, p_branches):
                                            filter_and_send_notification(assignee_member, mr_obj, p_branches)
                                        else:
                                            for pj_member in pj.members.list(all=True):
                                                filter_and_send_notification(pj_member, mr_obj, p_branches)

                            else:
                                nm_rows = NotificationMessage.query.filter_by(
                                    alert_level=201, alert_service_id=mr_obj.id).all()
                                if len(nm_rows) > 0:
                                    for nm_row in nm_rows:
                                        close_notification_message(nm_row.id)


def filter_and_send_notification(pj_member, mr_obj, p_branches):
    if is_this_not_admin_or_bot(pj_member.id) and \
            verify_user_can_merge_into_this_branch(pj_member, mr_obj, p_branches):
        nm_row = NotificationMessage.query.filter_by(alert_level=201, alert_service_id=mr_obj.id).first()
        upr_row = UserPluginRelation.query.filter_by(repository_user_id=pj_member.id).first()
        if nm_row and upr_row:
            nm_rep_row = NotificationMessageRecipient.query.filter_by(message_id=nm_row.id).first()
            user_lists = nm_rep_row.type_parameter.get('user_ids')
            if upr_row.user_id not in user_lists:
                user_lists.append(upr_row.user_id)
                nm_rep_row.type_parameter.update({"user_ids": user_lists})
                flag_modified(nm_rep_row, 'type_parameter')
                db.session.add(nm_rep_row)
                db.session.commit()
        else:
            if upr_row:
                print(
                    f"Don't assignees project_name: {pj_member.name}, MR_id: {mr_obj.id} sent notification to user {pj_member.name}")
                args = {"alert_level": 201, "title": f"Review merge request: {mr_obj.title}", "alert_service_id": mr_obj.id,
                        "message_parameter": {"mr_id": mr_obj.id}, "message": f"Merge request link:{mr_obj.web_url}",
                        "type_ids": [3], "type_parameters": {"user_ids": [upr_row.user_id]}}
                create_notification_message(args, user_id=1)


def verify_user_can_merge_into_this_branch(pj_member, mr_obj, p_branches):
    if len(p_branches) > 0:
        for protect_branch in p_branches:
            if mr_obj.target_branch == protect_branch.name \
                    and pj_member.access_level >= protect_branch.merge_access_levels[0]['access_level']:
                return True
        return False
    else:
        return True


def is_this_not_admin_or_bot(git_user_id):
    upr_row = UserPluginRelation.query.filter_by(repository_user_id=git_user_id).first()
    if upr_row:
        from resources import user as user_py
        if user_py.get_role_id(upr_row.user_id) not in (5, 6):
            return True
    return False
