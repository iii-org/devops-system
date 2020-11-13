import re
import urllib
from datetime import datetime

import requests
from flask_jwt_extended import jwt_required, get_jwt_identity
from flask_restful import Resource, reqparse

import config
import resources.apiError as apiError
import resources.util as util
from model import db, ProjectUserRole, ProjectPluginRelation, TableProjects
from resources.logger import logger
from . import role
from .gitlab import GitLab
from .rancher import Rancher
from .redmine import Redmine
from .user import User, get_3pt_user_ids

redmine = Redmine()
gitlab = GitLab()
rancher = Rancher()


def get_project_plugin_relation(project_id):
    select_project_relation_command = db.select([ProjectPluginRelation.stru_project_plug_relation]) \
        .where(db.and_(ProjectPluginRelation.stru_project_plug_relation.c.project_id == project_id))
    return util.call_sqlalchemy(select_project_relation_command).fetchone()


def verify_project_user(project_id, user_id):
    if util.is_dummy_project(project_id):
        return True
    select_project_user_role_command = db.select([ProjectUserRole.stru_project_user_role]).where(
        db.and_(ProjectUserRole.stru_project_user_role.c.project_id == project_id,
                ProjectUserRole.stru_project_user_role.c.user_id == user_id))
    match_list = util.call_sqlalchemy(select_project_user_role_command).fetchall()
    if len(match_list) > 0:
        return True
    else:
        return False


# List all projects of a PM
def get_pm_project_list(user_id):
    # 查詢db該pm負責的project_id並存入project_ids array
    result = db.engine.execute(
        "SELECT project_id FROM public.project_user_role WHERE user_id = '{0}' "
        "ORDER BY project_id DESC".format(user_id))
    project_ids = result.fetchall()
    result.close()
    if project_ids is None:
        return util.respond(500, "Cannot get project list.",
                            error=apiError.db_error("List projects returns None."))
    output_array = []
    # 用project_id依序查詢redmine的project_id
    for project_id in project_ids:
        project_id = project_id[0]
        if project_id is None or project_id == -1:
            continue
        result = db.engine.execute(
            "SELECT plan_project_id FROM public.project_plugin_relation WHERE "
            "project_id = '{0}'".format(project_id))
        fetch = result.fetchone()
        if fetch is None:
            continue
        plan_project_id = fetch[0]
        result.close()

        # 用redmine api查詢相關資訊
        # 抓專案最近更新時間
        output1 = redmine.rm_get_project(plan_project_id).json()
        # 抓專案狀態＆專案工作進度＆進度落後數目
        output2 = redmine.rm_get_issues_by_project(plan_project_id).json()
        closed_count = 0
        overdue_count = 0
        for issue in output2["issues"]:
            if issue["status"]["name"] == "Closed":
                closed_count += 1
            if issue["due_date"] is not None:
                if (datetime.today() > datetime.strptime(
                        issue["due_date"], "%Y-%m-%d")):
                    overdue_count += 1

        project_status = "進行中"
        if output2["total_count"] == 0:
            project_status = "未開始"
        if closed_count == output2["total_count"] and output2["total_count"] != 0:
            project_status = "已結案"

        # 查詢專案名稱＆專案說明＆專案狀態
        result = db.engine.execute(
            "SELECT * FROM public.projects WHERE id = '{0}'".format(
                project_id))
        project_info = result.fetchone()
        result.close()

        # 查詢專案負責人id & name
        result = db.engine.execute(
            "SELECT user_id FROM public.project_user_role"
            " WHERE project_id = '{0}' AND role_id = '{1}'".format(
                project_id, role.PM))
        user_id = result.fetchone()[0]
        result.close()

        result = db.engine.execute(
            "SELECT name FROM public.user WHERE id = '{0}'".format(
                user_id))
        user_name = result.fetchone()[0]
        result.close()

        # # 查詢sonar_quality_score
        # project_name = project_info["name"]
        # # print(project_name)
        # # project_name = "devops-flask"
        # url = "http://{0}/api/measures/component?component={1}
        # &metricKeys=reliability_rating,security_rating,security_review_rating,sqale_rating".format( \
        #     config.get("SONAR_IP_PORT"), project_name)
        # logger.info("get sonar report url: {0}".format(url))
        # output = requests.get(url,
        #                       headers=self.headers,
        #                       verify=False)
        # logger.info("get sonar report output: {0} / {1}".format(
        #     output, output.json()))
        # quality_score = None
        # if output.status_code == 200:
        #     quality_score = 0
        #     data_list = output.json()["component"]["measures"]
        #     for data in data_list:
        #         # print(type(data["value"]))
        #         rating = float(data["value"])
        #         quality_score += (
        #                                  6 - rating) * 5  # A-25, B-20, C-15, D-10, E-5

        redmine_url = "http://{0}/projects/{1}".format(config.get("REDMINE_IP_PORT"), plan_project_id)
        project_output = {
            "id": project_id,
            "name": project_info["name"],
            "display": project_info["display"],
            "description": project_info["description"],
            "git_url": project_info["http_url"],
            "redmine_url": redmine_url,
            "disabled": project_info["disabled"],
            "pm_user_id": user_id,
            "pm_user_name": user_name,
            "updated_time": output1["project"]["updated_on"],
            "project_status": project_status,
            "closed_count": closed_count,
            "total_count": output2["total_count"],
            "overdue_count": overdue_count,
            # "quality_score": quality_score
        }

        output_array.append(project_output)

    return util.success({"project_list": output_array})


# 新增redmine & gitlab的project並將db相關table新增資訊
def create_project(user_id, args):
    if args["description"] is None:
        args["description"] = ""
    if args['display'] is None:
        args['display'] = args['name']

    # 建立順序為 redmine, gitlab, rancher, api server，有失敗時 rollback 依此次序處理

    # 建立redmine project
    redmine_output, output_status = redmine.rm_create_project(args)
    try:
        redmine_pj_id = redmine_output.json()["project"]["id"]
    except Exception:
        return util.respond(500, "Error while creating redmine project",
                            error=apiError.redmine_error(redmine_output))

    if redmine_output.status_code != 201:
        status_code = redmine_output.status_code
        resp = redmine_output.json()
        error = None
        if status_code == 422 and 'errors' in resp:
            if len(resp['errors']) > 0:
                if resp['errors'][0] == 'Identifier has already been taken':
                    error = apiError.identifier_has_been_token(args['name'])
        return util.respond(status_code, {"redmine": resp}, error=error)

    # 建立gitlab project
    gitlab_output = gitlab.gl_create_project(args)

    if gitlab_output.status_code != 201:
        # Rollback
        redmine.rm_delete_project(redmine_pj_id)

        status_code = gitlab_output.status_code
        if status_code == 400:
            try:
                gitlab_json = gitlab_output.json()
                if gitlab_json['message']['name'][0] == 'has already been taken':
                    return util.respond(
                        status_code, {"gitlab": gitlab_json},
                        error=apiError.identifier_has_been_token(args['name'])
                    )
            except (KeyError, IndexError):
                pass
        return util.respond(status_code, {"gitlab": gitlab_output.json()})

    # 寫入db
    gitlab_json = gitlab_output.json()
    gitlab_pj_id = gitlab_json["id"]
    gitlab_pj_name = gitlab_json["name"]
    gitlab_pj_ssh_url = gitlab_json["ssh_url_to_repo"]
    gitlab_pj_http_url = gitlab_json["http_url_to_repo"]

    # 寫入projects
    db.engine.execute(
        "INSERT INTO public.projects (name, display, description, ssh_url, http_url, disabled)"
        " VALUES ('{0}', '{1}', '{2}', '{3}', '{4}', '{5}')".format(
            gitlab_pj_name, args['display'], args["description"],
            gitlab_pj_ssh_url, gitlab_pj_http_url,
            args["disabled"]))

    # 查詢寫入projects的project_id
    result = db.engine.execute(
        "SELECT id FROM public.projects WHERE name = '{0}'".format(gitlab_pj_name))
    project_id = result.fetchone()[0]
    result.close()

    # enable rancher pipeline
    rancher_project_id = rancher.rc_get_project_id()
    rancher_pipeline_id = rancher.rc_enable_project_pipeline(gitlab_pj_http_url)

    # 加關聯project_plugin_relation
    db.engine.execute(
        "INSERT INTO public.project_plugin_relation"
        " (project_id, plan_project_id, git_repository_id, ci_project_id, ci_pipeline_id)"
        " VALUES ('{0}', '{1}', '{2}', '{3}', '{4}')".format(
            project_id, redmine_pj_id, gitlab_pj_id, rancher_project_id, rancher_pipeline_id))

    # 加關聯project_user_role
    args["user_id"] = user_id
    output, status = project_add_member(project_id, args)
    if status / 100 != 2:
        return output, status

    return util.success({
        "project_id": project_id,
        "plan_project_id": redmine_pj_id,
        "git_repository_id": gitlab_pj_id
    })


def pm_update_project(project_id, args):
    result = db.engine.execute(
        "SELECT * FROM public.project_plugin_relation WHERE project_id = '{0}'".format(
            project_id))
    project_relation = result.fetchone()
    result.close()

    redmine_project_id = project_relation["plan_project_id"]
    gitlab_project_id = project_relation["git_repository_id"]

    if args["name"] is None:
        result = db.engine.execute(
            "SELECT name FROM public.projects WHERE id = '{0}'".format(
                project_id))
        args["name"] = result.fetchone()[0]
        result.close()
    if args["display"] is None:
        result = db.engine.execute(
            "SELECT name FROM public.projects WHERE id = '{0}'".format(
                project_id))
        args["display"] = result.fetchone()[0]
        result.close()
    if args["description"] is None:
        result = db.engine.execute(
            "SELECT description FROM public.projects WHERE id = '{0}'".format(
                project_id))
        args["description"] = result.fetchone()[0]
        result.close()

    # 更新gitlab project
    gitlab_output = gitlab.gl_update_project(gitlab_project_id, args["description"])
    if gitlab_output.status_code != 200:
        return util.respond(gitlab_output.status_code, "Error while updating project.",
                            error=apiError.gitlab_error(gitlab_output))

    # 更新redmine project
    redmine_output = redmine.rm_update_project(redmine_project_id, args)
    if redmine_output.status_code != 204:
        return util.respond(redmine_output.status_code, "Error while updating project.",
                            error=apiError.redmine_error(redmine_output))

    # 修改db
    # 修改projects
    fields = ['name', 'display', 'description', 'disabled']
    for field in fields:
        if args[field] is not None:
            db.engine.execute(
                "UPDATE public.projects SET {0} = '{1}' WHERE id = '{2}'".format(
                    field, args[field], project_id))

    # 修改project_user_role
    if args["user_id"] is not None:
        user_id = args['user_id']
        db.engine.execute(
            "UPDATE public.project_user_role SET user_id = '{0}'"
            " WHERE project_id = '{1}' AND role_id = '{2}'".format(
                user_id, project_id, User.get_role_id(user_id)))

    return util.success()


# 用project_id刪除redmine & gitlab的project並將db的相關table欄位一併刪除
def delete_project(project_id):
    # 取得gitlab & redmine project_id
    result = db.engine.execute(
        "SELECT * FROM public.project_plugin_relation WHERE project_id = '{0}'".format(
            project_id))
    project_relation = result.fetchone()
    result.close()
    if project_relation is None:
        return util.respond(404, "Error while deleting project.",
                            error=apiError.project_not_found(project_id))
    redmine_project_id = project_relation["plan_project_id"]
    gitlab_project_id = project_relation["git_repository_id"]

    # disabled rancher pipeline
    rancher.rc_disable_project_pipeline(
        project_relation["ci_project_id"],
        project_relation["ci_pipeline_id"])

    gitlab_output = gitlab.gl_delete_project(gitlab_project_id)
    if gitlab_output.status_code != 202:
        return util.respond(gitlab_output.status_code, "Error while deleting project.",
                            error=apiError.gitlab_error(gitlab_output))

    redmine_output = redmine.rm_delete_project(redmine_project_id)
    if redmine_output.status_code != 204:
        return util.respond(gitlab_output.status_code, "Error while deleting project.",
                            error=apiError.redmine_error(redmine_output))

    # 如果gitlab & redmine project都成功被刪除則繼續刪除db內相關tables欄位
    db.engine.execute(
        "DELETE FROM public.project_plugin_relation WHERE project_id = '{0}'".format(
            project_id))
    db.engine.execute(
        "DELETE FROM public.project_user_role WHERE project_id = '{0}'".format(
            project_id))
    db.engine.execute(
        "DELETE FROM public.projects WHERE id = '{0}'".format(
            project_id))

    return util.success()


# 用project_id查詢db的相關table欄位資訊
def pm_get_project(project_id):
    plan_project_id = get_plan_project_id(project_id)
    # 查詢專案名稱＆專案說明＆＆專案狀態
    if plan_project_id < 0:
        return util.respond(404, 'Error when getting project info.',
                            error=apiError.project_not_found(project_id))
    result = db.engine.execute(
        "SELECT * FROM public.projects as pj, public.project_plugin_relation as ppr "
        "WHERE pj.id = '{0}' AND pj.id = ppr.project_id".format(
            project_id))
    if result.rowcount == 0:
        result.close()
        return util.respond(404, 'Error when getting project info.',
                            error=apiError.project_not_found(project_id))
    project_info = result.fetchone()
    result.close()
    redmine_url = "http://{0}/projects/{1}".format(config.get("REDMINE_IP_PORT"), plan_project_id)
    output = {
        "project_id": project_info["project_id"],
        "name": project_info["name"],
        "display": project_info["display"],
        "description": project_info["description"],
        "disabled": project_info["disabled"],
        "git_url": project_info["http_url"],
        "redmine_url": redmine_url,
        "ssh_url": project_info["ssh_url"],
        "repository_id": project_info["git_repository_id"],
    }
    # 查詢專案負責人
    result = db.engine.execute(
        "SELECT user_id FROM public.project_user_role WHERE project_id = '{0}'"
        " AND role_id = '{1}'".format(project_id, 3))
    user_id = result.fetchone()[0]
    result.close()

    result = db.engine.execute(
        "SELECT name FROM public.user WHERE id = '{0}'".format(user_id))
    user_name = result.fetchone()[0]
    result.close()
    output["pm_user_id"] = user_id
    output["pm_user_name"] = user_name

    return util.success(output)


def project_add_member(project_id, args):
    user_id = args['user_id']
    role_id = User.get_role_id(user_id)

    # Check ProjectUserRole table has relationship or not
    get_pj_ur_rl_cmd = db.select([ProjectUserRole.stru_project_user_role]).where(db.and_(
        ProjectUserRole.stru_project_user_role.c.user_id == user_id,
        ProjectUserRole.stru_project_user_role.c.project_id == project_id,
        ProjectUserRole.stru_project_user_role.c.role_id == role_id))
    get_pj_ur_rl = util.call_sqlalchemy(get_pj_ur_rl_cmd).fetchone()
    # if ProjectUserRole table not has relationship
    if get_pj_ur_rl is None:
        # insert one relationship
        get_pj_ur_rl_cmd = db.insert(ProjectUserRole.stru_project_user_role).values(
            project_id=project_id, user_id=user_id, role_id=role_id)
        util.call_sqlalchemy(get_pj_ur_rl_cmd)
    else:
        return util.respond(422, "Error while adding user to project.",
                            error=apiError.already_in_project(user_id, project_id))

    error, redmine_user_id, gitlab_user_id = get_3pt_user_ids(
        user_id, "Error while adding user to project.")
    if error is not None:
        return error
    error, redmine_project_id, gitlab_project_id = get_3pt_project_ids(
        project_id, "Error while adding user to project.")
    if error is not None:
        return error

    redmine_role_id = User.to_redmine_role_id(role_id)
    if redmine_role_id is None:
        return util.respond(500, "Error while adding user to project.",
                            error=apiError.db_error("Cannot get redmine role of the user."))

    output, status_code = redmine.rm_create_memberships(
        redmine_project_id, redmine_user_id, redmine_role_id)
    if status_code == 201:
        pass
    elif status_code == 422:
        return util.respond(422, "Error while adding user to project: Already in redmine project.",
                            error=apiError.already_in_project(user_id, project_id))
    else:
        return util.respond(status_code, "Error while adding user to project.",
                            error=apiError.redmine_error(output))

    # gitlab project add member
    output = gitlab.gl_project_add_member(gitlab_project_id, gitlab_user_id)
    status_code = output.status_code
    if status_code == 201:
        pass
    else:
        return util.respond(status_code, "Error while adding user from project.",
                            error=apiError.gitlab_error(output))

    return util.success()


def project_remove_member(project_id, user_id):
    role_id = User.get_role_id(user_id)

    error, redmine_user_id, gitlab_user_id = get_3pt_user_ids(
        user_id, "Error while removing user from project.")
    if error is not None:
        return error
    error, redmine_project_id, gitlab_project_id = get_3pt_project_ids(
        project_id, "Error while removing user from project.")
    if error is not None:
        return error

    # get membership id
    memberships, status_code = redmine.rm_get_memberships_list(redmine_project_id)
    redmine_membership_id = None
    if status_code == 200:
        for membership in memberships.json()['memberships']:
            if membership['user']['id'] == redmine_user_id:
                redmine_membership_id = membership['id']
    if redmine_membership_id is not None:
        # delete membership
        output = redmine.rm_delete_memberships(redmine_membership_id)
        status_code = output.status_code
        if status_code == 204:
            pass
        elif status_code == 404:
            # Already deleted, let it go
            pass
        else:
            return util.respond(status_code, "Error while removing user from project.",
                                error=apiError.redmine_error(output))
    else:
        # Redmine does not have this membership, just let it go
        pass

    # gitlab project delete member
    output = gitlab.gl_project_delete_member(gitlab_project_id, gitlab_user_id)
    status_code = output.status_code
    if status_code == 204:
        pass
    else:
        return util.respond(status_code, "Error while removing user from project.",
                            error=apiError.gitlab_error(output))

    # delete relationship from  ProjectUserRole table.
    delete_pj_ur_rl_cmd = db.delete(ProjectUserRole.stru_project_user_role).where(db.and_(
        ProjectUserRole.stru_project_user_role.c.user_id == user_id,
        ProjectUserRole.stru_project_user_role.c.project_id == project_id,
        ProjectUserRole.stru_project_user_role.c.role_id == role_id))
    util.call_sqlalchemy(delete_pj_ur_rl_cmd)

    return util.success()


def get_3pt_project_ids(project_id, message):
    project_relation = get_project_plugin_relation(project_id)
    if project_relation is None:
        return util.respond(400, message,
                            error=apiError.project_not_found(project_id)), None, None
    redmine_project_id = project_relation['plan_project_id']
    gitlab_project_id = project_relation['git_repository_id']

    if redmine_project_id is None:
        return util.respond(500, message,
                            error=apiError.db_error(
                                "Cannot get redmine id of the project.")), None, None
    if gitlab_project_id is None:
        return util.respond(500, message,
                            error=apiError.db_error(
                                "Gitlab does not have this project.")), None, None

    return None, redmine_project_id, gitlab_project_id


def get_plan_project_id(project_id):
    result = db.engine.execute(
        "SELECT plan_project_id FROM public.project_plugin_relation"
        " WHERE project_id = {0}".format(project_id))
    if result.rowcount > 0:
        project = result.fetchone()
        ret = project['plan_project_id']
    else:
        ret = -1
    result.close()
    return ret


def get_projects_by_user(user_id):
    output_array = []
    result = db.engine.execute(
        "SELECT pj.id, pj.name, pj.display, ppl.plan_project_id,"
        " ppl.git_repository_id, ppl.ci_project_id, ppl.ci_pipeline_id, pj.http_url"
        " FROM public.project_user_role as pur, public.projects as pj,"
        " public.project_plugin_relation as ppl"
        " WHERE pur.user_id = {0} AND pur.project_id = pj.id AND pj.id = ppl.project_id;".format(
            user_id))
    project_list = result.fetchall()
    result.close()
    if len(project_list) == 0:
        return util.success([])
    # get user ids
    result = db.engine.execute(
        "SELECT plan_user_id, repository_user_id"
        " FROM public.user_plugin_relation WHERE user_id = {0}; ".format(
            user_id))
    userid_list_output = result.fetchone()
    if userid_list_output is None:
        return util.respond(404, "Error while getting projects of a user.",
                            error=apiError.user_not_found(user_id))
    plan_user_id = userid_list_output[0]
    result.close()
    for project in project_list:
        output_dict = {'name': project['name'],
                       'display': project['display'],
                       'project_id': project['id'],
                       'git_url': project['http_url'],
                       'redmine_url': "http://{0}/projects/{1}".format(
                           config.get("REDMINE_IP_PORT"),
                           project['plan_project_id']),
                       'repository_ids': project['git_repository_id'],
                       'issues': None,
                       'branch': None,
                       'tag': None,
                       'next_d_time': None,
                       'last_test_time': "",
                       'last_test_result': {}
                       }

        # get issue total cont
        issue_output, status_code = redmine.rm_get_issues_by_project_and_user(
            plan_user_id, project['plan_project_id'])
        total_issue = issue_output.json()
        output_dict['issues'] = total_issue['total_count']

        # get next_d_time
        issue_due_date_list = []
        for issue in total_issue['issues']:
            if issue['due_date'] is not None:
                issue_due_date_list.append(
                    datetime.strptime(issue['due_date'], "%Y-%m-%d"))
        next_d_time = None
        if len(issue_due_date_list) != 0:
            next_d_time = min(
                issue_due_date_list,
                key=lambda d: abs(d - datetime.now()))
        if next_d_time is not None:
            output_dict['next_d_time'] = next_d_time.isoformat()

        if project['git_repository_id'] is not None:
            # branch number
            branch_number, err = gitlab.gl_count_branches(project['git_repository_id'])
            if branch_number < 0:
                return err, err.status_code
            output_dict['branch'] = branch_number
            # tag number
            tag_number = 0
            output = gitlab.gl_get_tags(project['git_repository_id'])
            if output.status_code == 200:
                tag_number = len(output.json())
            output_dict['tag'] = tag_number

        if project['ci_project_id'] is not None:
            output_dict = get_ci_last_test_result(output_dict, project)

        output_array.append(output_dict)

    return util.success(output_array)


def get_ci_last_test_result(output_dict, project):
    # get rancher pipeline
    pipeline_output, response = rancher.rc_get_pipeline_executions(
        project["ci_project_id"], project["ci_pipeline_id"])
    if len(pipeline_output) != 0:
        output_dict['last_test_time'] = pipeline_output[0]['created']
        stage_status = []
        for stage in pipeline_output[0]['stages']:
            if 'state' in stage:
                stage_status.append(stage['state'])
        if 'Failed' in stage_status:
            failed_item = stage_status.index('Failed')
            output_dict['last_test_result'] = {'total': len(pipeline_output[0]['stages']),
                                               'success': failed_item}
        else:
            output_dict['last_test_result'] = {'total': len(pipeline_output[0]['stages']),
                                               'success': len(pipeline_output[0]['stages'])}
    return output_dict


def get_project_by_plan_project_id(plan_project_id):
    result = db.engine.execute(
        "SELECT * FROM public.project_plugin_relation"
        " WHERE plan_project_id = {0}".format(plan_project_id))
    project = result.fetchone()
    result.close()
    return project


def get_project_info(project_id):
    select_project_cmd = db.select([TableProjects.stru_projects]).where(
        db.and_(TableProjects.stru_projects.c.id == project_id))
    return util.call_sqlalchemy(select_project_cmd).fetchone()


class ProjectResource(object):
    def __init__(self, app, au, redmine, gitlab):
        self.app = app
        self.au = au
        self.rancher = Rancher()
        self.redmine = redmine
        self.gitlab = gitlab
        self.private_token = gitlab.private_token

    @staticmethod
    # FIXME: Eventually remove this method (extracted already)
    def verify_project_user(project_id, user_id):
        if util.is_dummy_project(project_id):
            return True
        select_project_user_role_command = db.select([ProjectUserRole.stru_project_user_role]) \
            .where(db.and_(ProjectUserRole.stru_project_user_role.c.project_id == project_id, \
                           ProjectUserRole.stru_project_user_role.c.user_id == user_id))
        logger.debug("select_project_user_role_command: {0}".format(
            select_project_user_role_command))
        reMessage = util.call_sqlalchemy(select_project_user_role_command)
        match_list = reMessage.fetchall()
        logger.info("reMessage: {0}".format(match_list))
        logger.info("reMessage len: {0}".format(len(match_list)))
        if len(match_list) > 0:
            return True
        else:
            return False

    # 用project_id及branch_name查詢project的branch
    def get_git_project_branch(self, logger, app, project_id, branch):
        url = "http://{0}/api/{1}/projects/{2}/repository/branches/{3}?private_token={4}".format( \
            config.get("GITLAB_IP_PORT"), config.get("GITLAB_API_VERSION"), project_id, branch, self.private_token)
        logger.info("get project branch url: {0}".format(url))
        output = requests.get(url, headers=self.headers, verify=False)
        logger.info("get project branch output: {0} / {1}".format(
            output, output.json()))
        if output.status_code == 200:
            return {"message": "success", "data": output.json()}, 200
        else:
            return {"message": output.json()["message"]}, output.status_code

    # 用project_id及branch_name刪除project的branch
    def delete_git_project_branch(self, logger, app, project_id, branch):
        url = "http://{0}/api/{1}/projects/{2}/repository/branches/{3}?private_token={4}".format( \
            config.get("GITLAB_IP_PORT"), config.get("GITLAB_API_VERSION"), project_id, branch, self.private_token)
        logger.info("delete project branch url: {0}".format(url))
        output = requests.delete(url, headers=self.headers, verify=False)
        logger.info("delete project branch output: {0}".format(output))
        if output.status_code == 204:
            return {"message": "success"}, 200
        else:
            return {"message": output.json()["message"]}, output.status_code

    # 用project_id查詢project的repositories
    def get_git_project_repositories(self, logger, app, project_id, branch):
        url = "http://{0}/api/{1}/projects/{2}/repository/tree?private_token={3}&ref={4}".format( \
            config.get("GITLAB_IP_PORT"), config.get("GITLAB_API_VERSION"), project_id, self.private_token, branch)
        logger.info("get project repositories url: {0}".format(url))
        output = requests.get(url, headers=self.headers, verify=False)
        logger.info("get project repositories output: {0} / {1}".format(
            output, output.json()))
        if output.status_code == 200:
            return {
                       "message": "success",
                       "data": {
                           "file_list": output.json()
                       }
                   }, 200
        else:
            return {"message": output.json()["message"]}, output.status_code

    # 用project_id及branch_name及file_path查詢project的file
    def get_git_project_file(self, logger, app, project_id, branch, file_path):
        url = "http://{0}/api/{1}/projects/{2}/repository/files/{3}?private_token={4}&ref={5}".format( \
            config.get("GITLAB_IP_PORT"), config.get("GITLAB_API_VERSION"), project_id, file_path, self.private_token,
            branch)
        logger.info("get project file url: {0}".format(url))
        output = requests.get(url, headers=self.headers, verify=False)
        logger.info("get project file output: {0} / {1}".format(
            output, output.json()))
        if output.status_code == 200:
            return {
                       "message": "success",
                       "data": {
                           "file_name": output.json()["file_name"],
                           "file_path": output.json()["file_path"],
                           "size": output.json()["size"],
                           "encoding": output.json()["encoding"],
                           "content": output.json()["content"],
                           "content_sha256": output.json()["content_sha256"],
                           "ref": output.json()["ref"],
                           "last_commit_id": output.json()["last_commit_id"]
                       }
                   }, 200
        else:
            error_code = output.status_code
            return {"message": output.json()["message"]}, error_code

    # 用project_id及branch_name及file_path新增project的file
    def create_git_project_file(self, logger, app, project_id, args):
        url = "http://{0}/api/{1}/projects/{2}/repository/files/{3}?private_token={4}&branch={5}&start_branch={6}&encoding={7}&author_email={8}&author_name={9}&content={10}&commit_message={11}".format( \
            config.get("GITLAB_IP_PORT"), config.get("GITLAB_API_VERSION"), project_id, args["file_path"],
            self.private_token, args["branch"], args["start_branch"], args["encoding"], args["author_email"],
            args["author_name"], args["content"], args["commit_message"])
        logger.info("post project file url: {0}".format(url))
        output = requests.post(url, headers=self.headers, verify=False)
        logger.info("post project file output: {0} / {1}".format(
            output, output.json()))
        if output.status_code == 201:
            return {
                       "message": "success",
                       "data": {
                           "file_path": output.json()["file_path"],
                           "branch_name": output.json()["branch"]
                       }
                   }, 200
        else:
            error_code = output.status_code
            return {"message": output.json()["message"]}, error_code

    # 用project_id及branch_name及file_path修改project的file
    def update_git_project_file(self, logger, app, project_id, args):
        url = "http://{0}/api/{1}/projects/{2}/repository/files/{3}?private_token={4}&branch={5}&start_branch={6}&encoding={7}&author_email={8}&author_name={9}&content={10}&commit_message={11}".format( \
            config.get("GITLAB_IP_PORT"), config.get("GITLAB_API_VERSION"), project_id, args["file_path"],
            self.private_token, args["branch"], args["start_branch"], args["encoding"], args["author_email"],
            args["author_name"], args["content"], args["commit_message"])
        logger.info("put project file url: {0}".format(url))
        output = requests.put(url, headers=self.headers, verify=False)
        logger.info("put project file output: {0}".format(output))
        if output.status_code == 200:
            return {
                       "message": "success",
                       "data": {
                           "file_path": output.json()["file_path"],
                           "branch_name": output.json()["branch"]
                       }
                   }, 200
        else:
            error_code = output.status_code
            return {"message": output.json()["message"]}, error_code

    # 用project_id及branch_name及file_path刪除project的file
    def delete_git_project_file(self, logger, app, project_id, branch,
                                file_path, args):
        url = "http://{0}/api/{1}/projects/{2}/repository/files/{3}?private_token={4}&branch={5}&commit_message={6}".format( \
            config.get("GITLAB_IP_PORT"), config.get("GITLAB_API_VERSION"), project_id, file_path, self.private_token,
            branch, args["commit_message"])
        logger.info("delete project file url: {0}".format(url))
        output = requests.delete(url, headers=self.headers, verify=False)
        logger.info("delete project file output: {0}".format(output))
        if output.status_code == 204:
            return {"message": "success"}, 200
        else:
            error_code = output.status_code
            return {"message": output.json()["message"]}, error_code

    # 用project_id新增project的tag
    def create_git_project_tags(self, logger, app, project_id, args):
        url = "http://{0}/api/{1}/projects/{2}/repository/tags?private_token={3}&tag_name={4}&ref={5}&message={6}&release_description={7}".format( \
            config.get("GITLAB_IP_PORT"), config.get("GITLAB_API_VERSION"), project_id, self.private_token,
            args["tag_name"], args["ref"], args["message"], args["release_description"])
        logger.info("create project tag url: {0}".format(url))
        output = requests.post(url, headers=self.headers, verify=False)
        logger.info("create project tag output: {0} / {1}".format(
            output, output.json()))
        if output.status_code == 201:
            return {"message": "success", "data": output.json()}, 200
        else:
            return {"message": output.json()["message"]}, output.status_code

    # 用project_id及tag_name刪除project的tag
    def delete_git_project_tag(self, logger, app, project_id, tag_name):
        url = "http://{0}/api/{1}/projects/{2}/repository/tags/{3}?private_token={4}".format( \
            config.get("GITLAB_IP_PORT"), config.get("GITLAB_API_VERSION"), project_id, tag_name, self.private_token)
        logger.info("delete project tag url: {0}".format(url))
        output = requests.delete(url, headers=self.headers, verify=False)
        logger.info("delete project tag output: {0}".format(output))
        if output.status_code == 204:
            return {"message": "success"}, 200
        else:
            return {"message": output.json()["message"]}, output.status_code

    # 用project_id合併project的任兩個branches
    def create_git_project_mergebranch(self, logger, app, project_id, args):
        # 新增merge request
        url = "http://{0}/api/{1}/projects/{2}/merge_requests?private_token={3}&source_branch={4}&target_branch={5}&title={6}".format( \
            config.get("GITLAB_IP_PORT"), config.get("GITLAB_API_VERSION"), project_id, self.private_token,
            args["source_branch"], args["target_branch"], args["title"])
        logger.info("post project mergerequest url: {0}".format(url))
        output = requests.post(url, headers=self.headers, verify=False)
        logger.info("post project mergerequest output:{0} / {1}".format(
            output, output.json()))

        if output.status_code == 201:
            # 同意merge request
            merge_request_iid = output.json()["iid"]
            url = "http://{0}/api/{1}/projects/{2}/merge_requests/{3}/merge?private_token={4}".format( \
                config.get("GITLAB_IP_PORT"), config.get("GITLAB_API_VERSION"), project_id, merge_request_iid,
                self.private_token)
            logger.info("post project acceptmerge url: {0}".format(url))
            output = requests.put(url, headers=self.headers, verify=False)
            logger.info("post project acceptmerge output:{0} / {1}".format(
                output, output.json()))
            if output.status_code == 200:
                return {"message": "success"}, 200
            else:
                # 刪除merge request
                url = "http://{0}/api/{1}/projects/{2}/merge_requests/{3}?private_token={4}".format( \
                    config.get("GITLAB_IP_PORT"), config.get("GITLAB_API_VERSION"), project_id, merge_request_iid,
                    self.private_token)
                logger.info("delete project mergerequest url: {0}".format(url))
                output_extra = requests.delete(url,
                                               headers=self.headers,
                                               verify=False)
                logger.info("delete project mergerequest output:{0}".format(
                    output_extra))
                if output_extra.status_code == 204:
                    return {
                               "message":
                                   "merge failed and already delete your merge request."
                           }, 400
                else:
                    return {
                               "message": "merge failed."
                           }, output_extra.status_code
        else:
            return {"message": output.json()["message"]}, output.status_code

    # 用project_id查詢project的commits
    def get_git_project_branch_commits(self, logger, project_id, branch):
        url = "http://{0}/api/{1}/projects/{2}/repository/commits?private_token={3}&ref_name={4}&per_page=100".format(
            config.get("GITLAB_IP_PORT"), config.get("GITLAB_API_VERSION"), project_id, self.private_token, branch)
        logger.info("get project branch commits url: {0}".format(url))
        output = requests.get(url, headers=self.headers, verify=False)
        logger.info("get project branch commits output: {0} / {1}".format(
            output, output.json()))
        if output.status_code == 200:
            return {"message": "success", "data": output.json()}, 200
        else:
            return {"message": output.json()["message"]}, output.status_code

    # 用project_id查詢project的網路圖
    def get_git_project_network(self, logger, app, project_id):
        try:
            branch_commit_list = []

            # 整理各branches的commit_list
            branches = self.get_git_project_branches(logger, app, project_id)
            if branches[1] / 100 != 2:
                return branches
            for branch in branches[0]["data"]["branch_list"]:
                branch_commits = self.get_git_project_branch_commits(
                    logger, project_id, branch["name"])
                if branch_commits[1] / 100 != 2:
                    return branch_commits
                for branch_commit in branch_commits[0]["data"]:
                    obj = {
                        "id": branch_commit["id"],
                        "title": branch_commit["title"],
                        "message": branch_commit["message"],
                        "author_name": branch_commit["author_name"],
                        "committed_date": branch_commit["committed_date"],
                        "parent_ids": branch_commit["parent_ids"],
                        "branch_name": branch["name"],
                        "tags": []
                    }

                    branch_commit_list.append(obj)

            # tag_list = []

            # 整理tags
            tags = self.get_git_project_tags(logger, app, project_id)
            if tags[1] / 100 != 2:
                return tags
            for tag in tags[0]["data"]["tag_list"]:
                # tag_obj = {
                #     "tag": tag["name"],
                #     # "message": tag["message"],
                #     "commit_id": tag["commit"]["id"]
                #     # "commit_message": tag["commit"]["message"],
                #     # "author_name": tag["commit"]["author_name"],
                #     # "created_at": tag["commit"]["created_at"]
                # }

                # tag_list.append(tag_obj)
                # print(tag_obj)
                for commit in branch_commit_list:
                    if commit["id"] == tag["commit"]["id"]:
                        commit["tags"].append(tag["name"])

            data_by_time = sorted(branch_commit_list,
                                  reverse=False,
                                  key=lambda c_list: c_list["committed_date"])
            # data_del_some = data_by_time

            return {
                       "message": "success",
                       "data": data_by_time}, 200
        except Exception as error:
            import traceback
            traceback.print_exc()
            return {"message": repr(error)}, 400

    # 用project_id查詢redmine的單一project
    def get_redmine_one_project(self, logger, app, project_id):
        url = "http://{0}/projects/{1}.json?key={2}".format(
            config.get("REDMINE_IP_PORT"), project_id,
            config.get("REDMINE_API_KEY"))
        logger.info("get redmine one project url: {0}".format(url))
        output = requests.get(url, headers=self.headers, verify=False)
        logger.info("get redmine one project output: {0} / {1}".format(
            output, output.json()))
        return output

    def get_git_project_id(self, logger, app, repository_id):
        result = db.engine.execute(
            "SELECT project_id FROM public.project_plugin_relation WHERE git_repository_id = '{0}'"
                .format(repository_id))
        project_relation = result.fetchone()
        result.close()
        if project_relation:
            project_id = project_relation['project_id']
            return {"message": "success", "data": project_id}, 200
        else:
            return {
                       "message": "error",
                       "data": "No such repository_id found!"
                   }, 404

    def get_sonar_report(self, logger, app, project_id):
        result = db.engine.execute(
            "SELECT name FROM public.projects WHERE id = '{0}'".format(
                project_id))
        project_name = result.fetchone()[0]
        result.close()
        # project_name = "devops-flask"
        url = "http://{0}/api/measures/component?component={1}&metricKeys=bugs,vulnerabilities,security_hotspots,code_smells,coverage,duplicated_blocks,sqale_index,duplicated_lines_density,reliability_rating,security_rating,security_review_rating,sqale_rating,security_hotspots_reviewed,lines_to_cover".format( \
            config.get("SONAR_IP_PORT"), project_name)
        logger.info("get sonar report url: {0}".format(url))
        output = requests.get(url, headers=self.headers, verify=False)
        logger.info("get sonar report output: {0} / {1}".format(
            output, output.json()))
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

    def get_test_summary(self, logger, app, project_id, cm):
        ret = {}

        # newman
        cursor = db.engine.execute(
            'SELECT id, total, fail FROM public.test_results '
            ' WHERE project_id={0}'
            ' ORDER BY id DESC'
            ' LIMIT 1'
                .format(project_id))
        if cursor.rowcount > 0:
            row = cursor.fetchone()
            id = row['id']
            total = row['total']
            fail = row['fail']
            passed = total - fail
            ret['postman'] = {
                "id": id,
                "passed": passed,
                "failed": fail,
                "total": total
            }
        else:
            ret['postman'] = {}

        # checkmarx
        cm_json, status_code = cm.get_result(project_id)
        cm_data = {}
        for key, value in cm_json.items():
            if key != 'data':
                cm_data[key] = value
            else:
                for k2, v2 in value.items():
                    if k2 != 'stats':
                        cm_data[k2] = v2
                    else:
                        for k3, v3 in v2.items():
                            cm_data[k3] = v3
        ret['checkmarx'] = cm_data

        # sonarqube
        # qube = self.get_sonar_report(logger, app, project_id)
        # FIXME: Fill qube values after connected
        # ret["sonarqube"] = {
        #     "bug": 1,
        #     "security": 1,
        #     "security_review": 1,
        #     "maintainability": 1
        # }

        return {'message': 'success', 'data': {'test_results': ret}}, 200


class ListMyProjects(Resource):
    @jwt_required
    def get(self):
        role.require_pm()
        user_id = get_jwt_identity()["user_id"]
        return get_pm_project_list(user_id)


class SingleProject(Resource):
    @jwt_required
    def get(self, project_id):
        role.require_pm("Error while getting project info.")
        role.require_in_project(project_id, "Error while getting project info.")
        return pm_get_project(project_id)

    @jwt_required
    def put(self, project_id):
        role.require_pm("Error while updating project info.")
        role.require_in_project(project_id, "Error while updating project info.")
        parser = reqparse.RequestParser()
        parser.add_argument('name', type=str)
        parser.add_argument('display', type=str)
        parser.add_argument('user_id', type=int)
        parser.add_argument('description', type=str)
        parser.add_argument('disabled', type=bool)
        args = parser.parse_args()
        return pm_update_project(project_id, args)

    @jwt_required
    def delete(self, project_id):
        role.require_pm()
        role.require_in_project(project_id)
        return delete_project(project_id)

    @jwt_required
    def post(self):
        role.require_pm()
        user_id = get_jwt_identity()["user_id"]
        parser = reqparse.RequestParser()
        parser.add_argument('name', type=str, required=True)
        parser.add_argument('display', type=str)
        parser.add_argument('description', type=str)
        parser.add_argument('disabled', type=bool, required=True)
        args = parser.parse_args()

        pattern = "^[a-z0-9][a-z0-9-]{0,253}[a-z0-9]$"
        result = re.fullmatch(pattern, args["name"])
        if result is None:
            return util.respond(400, 'Error while creating project',
                                error=apiError.invalid_project_name(args['name']))

        return create_project(user_id, args)


class ProjectMember(Resource):
    @jwt_required
    def post(self, project_id):
        role.require_pm()
        role.require_in_project(project_id)
        parser = reqparse.RequestParser()
        parser.add_argument('user_id', type=int, required=True)
        args = parser.parse_args()
        return project_add_member(project_id, args)

    @jwt_required
    def delete(self, project_id, user_id):
        role.require_pm()
        role.require_in_project(project_id)
        return project_remove_member(project_id, user_id)


class ProjectsByUser(Resource):
    @jwt_required
    def get(self, user_id):
        role.require_user_himself(user_id, even_pm=False)
        return get_projects_by_user(user_id)
