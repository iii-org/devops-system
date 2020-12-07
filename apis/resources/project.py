import re
from datetime import datetime

from flask_jwt_extended import jwt_required, get_jwt_identity
from flask_restful import Resource, reqparse
from sqlalchemy import desc
from sqlalchemy.orm.exc import NoResultFound

import config
import model
import resources.apiError as apiError
import util as util
from model import db
from resources.apiError import DevOpsError
from . import role, user, harbor, kubernetesClient
from .checkmarx import checkmarx
from .gitlab import gitlab
from .rancher import rancher
from .redmine import redmine


def get_project_plugin_relation(project_id):
    try:
        return model.ProjectPluginRelation.query.filter_by(project_id=project_id).one()
    except NoResultFound:
        raise DevOpsError(404, 'Error when getting project relations.',
                          error=apiError.project_not_found(project_id))


def list_projects(user_id):
    query = db.session.query(model.Project, model.ProjectPluginRelation) \
        .join(model.ProjectPluginRelation) \
        .join(model.ProjectUserRole,
              model.ProjectUserRole.project_id == model.Project.id)
    # 如果是 admin，列出所有 project
    # 如果不是 admin，取得 user_id 有參加的 project 列表
    if user.get_role_id(user_id) != role.ADMIN.id:
        query = query.filter(model.ProjectUserRole.user_id == user_id)
    rows = query.order_by(desc(model.Project.id)).all()

    project_id_list = []
    for row in rows:
        project_id_list.append(row.Project.id)

    pm_map = {}
    pms = db.session.query(model.User, model.Project.id) \
        .join(model.ProjectUserRole,
              model.ProjectUserRole.user_id == model.User.id) \
        .filter(model.ProjectUserRole.project_id.in_(project_id_list),
                model.ProjectUserRole.role_id.in_((role.PM.id, role.ADMIN.id))) \
        .all()
    for pm in pms:
        pm_map[pm.id] = pm.User

    projects = redmine.rm_list_projects()
    issues = redmine.rm_list_issues()

    output_array = []
    for row in rows:
        project_id = row.Project.id
        if project_id == -1:
            continue
        plan_project_id = row.ProjectPluginRelation.plan_project_id
        if plan_project_id is None:
            continue

        closed_count = 0
        overdue_count = 0
        total_count = 0
        for issue in issues:
            if issue['project']['id'] != plan_project_id:
                continue
            if issue["status"]["name"] == "Closed":
                closed_count += 1
            if issue["due_date"] is not None:
                if (datetime.today() > datetime.strptime(
                        issue["due_date"], "%Y-%m-%d")):
                    overdue_count += 1
            total_count += 1
            del issue

        project_status = "進行中"
        if total_count == 0:
            project_status = "未開始"
        if closed_count == total_count and total_count != 0:
            project_status = "已結案"

        pm = pm_map[project_id]
        if pm is None:
            pm = model.User(id=0, name='No One')

        updated_on = None
        for pjt in projects:
            if pjt['id'] == plan_project_id:
                updated_on = pjt['updated_on']
                del pjt
                break

        redmine_url = "http://{0}/projects/{1}".format(config.get("REDMINE_IP_PORT"), plan_project_id)
        output_array.append({
            "id": project_id,
            "name": row.Project.name,
            "display": row.Project.display,
            "description": row.Project.description,
            "git_url": row.Project.http_url,
            "redmine_url": redmine_url,
            "disabled": row.Project.disabled,
            "pm_user_id": pm.id,
            "pm_user_name": pm.name,
            "updated_time": updated_on,
            "project_status": project_status,
            "closed_count": closed_count,
            "total_count": total_count,
            "overdue_count": overdue_count
        })

    return util.success({"project_list": output_array})


# 新增redmine & gitlab的project並將db相關table新增資訊
def create_project(user_id, args):
    if args["description"] is None:
        args["description"] = ""
    if args['display'] is None:
        args['display'] = args['name']

    # 建立順序為 redmine, gitlab, rancher, k8s-namespace, api server，有失敗時 rollback 依此次序處理

    # 建立redmine project
    try:
        redmine_output = redmine.rm_create_project(args)
    except DevOpsError as e:
        status_code = e.status_code
        resp = e.unpack_response()
        print(resp)
        if status_code == 422 and 'errors' in resp:
            if len(resp['errors']) > 0:
                if resp['errors'][0] == 'Identifier has already been taken':
                    raise DevOpsError(status_code, 'Redmine already used this identifier.',
                                      error=apiError.identifier_has_been_token(args['name']))
        raise e

    redmine_pj_id = redmine_output["project"]["id"]

    # 建立gitlab project
    try:
        gitlab_json = gitlab.gl_create_project(args)
    except DevOpsError as e:
        # Rollback
        redmine.rm_delete_project(redmine_pj_id)
        status_code = e.status_code
        gitlab_json = e.unpack_response()
        if status_code == 400:
            try:
                if gitlab_json['message']['name'][0] == 'has already been taken':
                    raise DevOpsError(
                        status_code, {"gitlab": gitlab_json},
                        error=apiError.identifier_has_been_token(args['name'])
                    )
            except (KeyError, IndexError):
                pass
        raise e

    gitlab_pj_id = gitlab_json["id"]
    gitlab_pj_name = gitlab_json["name"]
    gitlab_pj_ssh_url = gitlab_json["ssh_url_to_repo"]
    gitlab_pj_http_url = gitlab_json["http_url_to_repo"]

    # enable rancher pipeline
    rancher_project_id = rancher.rc_get_project_id()
    rancher_pipeline_id = rancher.rc_enable_project_pipeline(gitlab_pj_http_url)
    
    # create namespace in kubernetes
    kubernetesClient.create_namespace(args['name'])

    try:
        harbor_pj_id = harbor.hb_create_project(args['name'])
    except DevOpsError as e:
        redmine.rm_delete_project(redmine_pj_id)
        gitlab.gl_delete_project(gitlab_pj_id)
        rancher.rc_disable_project_pipeline(gitlab_pj_http_url)
        raise e
    
    try:
        new_pjt = model.Project(
            name=gitlab_pj_name,
            display=args['display'],
            description=args['description'],
            ssh_url=gitlab_pj_ssh_url,
            http_url=gitlab_pj_http_url,
            disabled=args['disabled']
        )
        db.session.add(new_pjt)
        db.session.commit()
        project_id = new_pjt.id

        # 加關聯project_plugin_relation
        new_relation = model.ProjectPluginRelation(
            project_id=project_id,
            plan_project_id=redmine_pj_id,
            git_repository_id=gitlab_pj_id,
            harbor_project_id=harbor_pj_id,
            ci_project_id=rancher_project_id,
            ci_pipeline_id=rancher_pipeline_id
        )
        db.session.add(new_relation)
        db.session.commit()

        # 加關聯project_user_role
        args['user_id'] = user_id
        project_add_member(project_id, args)

        return util.success({
            "project_id": project_id,
            "plan_project_id": redmine_pj_id,
            "git_repository_id": gitlab_pj_id,
            "harbor_project_id": harbor_pj_id
        })
    except Exception as e:
        redmine.rm_delete_project(redmine_pj_id)
        gitlab.gl_delete_project(gitlab_pj_id)
        harbor.hb_delete_project(harbor_pj_id)
        raise e


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

    gitlab.gl_update_project(gitlab_project_id, args["description"])
    redmine.rm_update_project(redmine_project_id, args)
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
                user_id, project_id, user.get_role_id(user_id)))

    return util.success()


def try_to_delete(delete_method, argument):
    try:
        delete_method(argument)
    except DevOpsError as e:
        if e.status_code != 404:
            raise e


# 用project_id刪除redmine & gitlab的project並將db的相關table欄位一併刪除
def delete_project(project_id):
    # 取得gitlab & redmine project_id
    relation = get_project_plugin_relation(project_id)
    if relation is None:
        # 如果 project table 有髒資料，將其移除
        corr = model.Project.query.filter_by(id=project_id).first()
        if corr is not None:
            db.session.delete(corr)
            db.session.commit()
            return util.success()
        else:
            raise DevOpsError(404, "Error while deleting project.",
                              error=apiError.project_not_found(project_id))
    redmine_project_id = relation.plan_project_id
    gitlab_project_id = relation.git_repository_id
    harbor_project_id = relation.harbor_project_id

    # disabled rancher pipeline
    try:
        rancher.rc_disable_project_pipeline(
            relation.ci_project_id,
            relation.ci_pipeline_id)
    except DevOpsError as e:
        if e.status_code != 404:
            raise e

    try_to_delete(gitlab.gl_delete_project, gitlab_project_id)
    try_to_delete(redmine.rm_delete_project, redmine_project_id)
    if harbor_project_id is not None:
        try_to_delete(harbor.hb_delete_project, harbor_project_id)

    corr = model.Project.query.filter_by(id=project_id).first()
    try_to_delete(kubernetesClient.delete_namespace, corr.name)

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
    # 查詢專案名稱＆專案說明＆＆專案狀態
    try:
        plan_project_id = get_plan_project_id(project_id)
    except NoResultFound:
        raise apiError.DevOpsError(404, 'Error when getting project info.',
                                   error=apiError.project_not_found(project_id))
    result = db.engine.execute(
        "SELECT * FROM public.projects as pj, public.project_plugin_relation as ppr "
        "WHERE pj.id = '{0}' AND pj.id = ppr.project_id".format(
            project_id))
    if result.rowcount == 0:
        result.close()
        raise apiError.DevOpsError(404, 'Error when getting project info.',
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
    role_id = user.get_role_id(user_id)

    # Check ProjectUserRole table has relationship or not
    row = model.ProjectUserRole.query.filter_by(
        user_id=user_id, project_id=project_id, role_id=role_id).first()
    # if ProjectUserRole table not has relationship
    if row is not None:
        raise DevOpsError(422, "Error while adding user to project.",
                          error=apiError.already_in_project(user_id, project_id))
    # insert one relationship
    new = model.ProjectUserRole(project_id=project_id, user_id=user_id, role_id=role_id)
    db.session.add(new)
    db.session.commit()

    user_relation = user.get_user_plugin_relation(user_id=user_id)
    project_relation = get_project_plugin_relation(project_id)
    redmine_role_id = user.to_redmine_role_id(role_id)

    redmine.rm_create_memberships(project_relation.plan_project_id,
                                  user_relation.plan_user_id, redmine_role_id)
    gitlab.gl_project_add_member(project_relation.git_repository_id,
                                 user_relation.repository_user_id)
    harbor.hb_add_member(project_relation.harbor_project_id,
                         user_relation.harbor_user_id)

    return util.success()


def project_remove_member(project_id, user_id):
    role_id = user.get_role_id(user_id)

    user_relation = user.get_user_plugin_relation(user_id=user_id)
    project_relation = get_project_plugin_relation(project_id)
    if project_relation is None:
        raise apiError.DevOpsError(404, "Error while removing a member from the project.",
                                   error=apiError.project_not_found(project_id))

    # get membership id
    memberships = redmine.rm_get_memberships_list(project_relation.plan_project_id)
    redmine_membership_id = None
    for membership in memberships['memberships']:
        if membership['user']['id'] == user_relation.plan_user_id:
            redmine_membership_id = membership['id']
    if redmine_membership_id is not None:
        # delete membership
        try:
            output = redmine.rm_delete_memberships(redmine_membership_id)
        except DevOpsError as e:
            if e.status_code == 404:
                # Already deleted, let it go
                pass
            else:
                raise e
    else:
        # Redmine does not have this membership, just let it go
        pass

    try:
        gitlab.gl_project_delete_member(project_relation.git_repository_id,
                                        user_relation.repository_user_id)
    except DevOpsError as e:
        if e.status_code != 404:
            raise e

    try:
        harbor.hb_remove_member(project_relation.harbor_project_id,
                                user_relation.harbor_user_id)
    except DevOpsError as e:
        if e.status_code != 400:
            raise e

    # delete relationship from ProjectUserRole table.
    try:
        row = model.ProjectUserRole.query.filter_by(
            project_id=project_id, user_id=user_id, role_id=role_id).one()
    except NoResultFound:
        raise apiError.DevOpsError(404, 'Relation not found, project_id={0}, role_id={1}.'.format(
            project_id, role_id
        ), error=apiError.user_not_found(user_id))
    db.session.delete(row)
    db.session.commit()
    return util.success()


# May throws NoResultFound
def get_plan_project_id(project_id):
    return model.ProjectPluginRelation.query.filter_by(
        project_id=project_id).one().plan_project_id


def get_projects_by_user(user_id):
    output_array = []
    rows = db.session.query(model.ProjectPluginRelation, model.Project, model.ProjectUserRole
                            ).join(model.ProjectUserRole). \
        filter(model.ProjectUserRole.user_id == user_id,
               model.ProjectUserRole.project_id == model.Project.id,
               model.ProjectPluginRelation.project_id == model.Project.id).all()
    if len(rows) == 0:
        return util.success([])
    relation = user.get_user_plugin_relation(user_id=user_id)
    plan_user_id = relation.plan_user_id
    for row in rows:
        output_dict = {'name': row.Project.name,
                       'display': row.Project.display,
                       'project_id': row.Project.id,
                       'git_url': row.Project.http_url,
                       'redmine_url': "http://{0}/projects/{1}".format(
                           config.get("REDMINE_IP_PORT"),
                           row.ProjectPluginRelation.plan_project_id),
                       'repository_ids': row.ProjectPluginRelation.git_repository_id,
                       'issues': None,
                       'branch': None,
                       'tag': None,
                       'next_d_time': None,
                       'last_test_time': "",
                       'last_test_result': {}
                       }

        # get issue total cont
        try:
            all_issues = redmine.rm_get_issues_by_project_and_user(
                plan_user_id, row.ProjectPluginRelation.plan_project_id)
        except DevOpsError as e:
            if e.status_code == 404:
                # No record, not error
                all_issues = []
            else:
                raise e
        output_dict['issues'] = len(all_issues)

        # get next_d_time
        issue_due_date_list = []
        for issue in all_issues:
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

        git_repository_id = row.ProjectPluginRelation.git_repository_id
        # branch number
        branch_number = gitlab.gl_count_branches(git_repository_id)
        output_dict['branch'] = branch_number
        # tag number
        tag_number = 0
        tags = gitlab.gl_get_tags(git_repository_id)
        tag_number = len(tags)
        output_dict['tag'] = tag_number

        output_dict = get_ci_last_test_result(output_dict, row.ProjectPluginRelation)

        output_array.append(output_dict)

    return util.success(output_array)


def get_ci_last_test_result(output_dict, relation):
    # get rancher pipeline
    pipeline_output, response = rancher.rc_get_pipeline_executions(
        relation.ci_project_id, relation.ci_pipeline_id)
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
    return model.Project.query.filter_by(id=project_id).first()


def get_test_summary(project_id):
    ret = {}

    # newman
    row = model.TestResults.query.filter_by(project_id=project_id).order_by(desc(
        model.TestResults.id)).limit(1).first()
    if row is not None:
        test_id = row.id
        total = row.total
        fail = row.fail
        run_at = str(row.run_at)
        passed = total - fail
        ret['postman'] = {
            'id': test_id,
            'passed': passed,
            'failed': fail,
            'total': total,
            'run_at': run_at
        }
    else:
        ret['postman'] = {}

    # checkmarx
    cm_json, status_code = checkmarx.get_result(project_id)
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
    # ret["sonarqube"] = {
    #     "bug": 1,
    #     "security": 1,
    #     "security_review": 1,
    #     "maintainability": 1
    # }

    return util.success({'test_results': ret})


# --------------------- Resources ---------------------
class ListMyProjects(Resource):
    @jwt_required
    def get(self):
        user_id = get_jwt_identity()["user_id"]
        return list_projects(user_id)


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

        pattern = "^[a-z][a-z0-9-]{0,253}[a-z0-9]$"
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
        role.require_user_himself(user_id, even_pm=False,
                                  err_message="Only admin and PM can access another user's data.")
        return get_projects_by_user(user_id)


class TestSummary(Resource):
    @jwt_required
    def get(self, project_id):
        role.require_pm()
        role.require_in_project(project_id)
        return get_test_summary(project_id)


class ProjectFile(Resource):
    @jwt_required
    def post(self, project_id):
        try:
            plan_project_id = get_plan_project_id(project_id)
        except NoResultFound:
            raise apiError.DevOpsError(404, 'Error while uploading a file to a project.',
                                       error=apiError.project_not_found(project_id))

        parser = reqparse.RequestParser()
        parser.add_argument('filename', type=str)
        parser.add_argument('version_id', type=str)
        parser.add_argument('description', type=str)
        args = parser.parse_args()
        return redmine.rm_upload_to_project(plan_project_id, args)

    @jwt_required
    def get(self, project_id):
        try:
            plan_project_id = get_plan_project_id(project_id)
        except NoResultFound:
            raise apiError.DevOpsError(404, 'Error while getting project files.',
                                       error=apiError.project_not_found(project_id))
        return util.success(redmine.rm_list_file(plan_project_id))


class ProjectUserList(Resource):
    @jwt_required
    def get(self, project_id):
        parser = reqparse.RequestParser()
        parser.add_argument('exclude', type=int)
        args = parser.parse_args()
        return user.user_list_by_project(project_id, args)


def sonar_cube(project_info, requests, self, logger):
    # 查詢sonar_quality_score
    project_name = project_info["name"]
    # print(project_name)
    # project_name = "devops-flask"
    url = "http://{0}/api/measures/component?component={1}" \
          "&metricKeys=reliability_rating,security_rating," \
          "security_review_rating,sqale_rating".format(config.get("SONAR_IP_PORT"),
                                                       project_name)
    output = requests.get(url,
                          headers=self.headers,
                          verify=False)
    logger.info("get sonar report output: {0} / {1}".format(
        output, output.json()))
    quality_score = None
    if output.status_code == 200:
        quality_score = 0
        data_list = output.json()["component"]["measures"]
        for data in data_list:
            # print(type(data["value"]))
            rating = float(data["value"])
            quality_score += (6 - rating) * 5  # A-25, B-20, C-15, D-10, E-5
