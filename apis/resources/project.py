import json
import re
from datetime import datetime
import base64

from flask_jwt_extended import jwt_required, get_jwt_identity
from flask_restful import Resource, reqparse
from kubernetes.client import ApiException
from sqlalchemy import desc, inspect
from sqlalchemy.orm.exc import NoResultFound
import config
import model
import nexus
import resources.apiError as apiError
import util as util
from model import db
from nexus import nx_get_project_plugin_relation
from resources.apiError import DevOpsError
from util import DevOpsThread
from . import user, harbor, kubernetesClient, role, sonarqube, template, webInspect, zap, sideex
from .activity import record_activity, ActionType
from .checkmarx import checkmarx
from .gitlab import gitlab
from .logger import logger
from .rancher import rancher
from .redmine import redmine


# Use lazy loading to avoid redundant db queries, build up this object like:
# NexusProject().set_project_id(4) or NexusProject().set_project_row(row)
class NexusProject:
    def __init__(self):
        self.__project_id = None
        self.__project_row = None
        self.__plugin_row = None
        self.__owner = None
        self.__extra_fields = {}

    # Usually for a single project query in an API flow
    def set_project_id(self, project_id, do_query=True):
        self.__project_id = project_id
        if do_query:
            self.get_project_row()
            self.get_plugin_row()
            self.get_owner()
        return self

    def set_plan_project_id(self, plan_project_id, do_query=True):
        row = model.ProjectPluginRelation.query.filter_by(plan_project_id=plan_project_id).one()
        self.set_project_id(row.project_id, do_query=do_query)
        return self

    def set_project_row(self, project_row):
        self.__project_row = project_row
        self.set_project_id(project_row.id)
        # Mirror data model fields to this object, so it can be used like an ORM row
        inst = inspect(model.Project)
        attr_names = [c_attr.key for c_attr in inst.mapper.column_attrs]
        for attr in attr_names:
            setattr(self, attr, getattr(project_row, attr))
        return self

    def set_plugin_row(self, plugin_row):
        self.__plugin_row = plugin_row
        self.set_project_id(plugin_row.project_id)
        return self

    # Owner is a NexusUser object
    def set_owner(self, owner):
        self.__owner = owner
        return self

    def get_project_id(self):
        if self.__project_id is None:
            raise DevOpsError(500, 'Project id or row is not set!')
        return self.__project_id

    def get_project_row(self):
        if self.__project_row is None:
            self.set_project_row(model.Project.query.filter_by(
                id=self.get_project_id()).one())
        return self.__project_row

    def get_plugin_row(self):
        if self.__plugin_row is None:
            self.set_plugin_row(model.ProjectPluginRelation.query.filter_by(
                project_id=self.get_project_id()).one())
        return self.__plugin_row

    def get_owner(self):
        if self.__owner is None:
            row = self.get_project_row()
            self.__owner = user.NexusUser().set_user_id(self.get_project_row().owner_id)
        return self.__owner

    def get_extra_fields(self):
        return self.__extra_fields

    def to_json(self):
        ret = json.loads(str(self.get_project_row()))
        ret['git_url'] = ret['http_url']
        del ret['http_url']
        ret['repository_ids'] = [self.get_plugin_row().git_repository_id]
        ret['redmine_url'] = \
            f'{config.get("REDMINE_EXTERNAL_BASE_URL")}/projects/' \
            f'{self.get_plugin_row().plan_project_id}'
        ret['harbor_url'] = \
            f'{config.get("HARBOR_EXTERNAL_BASE_URL")}/harbor/projects/' \
            f'{self.get_plugin_row().harbor_project_id}/repositories'
        ret['pm_user_id'] = self.get_owner().id
        ret['pm_user_name'] = self.get_owner().name
        ret['department'] = self.get_owner().department
        for key, value in self.get_extra_fields().items():
            ret[key] = value
        return ret

    def fill_redmine_fields(self, redmine_projects, issues):
        self.__extra_fields['updated_time'] = self.get_updated_time(redmine_projects)
        issue_stats = self.get_issue_statistics(issues)
        for key, value in issue_stats.items():
            self.__extra_fields[key] = value
        return self

    def get_updated_time(self, redmine_projects):
        ret = None
        for pjt in redmine_projects:
            if pjt['id'] == self.get_plugin_row().plan_project_id:
                ret = pjt['updated_on']
                del pjt
                break
        return ret

    def get_issue_statistics(self, issues):
        ret = {
            'closed_count': 0,
            'overdue_count': 0,
            'total_count': 0,
            'project_status': None
        }
        for issue in issues:
            if issue['project']['id'] != self.get_plugin_row().plan_project_id:
                continue
            if issue["status"]["name"] == "Closed":
                ret['closed_count'] += 1
            if issue["due_date"] is not None:
                if (datetime.utcnow() > datetime.strptime(
                        issue["due_date"], "%Y-%m-%d")):
                    ret['overdue_count'] += 1
            ret['total_count'] += 1
            del issue
        ret['project_status'] = "進行中"
        if ret['total_count'] == 0:
            ret['project_status'] = "未開始"
        if ret['closed_count'] == ret['total_count'] and ret['total_count'] != 0:
            ret['project_status'] = "已結案"
        return ret


def list_projects(user_id):
    query = db.session.query(model.Project, model.ProjectPluginRelation) \
        .join(model.ProjectPluginRelation) \
        .join(model.ProjectUserRole,
              model.ProjectUserRole.project_id == model.Project.id)
    # 如果不是admin（也就是一般RD/PM/QA），取得 user_id 有參加的 project 列表
    if user.get_role_id(user_id) != role.ADMIN.id:
        query = query.filter(model.ProjectUserRole.user_id == user_id)
    rows = query.order_by(desc(model.Project.id)).all()

    output_array = []
    redmine_projects = redmine.rm_list_projects()
    issues = redmine.rm_list_issues()
    for row in rows:
        if row.Project.id == -1:
            continue
        output_array.append(NexusProject()
                            .set_project_row(row.Project)
                            .set_plugin_row(row.ProjectPluginRelation)
                            .fill_redmine_fields(redmine_projects, issues)
                            .to_json())
    return util.success({"project_list": output_array})


# 新增redmine & gitlab的project並將db相關table新增資訊
@record_activity(ActionType.CREATE_PROJECT)
def create_project(user_id, args):
    if args["description"] is None:
        args["description"] = ""
    if args['display'] is None:
        args['display'] = args['name']
    if not args['owner_id']:
        owner_id = user_id
    else:
        owner_id = args['owner_id']
    project_name = args['name']
    # create namespace in kubernetes
    try:
        kubernetesClient.create_namespace(project_name)
        kubernetesClient.create_role_in_namespace(project_name)
        kubernetesClient.create_namespace_quota(project_name)
        kubernetesClient.create_namespace_limitrange(project_name)
    except ApiException as e:
        if e.status == 409:
            raise DevOpsError(e.status, 'Kubernetes already has this identifier.',
                              error=apiError.identifier_has_been_taken(args['name']))
        kubernetesClient.delete_namespace(project_name)
        raise e

    # 使用 multi-thread 建立各專案
    services = ['redmine', 'gitlab', 'harbor', 'sonarqube']
    targets = {
        'redmine': redmine.rm_create_project,
        'gitlab': gitlab.gl_create_project,
        'harbor': harbor.hb_create_project,
        'sonarqube': sonarqube.sq_create_project
    }
    service_args = {
        'redmine': (args,),
        'gitlab': (args,),
        'harbor': (args['name'],),
        'sonarqube': (args['name'], args['display'])
    }
    helper = util.ServiceBatchOpHelper(services, targets, service_args)
    helper.run()

    # 先取出已成功的專案建立 id，以便之後可能的回溯需求
    redmine_pj_id = None
    gitlab_pj_id = None
    gitlab_pj_name = None
    gitlab_pj_ssh_url = None
    gitlab_pj_http_url = None
    harbor_pj_id = None
    project_name = args['name']

    for service in services:
        if helper.errors[service] is None:
            output = helper.outputs[service]
            if service == 'redmine':
                redmine_pj_id = output["project"]["id"]
            elif service == 'gitlab':
                gitlab_pj_id = output["id"]
                gitlab_pj_name = output["name"]
                gitlab_pj_ssh_url = output["ssh_url_to_repo"]
                gitlab_pj_http_url = output["http_url_to_repo"]
            elif service == 'harbor':
                harbor_pj_id = output

    # 如果不是全部都成功，rollback
    if any(helper.errors.values()):
        kubernetesClient.delete_namespace(project_name)
        for service in services:
            if helper.errors[service] is None:
                if service == 'redmine':
                    redmine.rm_delete_project(redmine_pj_id)
                elif service == 'gitlab':
                    gitlab.gl_delete_project(gitlab_pj_id)
                elif service == 'harbor':
                    harbor_param = [harbor_pj_id, project_name]
                    harbor.hb_delete_project(harbor_param)
                elif service == 'sonarqube':
                    sonarqube.sq_delete_project(project_name)

        # 丟出服務序列在最前的錯誤
        for service in services:
            e = helper.errors[service]
            if e is not None:
                if service == 'redmine':
                    status_code = e.status_code
                    resp = e.unpack_response()
                    if status_code == 422 and 'errors' in resp:
                        if len(resp['errors']) > 0:
                            if resp['errors'][0] == 'Identifier has already been taken':
                                raise DevOpsError(status_code, 'Redmine already used this identifier.',
                                                  error=apiError.identifier_has_been_taken(args['name']))
                    raise e
                elif service == 'gitlab':
                    status_code = e.status_code
                    gitlab_json = e.unpack_response()
                    if status_code == 400:
                        try:
                            if gitlab_json['message']['name'][0] == 'has already been taken':
                                raise DevOpsError(
                                    status_code, {"gitlab": gitlab_json},
                                    error=apiError.identifier_has_been_taken(args['name'])
                                )
                        except (KeyError, IndexError):
                            pass
                    raise e
                else:
                    raise e
    try:
        # enable rancher pipeline
        rancher.rc_get_project_id()
        t_rancher = DevOpsThread(target=rancher.rc_enable_project_pipeline,
                                 args=(gitlab_pj_http_url,))
        t_rancher.start()
        rancher_pipeline_id = t_rancher.join_()

        # add kubernetes namespace into rancher default project
        rancher.rc_add_namespace_into_rc_project(args['name'])

        # Insert into nexus database
        new_pjt = model.Project(
            name=gitlab_pj_name,
            display=args['display'],
            description=args['description'],
            ssh_url=gitlab_pj_ssh_url,
            http_url=gitlab_pj_http_url,
            disabled=args['disabled'],
            start_date=args['start_date'],
            due_date=args['due_date'],
            create_at=str(datetime.utcnow()),
            owner_id=owner_id,
            creator_id=user_id
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
            ci_project_id=rancher.project_id,
            ci_pipeline_id=rancher_pipeline_id
        )
        db.session.add(new_relation)
        db.session.commit()

        # 加關聯project_user_role
        project_add_member(project_id, owner_id)
        if owner_id != user_id:
            project_add_subadmin(project_id, user_id)
        create_bot(project_id)

        # Commit and push file by template , if template env is not None
        if args["template_id"] is not None:
            template.tm_use_template_push_into_pj(args["template_id"], gitlab_pj_id,
                                                  args["tag_name"], args["arguments"])

        return {
            "project_id": project_id,
            "plan_project_id": redmine_pj_id,
            "git_repository_id": gitlab_pj_id,
            "harbor_project_id": harbor_pj_id
        }
    except Exception as e:
        redmine.rm_delete_project(redmine_pj_id)
        gitlab.gl_delete_project(gitlab_pj_id)
        harbor_param = [harbor_pj_id, project_name]
        harbor.hb_delete_project(harbor_param)
        kubernetesClient.delete_namespace(project_name)
        sonarqube.sq_delete_project(project_name)
        t_rancher = DevOpsThread(target=rancher.rc_disable_project_pipeline,
                                 args=(gitlab_pj_http_url,))
        t_rancher.start()
        kubernetesClient.delete_namespace(project_name)
        raise e


def project_add_subadmin(project_id, user_id):
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


def create_bot(project_id):
    # Create project BOT
    login = f'project_bot_{project_id}'
    password = util.get_random_alphanumeric_string(6, 3)
    args = {
        'name': f'專案管理機器人{project_id}號',
        'email': f'project_bot_{project_id}@nowhere.net',
        'phone': 'BOTRingRing',
        'login': login,
        'password': password,
        'role_id': role.BOT.id,
        'status': 'enable'
    }
    u = user.create_user(args)
    user_id = u['user_id']
    project_add_member(project_id, user_id)
    git_user_id = u['repository_user_id']
    git_access_token = gitlab.gl_create_access_token(git_user_id)
    sonar_access_token = sonarqube.sq_create_access_token(login)

    # Add bot secrets to rancher
    create_kubernetes_namespace_secret(
        project_id, 'gitlab-bot', {'git-token': git_access_token})
    create_kubernetes_namespace_secret(
        project_id, 'sonar-bot', {'sonar-token': sonar_access_token})
    create_kubernetes_namespace_secret(
        project_id, 'nexus-bot', {'username': login, 'password': password})


def check_modify_database_type(items, args, select_db):
    output = {}
    for item in items:
        if args[item] is None:
            output[item] = getattr(select_db, item)
        else:
            output[item] = args[item]
            setattr(select_db, item, args[item])
    return args, select_db


@record_activity(ActionType.UPDATE_PROJECT)
def pm_update_project(project_id, args):
    targets = ['display', 'description', 'disabled', 'owner_id', 'start_date', 'due_date']
    plugin_relation = model.ProjectPluginRelation.query.filter_by(project_id=project_id).first()
    if args['description'] is not None:
        gitlab.gl_update_project(plugin_relation.git_repository_id, args["description"])
    redmine.rm_update_project(plugin_relation.plan_project_id, args)
    project = model.Project.query.filter_by(id=project_id).first()
    args, project = check_modify_database_type(targets, args, project)
    project.update_at = str(datetime.utcnow())
    db.session.commit()
    return util.success()


def try_to_delete(delete_method, argument):
    try:
        delete_method(argument)
    except DevOpsError as e:
        if e.status_code != 404:
            raise e


# 用project_id刪除redmine & gitlab的project並將db的相關table欄位一併刪除
@record_activity(ActionType.DELETE_PROJECT)
def delete_project(project_id):
    # 取得gitlab & redmine project_id
    relation = nx_get_project_plugin_relation(nexus_project_id=project_id)
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
    project_name = nexus.nx_get_project(id=project_id).name

    delete_bot(project_id)

    try:
        # disabled rancher pipeline
        rancher.rc_disable_project_pipeline(
            relation.ci_project_id,
            relation.ci_pipeline_id)
        # remove kubernetes namespace out to rancher project
        rancher.rc_add_namespace_into_rc_project(None)
    except DevOpsError as e:
        if e.status_code != 404:
            raise e

    try_to_delete(gitlab.gl_delete_project, gitlab_project_id)
    try_to_delete(redmine.rm_delete_project, redmine_project_id)
    if harbor_project_id is not None:
        harbor_param = [harbor_project_id, project_name]
        try_to_delete(harbor.hb_delete_project, harbor_param)
    try_to_delete(sonarqube.sq_delete_project, project_name)

    # delete rancher app
    try_to_delete(rancher.rc_del_app_when_devops_del_pj, project_name)
    # delete kubernetes namespace
    try_to_delete(kubernetesClient.delete_namespace, project_name)

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


def delete_bot(project_id):
    row = model.ProjectUserRole.query.filter_by(
        project_id=project_id, role_id=role.BOT.id).first()
    if row is None:
        return
    user.delete_user(row.user_id)


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
    redmine_url = f'{config.get("REDMINE_EXTERNAL_BASE_URL")}/projects/{plan_project_id}'
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


@record_activity(ActionType.ADD_MEMBER)
def project_add_member(project_id, user_id):
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

    user_relation = nexus.nx_get_user_plugin_relation(user_id=user_id)
    project_relation = nx_get_project_plugin_relation(nexus_project_id=project_id)
    redmine_role_id = user.to_redmine_role_id(role_id)

    # get project name
    pj_row = model.Project.query.filter_by(id=project_id).one()
    # get user name
    ur_row = model.User.query.filter_by(id=user_id).one()

    services = ['redmine', 'gitlab', 'harbor', 'kubernetes_role_binding', 'sonarqube']
    targets = {
        'redmine': redmine.rm_create_memberships,
        'gitlab': gitlab.gl_project_add_member,
        'harbor': harbor.hb_add_member,
        'kubernetes_role_binding': kubernetesClient.create_role_binding,
        'sonarqube': sonarqube.sq_add_member
    }
    service_args = {
        'redmine': (project_relation.plan_project_id,
                    user_relation.plan_user_id, redmine_role_id),
        'gitlab': (project_relation.git_repository_id,
                   user_relation.repository_user_id),
        'harbor': (project_relation.harbor_project_id,
                   user_relation.harbor_user_id),
        'kubernetes_role_binding': (pj_row.name, util.encode_k8s_sa(ur_row.login)),
        'sonarqube': (pj_row.name, ur_row.login)
    }
    helper = util.ServiceBatchOpHelper(services, targets, service_args)
    helper.run()
    for e in helper.errors.values():
        if e is not None:
            raise e

    return util.success()


@record_activity(ActionType.REMOVE_MEMBER)
def project_remove_member(project_id, user_id):
    role_id = user.get_role_id(user_id)
    project = model.Project.query.filter_by(id=project_id).first()
    if project.owner_id == user_id:
        raise apiError.DevOpsError(404, "Error while removing a member from the project.",
                                   error=apiError.is_project_owner_in_project(user_id, project_id))

    user_relation = nexus.nx_get_user_plugin_relation(user_id=user_id)
    project_relation = nx_get_project_plugin_relation(nexus_project_id=project_id)
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
            redmine.rm_delete_memberships(redmine_membership_id)
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
        if e.status_code != 404:
            raise e

    # get project name
    pj_row = model.Project.query.filter_by(id=project_id).one()
    # get user name
    ur_row = model.User.query.filter_by(id=user_id).one()
    try:
        kubernetesClient.delete_role_binding(pj_row.name,
                                             f"{util.encode_k8s_sa(ur_row.login)}-rb")
    except DevOpsError as e:
        if e.status_code != 404:
            raise e

    try:
        sonarqube.sq_remove_member(pj_row.name, ur_row.login)
    except DevOpsError as e:
        if e.status_code != 404:
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
    relation = nexus.nx_get_user_plugin_relation(user_id=user_id)
    plan_user_id = relation.plan_user_id
    for row in rows:
        output_dict = {'name': row.Project.name,
                       'display': row.Project.display,
                       'project_id': row.Project.id,
                       'git_url': row.Project.http_url,
                       'redmine_url': f'{config.get("REDMINE_EXTERNAL_BASE_URL")}/projects/'
                                      f'{row.ProjectPluginRelation.plan_project_id}',
                       'harbor_url': f'{config.get("HARBOR_EXTERNAL_BASE_URL")}/harbor/projects/' +
                                     f'{row.ProjectPluginRelation.harbor_project_id}/repositories',
                       'repository_ids': [row.ProjectPluginRelation.git_repository_id],
                       'department': user.NexusUser().set_user_id(row.Project.owner_id).department,
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
                key=lambda d: abs(d - datetime.utcnow()))
        if next_d_time is not None:
            output_dict['next_d_time'] = next_d_time.isoformat()

        git_repository_id = row.ProjectPluginRelation.git_repository_id
        try:
            # branch number
            branch_number = gitlab.gl_count_branches(git_repository_id)
            output_dict['branch'] = branch_number
            # tag number
            tags = gitlab.gl_get_tags(git_repository_id)
            tag_number = len(tags)
            output_dict['tag'] = tag_number
        except DevOpsError as e:
            if e.status_code == 404:
                logger.error('project not found. repository_id={0}'.format(git_repository_id))
                continue

        output_dict = get_ci_last_test_result(output_dict, row.ProjectPluginRelation)

        output_array.append(output_dict)

    return util.success(output_array)


def get_ci_last_test_result(output_dict, relation):
    # get rancher pipeline
    pipeline_output = rancher.rc_get_pipeline_executions(
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
    project_name = nexus.nx_get_project(id=project_id).name

    # newman
    row = model.TestResults.query.filter_by(project_id=project_id).order_by(desc(
        model.TestResults.id)).limit(1).first()
    if row is not None:
        test_id = row.id
        total = row.total
        if total is None:
            total = 0
            fail = 0
            passed = 0
        else:
            fail = row.fail
            passed = total - fail
        run_at = str(row.run_at)
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

    # webinspect
    scans = webInspect.wi_list_scans(project_name)
    wi_data = {}
    for scan in scans:
        if type(scan['stats']) is dict and scan['stats']['status'] == 'Complete':
            wi_data = scan['stats']
            wi_data['run_at'] = scan['run_at']
            break
    ret['webinspect'] = wi_data

    ret['sonarqube'] = sonarqube.sq_get_current_measures(project_name)
    ret['zap'] = zap.zap_get_latest_test(project_id)
    ret['sideex'] = sideex.sd_get_latest_test(project_id)

    return util.success({'test_results': ret})


def get_kubernetes_namespace_Quota(project_id):
    project_name = str(model.Project.query.filter_by(id=project_id).first().name)
    project_quota = kubernetesClient.get_namespace_quota(project_name)
    deployments = kubernetesClient.list_namespace_deployments(project_name)
    ingresses = kubernetesClient.list_namespace_ingresses(project_name)
    project_quota["quota"]["deployments"] = None
    project_quota["used"]["deployments"] = str(len(deployments))
    project_quota["quota"]["ingresses"] = None
    project_quota["used"]["ingresses"] = str(len(ingresses))
    if "secrets" not in project_quota["quota"]:
        secrets = kubernetesClient.list_namespace_secrets(project_name)
        project_quota["quota"]["secrets"] = None
        project_quota["used"]["secrets"] = str(len(secrets))
    return util.success(project_quota)


def update_kubernetes_namespace_Quota(project_id, resource):
    project_name = str(model.Project.query.filter_by(id=project_id).first().name)
    project_quota = kubernetesClient.update_namespace_quota(project_name, resource)
    return util.success(project_quota)


def get_kubernetes_namespace_pods(project_id):
    project_name = str(model.Project.query.filter_by(id=project_id).first().name)
    project_pod = kubernetesClient.list_namespace_pods_info(project_name)
    return util.success(project_pod)


def delete_kubernetes_namespace_pod(project_id, name):
    project_name = str(model.Project.query.filter_by(id=project_id).first().name)
    project_pod = kubernetesClient.delete_namespace_pod(project_name, name)
    return util.success(project_pod)


def get_kubernetes_namespace_pod_log(project_id, name, container_name=None):
    project_name = str(model.Project.query.filter_by(id=project_id).first().name)
    pod_log = kubernetesClient.read_namespace_pod_log(project_name, name, container_name)
    return util.success(pod_log)


def get_kubernetes_namespace_deployment(project_id):
    project_name = str(model.Project.query.filter_by(id=project_id).first().name)
    project_deployment = kubernetesClient.list_namespace_deployments(project_name)
    return util.success(project_deployment)


def put_kubernetes_namespace_deployment(project_id, name):
    project_name = str(model.Project.query.filter_by(id=project_id).first().name)
    deployment_info = kubernetesClient.read_namespace_deployment(project_name, name)
    if deployment_info.spec.template.metadata.annotations is not None:
        deployment_info.spec.template.metadata.annotations["iiidevops_redeploy_at"] = str(datetime.utcnow())
    project_deployment = kubernetesClient.update_namespace_deployment(project_name, name, deployment_info)
    print(project_deployment)
    return util.success(project_deployment.metadata.name)


def delete_kubernetes_namespace_deployment(project_id, name):
    project_name = str(model.Project.query.filter_by(id=project_id).first().name)
    project_deployment = kubernetesClient.delete_namespace_deployment(project_name, name)
    return util.success(project_deployment)


def get_kubernetes_namespace_dev_environment(project_id):
    project_info = model.Project.query.filter_by(id=project_id).first()
    project_deployment = kubernetesClient.list_dev_environment_by_branch(str(project_info.name),
                                                                         str(project_info.http_url))
    return util.success(project_deployment)


def put_kubernetes_namespace_dev_environment(project_id, branch_name):
    project_info = model.Project.query.filter_by(id=project_id).first()
    update_info = kubernetesClient.update_dev_environment_by_branch(str(project_info.name), branch_name)
    return util.success(update_info)


def delete_kubernetes_namespace_dev_environment(project_id, branch_name):
    project_name = str(model.Project.query.filter_by(id=project_id).first().name)
    project_deployment = kubernetesClient.delete_dev_environment_by_branch(project_name, branch_name)
    return util.success(project_deployment)


def get_kubernetes_namespace_services(project_id):
    project_name = str(model.Project.query.filter_by(id=project_id).first().name)
    project_service = kubernetesClient.list_namespace_services(project_name)
    return util.success(project_service)


def delete_kubernetes_namespace_service(project_id, name):
    project_name = str(model.Project.query.filter_by(id=project_id).first().name)
    project_service = kubernetesClient.delete_namespace_service(project_name, name)
    return util.success(project_service)


def get_kubernetes_namespace_secrets(project_id):
    project_name = str(model.Project.query.filter_by(id=project_id).first().name)
    project_secret = kubernetesClient.list_namespace_secrets(project_name)
    return util.success(project_secret)


def read_kubernetes_namespace_secret(project_id, secret_name):
    project_name = str(model.Project.query.filter_by(id=project_id).first().name)
    project_secret = kubernetesClient.read_namespace_secret(project_name, secret_name)
    return util.success(project_secret)


def create_kubernetes_namespace_secret(project_id, secret_name, secrets):
    project_name = str(model.Project.query.filter_by(id=project_id).first().name)
    kubernetesClient.create_namespace_secret(project_name, secret_name, secrets)
    return util.success()


def put_kubernetes_namespace_secret(project_id, secret_name, secrets):
    project_name = str(model.Project.query.filter_by(id=project_id).first().name)
    kubernetesClient.patch_namespace_secret(project_name, secret_name, secrets)
    return util.success()


def delete_kubernetes_namespace_secret(project_id, name):
    project_name = str(model.Project.query.filter_by(id=project_id).first().name)
    project_secret = kubernetesClient.delete_namespace_secret(project_name, name)
    return util.success(project_secret)


# ConfigMap
def get_kubernetes_namespace_configmaps(project_id):
    project_name = str(model.Project.query.filter_by(id=project_id).first().name)
    project_configmap = kubernetesClient.list_namespace_configmap(project_name)
    return util.success(project_configmap)


def read_kubernetes_namespace_configmap(project_id, name):
    project_name = str(model.Project.query.filter_by(id=project_id).first().name)
    project_configmap = kubernetesClient.read_namespace_configmap(project_name, name)
    return util.success(project_configmap)


def create_kubernetes_namespace_configmap(project_id, name, configmaps):
    project_name = str(model.Project.query.filter_by(id=project_id).first().name)
    project_configmap = kubernetesClient.create_namespace_configmap(project_name, name, configmaps)
    return util.success(project_configmap)


def put_kubernetes_namespace_configmap(project_id, name, configmaps):
    project_name = str(model.Project.query.filter_by(id=project_id).first().name)
    project_configmap = kubernetesClient.put_namespace_configmap(project_name, name, configmaps)
    return util.success(project_configmap)


def create_kubernetes_namespace_configmap(project_id, name, configmaps):
    project_name = str(model.Project.query.filter_by(id=project_id).first().name)
    project_configmap = kubernetesClient.create_namespace_configmap(project_name, name, configmaps)
    return util.success(project_configmap)


def put_kubernetes_namespace_configmap(project_id, name, configmaps):
    project_name = str(model.Project.query.filter_by(id=project_id).first().name)
    project_configmap = kubernetesClient.put_namespace_configmap(project_name, name, configmaps)
    return util.success(project_configmap)


def delete_kubernetes_namespace_configmap(project_id, name):
    project_name = str(model.Project.query.filter_by(id=project_id).first().name)
    project_configmap = kubernetesClient.delete_namespace_configmap(project_name, name)
    return util.success(project_configmap)


def get_kubernetes_namespace_ingresses(project_id):
    project_name = str(model.Project.query.filter_by(id=project_id).first().name)
    ingress_list = kubernetesClient.list_namespace_ingresses(project_name)
    return util.success(ingress_list)


def get_plugin_usage(project_id):
    project_plugin_relation = model.ProjectPluginRelation.query.filter_by(project_id=project_id).first()
    plugin_info = []
    plugin_info.append(harbor.get_storage_usage(project_plugin_relation.harbor_project_id))
    plugin_info.append(gitlab.gl_get_storage_usage(project_plugin_relation.git_repository_id))
    return util.success(plugin_info)


def git_repo_id_to_ci_pipe_id(repository_id):
    project_plugin_relation = model.ProjectPluginRelation.query.filter_by(git_repository_id=int(repository_id)).first()
    return util.success(project_plugin_relation.ci_pipeline_id)

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
        role.require_pm("Error while updating project info.", exclude_qa=True)
        role.require_in_project(project_id, "Error while updating project info.")
        parser = reqparse.RequestParser()
        parser.add_argument('display', type=str, required=True)
        parser.add_argument('description', type=str)
        parser.add_argument('disabled', type=bool, required=True)
        parser.add_argument('start_date', type=str, required=True)
        parser.add_argument('due_date', type=str, required=True)
        parser.add_argument('owner_id', type=int, required=True)
        args = parser.parse_args()
        return pm_update_project(project_id, args)

    @jwt_required
    def delete(self, project_id):
        role.require_pm()
        role.require_in_project(project_id)
        role_id = get_jwt_identity()["role_id"]
        user_id = get_jwt_identity()["user_id"]
        if role_id == role.QA.id:
            if not bool(
                    model.Project.query.filter_by(
                        id=project_id,
                        creator_id=user_id
                    ).count()):
                raise apiError.NotAllowedError('Error while deleting project.')
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
        parser.add_argument('template_id', type=int)
        parser.add_argument('tag_name', type=str)
        parser.add_argument('arguments', type=dict)
        parser.add_argument('start_date', type=str, required=True)
        parser.add_argument('due_date', type=str, required=True)
        parser.add_argument('owner_id', type=int)
        args = parser.parse_args()
        pattern = "^[a-z][a-z0-9-]{0,28}[a-z0-9]$"
        result = re.fullmatch(pattern, args["name"])
        if result is None:
            return util.respond(400, 'Error while creating project',
                                error=apiError.invalid_project_name(args['name']))
        return util.success(create_project(user_id, args))


class SingleProjectByName(Resource):
    @jwt_required
    def get(self, project_name):
        project_id = nexus.nx_get_project(name=project_name).id
        role.require_pm("Error while getting project info.")
        role.require_in_project(project_id, "Error while getting project info.")
        return pm_get_project(project_id)


class ProjectMember(Resource):
    @jwt_required
    def post(self, project_id):
        role.require_pm()
        role.require_in_project(project_id)
        parser = reqparse.RequestParser()
        parser.add_argument('user_id', type=int, required=True)
        args = parser.parse_args()
        return project_add_member(project_id, args['user_id'])

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


class ProjectPluginUsage(Resource):
    @jwt_required
    def get(self, project_id):
        role.require_in_project(project_id, "Error while getting project info.")
        return get_plugin_usage(project_id)


class ProjectUserResource(Resource):
    @jwt_required
    def get(self, project_id):
        role.require_in_project(project_id, "Error while getting project info.")
        return get_kubernetes_namespace_Quota(project_id)

    @jwt_required
    def put(self, project_id):
        role.require_admin("Error while updating project resource.")
        parser = reqparse.RequestParser()
        parser.add_argument('memory', type=str, required=True)
        parser.add_argument('pods', type=int, required=True)
        parser.add_argument('secrets', type=int, required=True)
        parser.add_argument('configmaps', type=int, required=True)
        parser.add_argument('services.nodeports', type=int, required=True)
        parser.add_argument('persistentvolumeclaims', type=int, required=True)
        args = parser.parse_args()
        return update_kubernetes_namespace_Quota(project_id, args)


class ProjectUserResourcePods(Resource):
    @jwt_required
    def get(self, project_id):
        role.require_in_project(project_id, "Error while getting project info.")
        return get_kubernetes_namespace_pods(project_id)


class ProjectUserResourcePod(Resource):

    @jwt_required
    def delete(self, project_id, pod_name):
        role.require_in_project(project_id, "Error while getting project info.")
        return delete_kubernetes_namespace_pod(project_id, pod_name)


class ProjectUserResourcePodLog(Resource):
    @jwt_required
    def get(self, project_id, pod_name):
        role.require_in_project(project_id, "Error while getting project info.")
        parser = reqparse.RequestParser()
        parser.add_argument('container_name', type=str)
        args = parser.parse_args()
        return get_kubernetes_namespace_pod_log(project_id, pod_name, args['container_name'])


class ProjectEnvironment(Resource):
    @jwt_required
    def get(self, project_id):
        role.require_in_project(project_id, "Error while getting project info.")
        return get_kubernetes_namespace_dev_environment(project_id)

    @jwt_required
    def put(self, project_id, branch_name):
        role.require_in_project(project_id, "Error while getting project info.")
        return put_kubernetes_namespace_dev_environment(project_id, branch_name)

    @jwt_required
    def delete(self, project_id, branch_name):
        role.require_in_project(project_id, "Error while getting project info.")
        return delete_kubernetes_namespace_dev_environment(project_id, branch_name)


class ProjectUserResourceDeployments(Resource):
    @jwt_required
    def get(self, project_id):
        role.require_in_project(project_id, "Error while getting project info.")
        return get_kubernetes_namespace_deployment(project_id)


class ProjectUserResourceDeployment(Resource):

    @jwt_required
    def put(self, project_id, deployment_name):
        role.require_in_project(project_id, "Error while getting project info.")
        return put_kubernetes_namespace_deployment(project_id, deployment_name)

    @jwt_required
    def delete(self, project_id, deployment_name):
        role.require_in_project(project_id, "Error while getting project info.")
        return delete_kubernetes_namespace_deployment(project_id, deployment_name)


class ProjectUserResourceServices(Resource):
    @jwt_required
    def get(self, project_id):
        role.require_in_project(project_id, "Error while getting project info.")
        return get_kubernetes_namespace_services(project_id)


class ProjectUserResourceService(Resource):
    @jwt_required
    def delete(self, project_id, service_name):
        role.require_in_project(project_id, "Error while getting project info.")
        return delete_kubernetes_namespace_service(project_id, service_name)


class ProjectUserResourceSecrets(Resource):
    @jwt_required
    def get(self, project_id):
        role.require_in_project(project_id, "Error while getting project info.")
        return get_kubernetes_namespace_secrets(project_id)


class ProjectUserResourceSecret(Resource):

    @jwt_required
    def get(self, project_id, secret_name):
        role.require_in_project(project_id, "Error while getting project info.")
        return read_kubernetes_namespace_secret(project_id, secret_name)

    @jwt_required
    def post(self, project_id, secret_name):
        role.require_in_project(project_id, "Error while getting project info.")
        parser = reqparse.RequestParser()
        parser.add_argument('secrets', type=dict, required=True)
        args = parser.parse_args()
        return create_kubernetes_namespace_secret(project_id, secret_name, args["secrets"])

    @jwt_required
    def put(self, project_id, secret_name):
        role.require_in_project(project_id, "Error while getting project info.")
        parser = reqparse.RequestParser()
        parser.add_argument('secrets', type=dict, required=True)
        args = parser.parse_args()
        return put_kubernetes_namespace_secret(project_id, secret_name, args["secrets"])

    @jwt_required
    def delete(self, project_id, secret_name):
        role.require_in_project(project_id, "Error while getting project info.")
        return delete_kubernetes_namespace_secret(project_id, secret_name)


class ProjectUserResourceConfigMaps(Resource):
    @jwt_required
    def get(self, project_id):
        role.require_in_project(project_id, "Error while getting project info.")
        return get_kubernetes_namespace_configmaps(project_id)


class ProjectUserResourceConfigMap(Resource):
    @jwt_required
    def get(self, project_id, configmap_name):
        role.require_in_project(project_id, "Error while getting project info.")
        return read_kubernetes_namespace_configmap(project_id, configmap_name)

    @jwt_required
    def delete(self, project_id, configmap_name):
        role.require_in_project(project_id, "Error while getting project info.")
        return delete_kubernetes_namespace_configmap(project_id, configmap_name)

    @jwt_required
    def put(self, project_id, configmap_name):
        parser = reqparse.RequestParser()
        parser.add_argument('configmaps', type=dict, required=True)
        args = parser.parse_args()
        role.require_in_project(project_id, "Error while getting project info.")
        return put_kubernetes_namespace_configmap(project_id, configmap_name, args['configmaps'])

    @jwt_required
    def post(self, project_id, configmap_name):
        parser = reqparse.RequestParser()
        parser.add_argument('configmaps', type=dict, required=True)
        args = parser.parse_args()
        role.require_in_project(project_id, "Error while getting project info.")
        print(args)
        return create_kubernetes_namespace_configmap(project_id, configmap_name, args['configmaps'])


class ProjectUserResourceIngresses(Resource):
    @jwt_required
    def get(self, project_id):
        role.require_in_project(project_id, "Error while getting project info.")
        return get_kubernetes_namespace_ingresses(project_id)


class GitRepoIdToCiPipeId(Resource):
    @jwt_required
    def get(self, repository_id):
        return git_repo_id_to_ci_pipe_id(repository_id)