import os
import shutil
import re
import zipfile
from datetime import datetime
from io import BytesIO
import json
import uuid

from accessories import redmine_lib
from flask import send_file
from flask_jwt_extended import jwt_required, get_jwt_identity
from flask_restful import Resource, reqparse
from kubernetes.client import ApiException
from sqlalchemy import desc, or_
from sqlalchemy.orm import joinedload
from sqlalchemy.orm.exc import NoResultFound

import model
import nexus
import plugins
import resources.apiError as apiError
import util as util
from data.nexus_project import NexusProject, calculate_project_issues, fill_rd_extra_fields
from model import ProjectPluginRelation, ProjectUserRole, StarredProject, db
from nexus import nx_get_project_plugin_relation
from plugins.checkmarx.checkmarx_main import checkmarx
from resources.apiError import DevOpsError
from resources.starred_project import spj_unset
from accessories import redmine_lib
from util import DevOpsThread
from redminelib.exceptions import ResourceNotFoundError
from . import user, harbor, kubernetesClient, role, template
from .activity import record_activity, ActionType
from plugins.webinspect import webinspect_main as webinspect
from plugins.sonarqube import sonarqube_main as sonarqube
from plugins.zap import zap_main as zap
from plugins.sideex import sideex_main as sideex
from plugins.cmas import cmas_main as cmas
from .gitlab import gitlab
from .rancher import rancher, remove_pj_executions
from .redmine import redmine
from resources.monitoring import Monitoring
from resources import sync_project
from resources.project_relation import get_all_sons_project, get_plan_id
from flask_apispec import doc
from flask_apispec.views import MethodResource
from resources import role
from resources.redis import update_pj_issue_calcs, get_certain_pj_issue_calc


def get_project_issue_calculation(user_id, project_ids=[]):
    from resources.sync_project import check_project_exist
    ret = []
    user_name = model.User.query.get(user_id).login
    recheck_project = False
    for project_id in project_ids:
        redmine_project_id = model.ProjectPluginRelation.query.filter_by(project_id=project_id).one().plan_project_id
        try:
            project_object = redmine_lib.rm_impersonate(user_name).project.get(redmine_project_id)
        except:
            project_object = None
        
        if project_object is None:
            recheck_project = True
            calculate_project_issue = {
                "id": project_id,
                'closed_count': None,
                'overdue_count': None,
                'total_count': None,
                'project_status': None,
                'updated_time': None,
                'is_lock': True
            }
        else:
            calculate_project_issue = get_certain_pj_issue_calc(project_id)
            # rm_project = {"updated_on": project_object.updated_on, "id": project_object.id}
            # calculate_project_issue = calculate_project_issues(rm_project, user_name)
            if role.is_role(role.RD):
                calculate_project_issue.update(fill_rd_extra_fields(user_id, redmine_project_id))
            calculate_project_issue["id"] = project_id
        ret.append(calculate_project_issue)
    if recheck_project:
        check_project_exist()
    return ret


def get_project_list(user_id, role="simple", args={}, disable=None, sync=False):
    limit = args.get("limit")
    offset = args.get("offset")
    extra_data = args.get("test_result", "false") == "true"
    pj_members_count = args.get("pj_members_count", "false") == "true"
    user_name = model.User.query.get(user_id).login

    rows, counts = get_project_rows_by_user(user_id, disable, args=args)
    ret = []
    for row in rows:
        nexus_project = NexusProject().set_project_row(row) \
            .set_starred_info(user_id)
        if role == "pm":
            redmine_project_id = row.plugin_relation.plan_project_id
            try:
                if sync:
                    project_object = redmine_lib.redmine.project.get(redmine_project_id)
                else:
                    project_object = redmine_lib.rm_impersonate(user_name).project.get(redmine_project_id)
                rm_project = {"updated_on": project_object.updated_on, "id": project_object.id}
            except ResourceNotFoundError:
                # When Redmin project was missing
                sync_project.lock_project(nexus_project.name, "Redmine")
                rm_project = {"updated_on": datetime.utcnow(), "id": -1}
            nexus_project = nexus_project.fill_pm_extra_fields(rm_project, user_name, sync)
        if extra_data:
            nexus_project = nexus_project.fill_extra_fields()

        if pj_members_count:
            nexus_project = nexus_project.set_project_members()

        ret.append(nexus_project.to_json())

    if limit is not None and offset is not None:
        page_dict = util.get_pagination(counts,
                                        limit, offset)
        return {'project_list': ret, 'page': page_dict}

    return ret


def get_project_rows_by_user(user_id, disable, args={}):
    search = args.get("search")
    limit, offset = args.get("limit"), args.get("offset")
    pj_due_start = datetime.strptime(args.get("pj_due_date_start"), "%Y-%m-%d").date() if args.get("pj_due_date_start") is not None else None
    pj_due_end = datetime.strptime(args.get("pj_due_date_end"), "%Y-%m-%d").date() if args.get("pj_due_date_end") is not None else None

    query = model.Project.query.options(
        joinedload(model.Project.user_role, innerjoin=True)
    )
    # 如果不是admin（也就是一般RD/PM/QA），取得 user_id 有參加的 project 列表
    if user.get_role_id(user_id) != role.ADMIN.id:
        query = query.filter(model.Project.user_role.any(user_id=user_id))
    
    stared_pjs = db.session.query(StarredProject).join(ProjectUserRole, StarredProject.project_id == ProjectUserRole.project_id). \
    filter(ProjectUserRole.user_id == user_id).filter(StarredProject.user_id == user_id).all()
    star_projects_obj = [model.Project.query.get(stared_pj.project_id) for stared_pj in stared_pjs]
   
    if disable is not None:
        query = query.filter_by(disabled=disable)
        star_projects_obj = [star_project for star_project in star_projects_obj if star_project.disabled == disable]

    if search is not None:
        users = model.User.query.filter(model.User.name.ilike(f'%{search}%')).all()
        owner_ids = [user.id for user in users]
        query = query.filter(or_(
            model.Project.owner_id.in_(owner_ids),
            model.Project.display.like(f'%{search}%'),
            model.Project.name.like(f'%{search}%'),
        ))
        star_projects_obj = [
            star_project for star_project in star_projects_obj
            if star_project.owner_id in owner_ids or
            search.upper() in star_project.display.upper() or
            search.upper() in star_project.name.upper()]

    if pj_due_start is not None and pj_due_end is not None:
        query = query.filter(
            model.Project.due_date.between(pj_due_start, pj_due_end))
        star_projects_obj = [
            star_project for star_project in star_projects_obj
            if pj_due_start <= star_project.due_date <= pj_due_end]
    

    # Remove dump_project and stared_project
    project_ids = [star_project.id for star_project in star_projects_obj]
    stared_project_num = len(project_ids)
    query = query.filter(~model.Project.id.in_(project_ids + [-1])).order_by(desc(model.Project.id))
    counts = query.count()
    if limit is not None:
        if offset == 0:
            limit -= stared_project_num
        else:
            offset -= stared_project_num
        rows = query.limit(limit).offset(offset).all()
        rows = star_projects_obj + rows if offset == 0 else rows
    else:
        rows = query.all()
        rows = star_projects_obj + rows
    return rows, counts + stared_project_num


# 新增redmine & gitlab的project並將db相關table新增資訊
@record_activity(ActionType.CREATE_PROJECT)
def create_project(user_id, args):
    is_inherit_members = args.pop("is_inherit_members", False)
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

    # 取得母專案資訊
    if args.get('parent_id', None) is not None:
        parent_plan_project_id = get_plan_project_id(args.get('parent_id'))
        args['parent_plan_project_id'] = parent_plan_project_id

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
        'sonarqube': (args['name'], args.get('display'))
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
                                    error=apiError.identifier_has_been_taken(
                                        args['name'])
                                )
                        except (KeyError, IndexError):
                            pass
                    raise e
                else:
                    raise e
    try:
        project_id = None
        uuids = uuid.uuid1().hex
        # enable rancher pipeline
        rancher.rc_get_project_id()
        t_rancher = DevOpsThread(target=rancher.rc_enable_project_pipeline,
                                 args=(gitlab_pj_http_url,))
        t_rancher.start()
        rancher_pipeline_id = t_rancher.join_()

        # add kubernetes namespace into rancher default project
        rancher.rc_add_namespace_into_rc_project(args['name'])

        # get base_example
        template_pj_path = None
        if args.get("template_id") is not None:
            template_pj = template.get_projects_detail(args["template_id"])
            template_pj_path = template_pj.path

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
            creator_id=user_id,
            base_example=template_pj_path,
            example_tag=args["tag_name"],
            uuid=uuids
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

        # 若有父專案, 加關聯進ProjectParentSonRelation
        if args.get('parent_plan_project_id') is not None:
            new_father_son_relation = model.ProjectParentSonRelation(
                parent_id=args.get('parent_id'),
                son_id=project_id
            )
            db.session.add(new_father_son_relation)
            db.session.commit()

        # 加關聯project_user_role
        project_add_member(project_id, owner_id)
        if owner_id != user_id:
            project_add_subadmin(project_id, user_id)
        create_bot(project_id)

        # 若要繼承父專案成員, 加剩餘成員加關聯project_user_role
        if is_inherit_members and args.get('parent_plan_project_id') is not None:
            for user in model.ProjectUserRole.query.filter_by(project_id=args.get('parent_id')).all():
                if user.user_id != owner_id:
                    project_add_member(project_id, user.user_id)

        # Commit and push file by template , if template env is not None
        if args.get("template_id") is not None:
            template.tm_use_template_push_into_pj(args["template_id"], gitlab_pj_id,
                                                  args["tag_name"], args["arguments"])

        # Create project NFS folder /(uuid)
        for folder in ["pipeline", uuids]:
            project_nfs_file_path = f"./devops-data/project-data/{gitlab_pj_name}/{folder}"
            os.makedirs(project_nfs_file_path, exist_ok=True)
            os.chmod(project_nfs_file_path, 0o777)

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

        if project_id is not None:
            delete_bot(project_id)
            db.engine.execute(
                "DELETE FROM public.project_plugin_relation WHERE project_id = '{0}'".format(
                    project_id))
            db.engine.execute(
                "DELETE FROM public.project_user_role WHERE project_id = '{0}'".format(
                    project_id))
            db.engine.execute(
                "DELETE FROM public.projects WHERE id = '{0}'".format(
                    project_id))
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
    new = model.ProjectUserRole(
        project_id=project_id, user_id=user_id, role_id=role_id)
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


@record_activity(ActionType.UPDATE_PROJECT)
def pm_update_project(project_id, args):
    is_inherit_members = args.pop("is_inherit_members", False)

    plugin_relation = model.ProjectPluginRelation.query.filter_by(
        project_id=project_id).first()
    if args['description'] is not None:
        gitlab.gl_update_project(
            plugin_relation.git_repository_id, args["description"])
    if args.get('parent_id', None) is not None:
        args['parent_plan_project_id'] = get_plan_project_id(args.get('parent_id'))
    redmine.rm_update_project(plugin_relation.plan_project_id, args)
    nexus.nx_update_project(project_id, args)

    # 如果有disable, 調整專案在gitlab archive狀態
    disabled = args.get('disabled')
    if disabled is not None:
        gitlab.gl_archive_project(
            plugin_relation.git_repository_id, disabled)

    # 若有父專案, 加關聯進ProjectParentSonRelation, 須等redmine更新完再寫入
    if args.get('parent_plan_project_id') is not None and model.ProjectParentSonRelation. \
            query.filter_by(parent_id=args.get('parent_id'), son_id=project_id).first() is None:
        new_father_son_relation = model.ProjectParentSonRelation(
            parent_id=args.get('parent_id'),
            son_id=project_id
        )
        db.session.add(new_father_son_relation)
        db.session.commit()

    # 若要繼承父專案成員, 加剩餘成員加關聯project_user_role
    if is_inherit_members and args.get('parent_plan_project_id') is not None:
        for user in model.ProjectUserRole.query.filter_by(project_id=args.get('parent_id')).all():
            if model.ProjectUserRole.query.filter_by(project_id=project_id, user_id=user.user_id).first() is None:
                project_add_member(project_id, user.user_id)


@record_activity(ActionType.UPDATE_PROJECT)
def nexus_update_project(project_id, args):
    nexus.nx_update_project(project_id, args)


def try_to_delete(delete_method, argument):
    try:
        delete_method(argument)
    except DevOpsError as e:
        if e.status_code != 404:
            raise e


def delete_project(project_id, force_delete_project=False):
    # Check project has son project and get all ids
    son_id_list = get_all_sons_project(project_id, [])
    delete_id_list = [project_id] + son_id_list

    if force_delete_project is False:
        # Check all projects' servers are alive first,
        # because redmine delete all sons projects at the same time.
        for project_id in delete_id_list:
            server_alive_output = Monitoring(project_id).check_project_alive()
            if not server_alive_output["all_alive"]:
                not_alive_server = [
                    server.capitalize() for server, alive in server_alive_output["alive"].items() if not alive]
                servers = ", ".join(not_alive_server)
                raise apiError.DevOpsError(500, f"{servers} not alive")
    else:
        server_alive_output = Monitoring().check_project_alive()
        if not server_alive_output["all_alive"]:
            not_alive_server = [
                server.capitalize() for server, alive in server_alive_output["alive"].items() if not alive]
            servers = ", ".join(not_alive_server)
            raise apiError.DevOpsError(500, f"{servers} not alive")

    for project_id in delete_id_list:
        delete_project_helper(project_id)
    return util.success()

# 用project_id刪除redmine & gitlab的project並將db的相關table欄位一併刪除


@record_activity(ActionType.DELETE_PROJECT)
def delete_project_helper(project_id):

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
    # delete rancher pod execution
    try_to_delete(remove_pj_executions, project_id)
    # delete kubernetes namespace
    try_to_delete(kubernetesClient.delete_namespace, project_name)

    redmine_pj = model.RedmineProject.query.filter_by(project_id=project_id).first()
    if redmine_pj is not None:
        db.engine.execute(
            "DELETE FROM public.redmine_project WHERE project_id = '{0}'".format(
                project_id))

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

    # Delete project NFS folder
    project_nfs_file_path = f"./devops-data/project-data/{project_name}"
    if os.path.isdir(project_nfs_file_path):
        shutil.rmtree(project_nfs_file_path)


def delete_bot(project_id):
    row = model.ProjectUserRole.query.filter_by(
        project_id=project_id, role_id=role.BOT.id).first()
    if row is None:
        return
    user.delete_user(row.user_id)
    delete_kubernetes_namespace_secret(project_id, 'gitlab-bot')
    delete_kubernetes_namespace_secret(project_id, 'sonar-bot')
    delete_kubernetes_namespace_secret(project_id, 'nexus-bot')


def get_project_info(project_id):
    return NexusProject().set_project_id(project_id, do_query=True).to_json()


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
    new = model.ProjectUserRole(
        project_id=project_id, user_id=user_id, role_id=role_id)
    db.session.add(new)
    db.session.commit()

    user_relation = nexus.nx_get_user_plugin_relation(user_id=user_id)
    project_relation = nx_get_project_plugin_relation(
        nexus_project_id=project_id)
    redmine_role_id = user.to_redmine_role_id(role_id)

    # get project name
    pj_row = model.Project.query.filter_by(id=project_id).one()
    # get user name
    ur_row = model.User.query.filter_by(id=user_id).one()

    services = ['redmine', 'gitlab', 'harbor',
                'kubernetes_role_binding', 'sonarqube']
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
    project_relation = nx_get_project_plugin_relation(
        nexus_project_id=project_id)
    if project_relation is None:
        raise apiError.DevOpsError(404, "Error while removing a member from the project.",
                                   error=apiError.project_not_found(project_id))

    # get membership id
    memberships = redmine.rm_get_memberships_list(
        project_relation.plan_project_id)
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
    spj_unset(user_id, project_id)
    return util.success()


# May throws NoResultFound
def get_plan_project_id(project_id):
    return model.ProjectPluginRelation.query.filter_by(
        project_id=project_id).one().plan_project_id


def get_project_by_plan_project_id(plan_project_id):
    result = db.engine.execute(
        "SELECT * FROM public.project_plugin_relation"
        " WHERE plan_project_id = {0}".format(plan_project_id))
    project = result.fetchone()
    result.close()
    return project


def get_test_summary(project_id):
    '''
    -1: fail
    0: No lastest
    1: success 
    2: running
    '''
    ret = {}
    project_name = nexus.nx_get_project(id=project_id).name
    not_found_ret = {
        'message': '',
        'status': 0,
        'result': {},
        'run_at': None,
    }
    not_found_ret_message = lambda plugin : f"The latest scan is not Found in the {plugin} server"

    # newman ..
    if not plugins.get_plugin_config('postman')['disabled']:
        row = model.TestResults.query.filter_by(project_id=project_id).order_by(desc(
            model.TestResults.id)).limit(1).first()
        if row is not None:
            total = row.total
            if total is None:
                total = fail = passed = 0
            else:
                fail = row.fail
                passed = total - fail
            ret['postman'] = {
                'message': 'success',
                'status': 1,
                'id': row.id,
                'result': {
                    'passed': passed,
                    'failed': fail,
                    'total': total,
                },
                'run_at': str(row.run_at) if row.run_at is not None else None
            }
        else:
            not_found_ret['message'] = not_found_ret_message("postman")
            ret['postman'] = not_found_ret.copy()

    # checkmarx
    if not plugins.get_plugin_config('checkmarx')['disabled']:
        try:
            ret['checkmarx'] = checkmarx.get_result(project_id)
        except DevOpsError as e:
            if e.status_code == 404:
                not_found_ret['message'] = not_found_ret_message("checkmarx")
                ret['checkmarx'] = not_found_ret.copy()
            else:
                raise e

    # webinspect ..
    if not plugins.get_plugin_config('webinspect')['disabled']:
        scan = webinspect.get_latest_scans(project_name)
        if scan is not None:
            if type(scan['stats']) is dict and scan['stats']['status'] == 'Complete':
                ret['webinspect'] = {
                    'message': 'success',
                    'status': 1,
                    'result': scan['stats'],
                    "run_at": scan['run_at'],
                }
            elif scan['stats']['status'] in ['NotRunning', 'Interrupted', 'Failed']:
                ret['webinspect'] = {
                    'message': f"Status is {scan['stats']['status'].lower()}.",
                    'status': -1,
                    'result': {},
                    "run_at": str(scan['run_at']) if scan['run_at'] is not None else None,
                }
            else:    
                ret['webinspect'] = {
                    'message': 'It is not finished yet.',
                    'status': 2,
                    'result': {},
                    "run_at": str(scan['run_at']) if scan.get('run_at') is not None else None,
                }
        else:
            not_found_ret['message'] = not_found_ret_message("webinspect")
            ret['webinspect'] = not_found_ret.copy()

    # sonarqube ..
    if not plugins.get_plugin_config('sonarqube')['disabled']:
        items = sonarqube.sq_get_current_measures(project_name)
        if items != []:
            sonar_result = {
                "result": {item["metric"]: item["value"] for item in items if item["metric"] != "run_at"}}

            sonar_result.update({
                "message": "success",
                "status": 1,
                "run_at": items[-1]["value"] if items[-1]["metric"] == "run_at" else None
            })
            ret['sonarqube'] = sonar_result
        else:
            not_found_ret['message'] = not_found_ret_message("sonarqube")
            ret['sonarqube'] = not_found_ret.copy()

    # zap ..
    if not plugins.get_plugin_config('zap')['disabled']:
        result = zap.zap_get_latest_test(project_id)
        if result != {}:
            if result["status"] in ["Aborted", "Failed"]:
                ret['zap'] = {
                    'message': 'failed',
                    'status': -1,
                    'result': {},
                    "run_at": None,
                }
            elif result["status"] == "Finished":
                result.update({
                    "message": "success",
                    "status": 1,
                })
                ret['zap'] = result
            else:
                result.update({
                    "message": "scanning",
                    "status": 2,
                })
                ret['zap'] = result
        else:
            not_found_ret['message'] = not_found_ret_message("zap")
            ret['zap'] = not_found_ret.copy()

    # sideex
    if not plugins.get_plugin_config('sideex')['disabled']:
        result = sideex.sd_get_latest_test(project_id)
        if result != {}:
            if result["status"] in ["Aborted", "Failed"]:
                ret['sideex'] = {
                    'message': 'failed',
                    'status': -1,
                    'result': {},
                    "run_at": None,
                }
            elif result["status"] == "Finished":
                result.update({
                    "message": "success",
                    "status": 1,
                })
                ret['sideex'] = result
            else:
                result.update({
                    "message": "scanning",
                    "status": 2,
                })
                ret['sideex'] = result
        else:
            not_found_ret['message'] = not_found_ret_message("sideex")
            ret['sideex'] = not_found_ret.copy()

    # cmas ..
    if not plugins.get_plugin_config('cmas')['disabled']:
        cmas_content = cmas.get_latest_state(project_id)
        if isinstance(cmas_content, dict):
            if cmas_content["status"] == "FAIL":
                ret['cmas'] = {
                    'message': cmas_content["logs"],
                    'status': -1,
                    'result': {},
                    "run_at": None,
                }
            elif cmas_content["status"] == "SUCCESS":
                cmas_content["result"] = cmas_content.pop("stats")
                cmas_content.update({
                    "message": "success",
                    "status": 1,
                })
                ret['cmas'] = cmas_content
            else:
                cmas_content.update({
                    "message": "scanning",
                    "status": 2,
                })
                ret['cmas'] = cmas_content
        else:
            not_found_ret['message'] = not_found_ret_message("cmas")
            ret['cmas'] = not_found_ret.copy()
    return util.success({'test_results': ret})


def get_all_reports(project_id):
    project_name = nexus.nx_get_project(id=project_id).name
    memory_file = BytesIO()
    with zipfile.ZipFile(memory_file, 'w', zipfile.ZIP_DEFLATED) as zf:
        # newman
        if not plugins.get_plugin_config('postman')['disabled']:
            row = model.TestResults.query.filter_by(project_id=project_id).order_by(desc(
                model.TestResults.id)).limit(1).first()
            if row is not None:
                zf.writestr('postman.json', row.report)

        # checkmarx
        if not plugins.get_plugin_config('checkmarx')['disabled']:
            report_id = checkmarx.get_latest('report_id', project_id)
            if report_id is not None:
                zf.writestr('checkmarx.pdf', checkmarx.get_report_content(report_id))

        # webinspect
        if not plugins.get_plugin_config('webinspect')['disabled']:
            scans = webinspect.wi_list_scans(project_name)
            scan_id = None
            for scan in scans:
                if type(scan['stats']) is dict and scan['stats']['status'] == 'Complete':
                    scan_id = scan['scan_id']
                    break
            if scan_id is not None:
                xml = webinspect.wix_get_report(scan_id)
                if xml is not None:
                    zf.writestr('webinspect.xml', xml)

        if not plugins.get_plugin_config('sonarqube')['disabled']:
            zf.writestr('sonarqube.json', str(sonarqube.sq_get_current_measures(project_name)))

        if not plugins.get_plugin_config('zap')['disabled']:
            report = zap.zap_get_latest_full_log(project_name)
            if report is not None:
                zf.writestr('zap.html', report)

        if not plugins.get_plugin_config('sideex')['disabled']:
            test_id = sideex.sd_get_latest_test(project_id).get('id', None)
            if test_id is not None:
                zf.writestr('sideex.html', sideex.sd_get_report(test_id))

    memory_file.seek(0)
    return memory_file


def get_kubernetes_namespace_Quota(project_id):
    project_name = str(model.Project.query.filter_by(
        id=project_id).first().name)
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
    project_name = str(model.Project.query.filter_by(
        id=project_id).first().name)
    project_quota = kubernetesClient.update_namespace_quota(
        project_name, resource)
    return util.success(project_quota)


def get_kubernetes_plugin_pods(project_id, plugin_name):
    pods, _ = get_kubernetes_namespace_pods(project_id)
    ret = {}
    for pod in pods["data"]:
        if pod["containers"][0]["name"].startswith(plugin_name):
            ret["container_name"] = pod["containers"][0]["name"]
            ret["pod_name"] = pod["name"]
    ret["has_pod"] = ret.get("pod_name") is not None
    return util.success(ret)


def get_kubernetes_namespace_pods(project_id):
    project_name = str(model.Project.query.filter_by(
        id=project_id).first().name)
    project_pod = kubernetesClient.list_namespace_pods_info(project_name)
    return util.success(project_pod)


def delete_kubernetes_namespace_pod(project_id, name):
    project_name = str(model.Project.query.filter_by(
        id=project_id).first().name)
    project_pod = kubernetesClient.delete_namespace_pod(project_name, name)
    return util.success(project_pod)


def get_kubernetes_namespace_pod_log(project_id, name, container_name=None):
    project_name = str(model.Project.query.filter_by(
        id=project_id).first().name)
    pod_status = kubernetesClient.read_namespaced_pod_status(name, project_name)
    if pod_status.status.phase == "Waiting":
        return util.success()
    pod_log = kubernetesClient.read_namespace_pod_log(
        project_name, name, container_name)
    return util.success(pod_log)


def get_kubernetes_namespace_deployment(project_id):
    project_name = str(model.Project.query.filter_by(
        id=project_id).first().name)
    project_deployment = kubernetesClient.list_namespace_deployments(
        project_name)
    return util.success(project_deployment)


def put_kubernetes_namespace_deployment(project_id, name):
    project_name = str(model.Project.query.filter_by(
        id=project_id).first().name)
    deployment_info = kubernetesClient.read_namespace_deployment(
        project_name, name)
    if deployment_info.spec.template.metadata.annotations is not None:
        deployment_info.spec.template.metadata.annotations["iiidevops_redeploy_at"] = str(
            datetime.utcnow())
    project_deployment = kubernetesClient.update_namespace_deployment(
        project_name, name, deployment_info)
    return util.success(project_deployment.metadata.name)


def delete_kubernetes_namespace_deployment(project_id, name):
    project_name = str(model.Project.query.filter_by(
        id=project_id).first().name)
    project_deployment = kubernetesClient.delete_namespace_deployment(
        project_name, name)
    return util.success(project_deployment)


def get_kubernetes_namespace_dev_environment(project_id):
    project_info = model.Project.query.filter_by(id=project_id).first()
    project_deployment = kubernetesClient.list_dev_environment_by_branch(str(project_info.name),
                                                                         str(project_info.http_url))
    return project_deployment


def get_kubernetes_namespace_dev_environment_urls(project_id, branch_name):
    ret = []
    data = get_kubernetes_namespace_dev_environment(project_id)
    for d in data:
        if d['branch'] == branch_name:
            for pod in d['pods']:
                if pod['type'] == 'web-server':
                    for con in pod['containers']:
                        if con['status']['state'] == 'running':
                            for mapping in con.get('service_port_mapping', []):
                                for service in mapping.get('services', []):
                                    ret.extend(service.get('url', []))
    return ret


def put_kubernetes_namespace_dev_environment(project_id, branch_name):
    project_info = model.Project.query.filter_by(id=project_id).first()
    update_info = kubernetesClient.update_dev_environment_by_branch(
        str(project_info.name), branch_name)
    return util.success(update_info)


def delete_kubernetes_namespace_dev_environment(project_id, branch_name):
    project_name = str(model.Project.query.filter_by(
        id=project_id).first().name)
    project_deployment = kubernetesClient.delete_dev_environment_by_branch(
        project_name, branch_name)
    return util.success(project_deployment)


def get_kubernetes_namespace_services(project_id):
    project_name = str(model.Project.query.filter_by(
        id=project_id).first().name)
    project_service = kubernetesClient.list_namespace_services(project_name)
    return util.success(project_service)


def delete_kubernetes_namespace_service(project_id, name):
    project_name = str(model.Project.query.filter_by(
        id=project_id).first().name)
    project_service = kubernetesClient.delete_namespace_service(
        project_name, name)
    return util.success(project_service)


def get_kubernetes_namespace_secrets(project_id):
    project_name = str(model.Project.query.filter_by(
        id=project_id).first().name)
    project_secret = kubernetesClient.list_namespace_secrets(project_name)
    return util.success(project_secret)


def read_kubernetes_namespace_secret(project_id, secret_name):
    project_name = str(model.Project.query.filter_by(
        id=project_id).first().name)
    project_secret = kubernetesClient.read_namespace_secret(
        project_name, secret_name)
    return util.success(project_secret)


def create_kubernetes_namespace_secret(project_id, secret_name, secrets):
    project_name = str(model.Project.query.filter_by(
        id=project_id).first().name)
    kubernetesClient.create_namespace_secret(
        project_name, secret_name, secrets)
    return util.success()


def put_kubernetes_namespace_secret(project_id, secret_name, secrets):
    project_name = str(model.Project.query.filter_by(
        id=project_id).first().name)
    kubernetesClient.patch_namespace_secret(project_name, secret_name, secrets)
    return util.success()


def delete_kubernetes_namespace_secret(project_id, name):
    project_name = str(model.Project.query.filter_by(
        id=project_id).first().name)
    project_secret = kubernetesClient.delete_namespace_secret(
        project_name, name)
    return util.success(project_secret)


# ConfigMap
def get_kubernetes_namespace_configmaps(project_id):
    project_name = str(model.Project.query.filter_by(
        id=project_id).first().name)
    project_configmap = kubernetesClient.list_namespace_configmap(project_name)
    return util.success(project_configmap)


def read_kubernetes_namespace_configmap(project_id, name):
    project_name = str(model.Project.query.filter_by(
        id=project_id).first().name)
    project_configmap = kubernetesClient.read_namespace_configmap(
        project_name, name)
    return util.success(project_configmap)


def create_kubernetes_namespace_configmap(project_id, name, configmaps):
    project_name = str(model.Project.query.filter_by(
        id=project_id).first().name)
    project_configmap = kubernetesClient.create_namespace_configmap(
        project_name, name, configmaps)
    return util.success(project_configmap)


def put_kubernetes_namespace_configmap(project_id, name, configmaps):
    project_name = str(model.Project.query.filter_by(
        id=project_id).first().name)
    project_configmap = kubernetesClient.put_namespace_configmap(
        project_name, name, configmaps)
    return util.success(project_configmap)


def delete_kubernetes_namespace_configmap(project_id, name):
    project_name = str(model.Project.query.filter_by(
        id=project_id).first().name)
    project_configmap = kubernetesClient.delete_namespace_configmap(
        project_name, name)
    return util.success(project_configmap)


def get_kubernetes_namespace_ingresses(project_id):
    project_name = str(model.Project.query.filter_by(
        id=project_id).first().name)
    ingress_list = kubernetesClient.list_namespace_ingresses(project_name)
    return util.success(ingress_list)


def get_plugin_usage(project_id):
    project_plugin_relation = model.ProjectPluginRelation.query.filter_by(
        project_id=project_id).first()
    plugin_info = []
    plugin_info.append(harbor.get_storage_usage(
        project_plugin_relation.harbor_project_id))
    plugin_info.append(gitlab.gl_get_storage_usage(
        project_plugin_relation.git_repository_id))
    return util.success(plugin_info)


def git_repo_id_to_ci_pipe_id(repository_id):
    project_plugin_relation = model.ProjectPluginRelation.query.filter_by(
        git_repository_id=int(repository_id)).first()
    return util.success(project_plugin_relation.ci_pipeline_id)


def check_project_args_patterns(args):
    keys_to_check = ["name", "display", "description"]
    for key in keys_to_check:
        if args.get(key, None):
            if key != "name":
                pattern = "&|<"
                result = re.findall(pattern, args[key])
                if any(result):
                    raise apiError.DevOpsError(400, "Error while creating project.",
                                               error=apiError.invalid_project_content(key, args[key]))
            else:
                pattern = "^[a-z][a-z0-9-]{0,28}[a-z0-9]$"
                result = re.findall(pattern, args[key])
                if result is None:
                    raise apiError.DevOpsError(400, "Error while creating project.",
                                               error=apiError.invalid_project_name(args[key]))


def check_project_owner_id(new_owner_id, user_id, project_id):
    origin_owner_id = model.Project.query.get(project_id).owner_id
    # 你是皇帝，你說了算
    if role.is_role(role.ADMIN):
        pass
    # 不更動 owner_id，僅修改其他資訊 (由 project 中 owner 的 PM 執行)
    elif origin_owner_id == user_id and new_owner_id == user_id:
        pass
    # 更動 owner_id (由 project 中 owner 的 PM 執行)
    elif origin_owner_id == user_id and new_owner_id != user_id:
        # 檢查 new_owner_id 的 role 是否為 PM
        if not bool(model.ProjectUserRole.query.filter_by(
                project_id=project_id, user_id=new_owner_id, role_id=3
        ).all()):
            raise apiError.DevOpsError(400, "Error while updating project info.",
                                       error=apiError.invalid_project_owner(new_owner_id))
    # 不更動 owner_id，僅修改其他資訊 (由 project 中其他 PM 執行)
    elif origin_owner_id != user_id and new_owner_id == origin_owner_id:
        pass
    # 其餘權限不足
    else:
        raise apiError.NotAllowedError("Error while updating project info.")


def get_projects_by_user(user_id):
    try:
        model.ProjectUserRole.query.filter_by(
            project_id=-1, user_id=user_id).one()
    except NoResultFound:
        raise apiError.DevOpsError(
            404, 'User id {0} does not exist.'.format(user_id),
            apiError.user_not_found(user_id))
    projects_id_list = list(sum(
        model.ProjectUserRole.query.filter_by(
            user_id=user_id).with_entities(model.ProjectUserRole.project_id), ()))
    projects = [NexusProject().set_project_id(id).to_json()
                for id in projects_id_list if id != -1]
    return projects


def sync_project_issue_calculate():
    project_issue_calculate = {}
    for project in model.Project.query.all():
        pj_id = project.id
        plan_id = get_plan_id(project.id)
        if plan_id != -1:
            try: 
                project_object = redmine_lib.redmine.project.get(plan_id)
                rm_project = {"updated_on": project_object.updated_on, "id": project_object.id}
                project_issue_calculate[pj_id] = json.dumps(
                    calculate_project_issues(rm_project, username=None, sync=True))
            except:
                continue

    update_pj_issue_calcs(project_issue_calculate)
    

def delete_rancher_app(project_id, branch_name):
    project_info = model.Project.query.filter_by(id=project_id).first()
    project_deployment = kubernetesClient.list_dev_environment_by_branch(str(project_info.name),str(project_info.http_url))
    for temp in project_deployment:
        if temp.get("branch") == branch_name:
            for pod in temp.get("pods"):
                if pod.get("type") == "web-server" or pod.get("type") == "db-server":
                    rancher.rc_del_app(pod.get("app_name"))
    return util.success()

# --------------------- Resources ---------------------

@doc(tags=['Pending'], description="Get CI pipeline id by git repo id")
class GitRepoIdToCiPipeIdV2(MethodResource):
    @jwt_required
    def get(self, repository_id):
        return git_repo_id_to_ci_pipe_id(repository_id)


class GitRepoIdToCiPipeId(Resource):
    @jwt_required
    def get(self, repository_id):
        return git_repo_id_to_ci_pipe_id(repository_id)


