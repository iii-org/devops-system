import os

import shutil
import threading
import config
import model
import util
from model import db, ProjectPluginRelation, Project, UserPluginRelation, User, ProjectUserRole, PluginSoftware, \
    DefaultAlertDays, TraceOrder, TraceResult, Application, IssueExtensions, Lock, RedmineProject, ServerType, SystemParameter
from plugins.sonarqube.sonarqube_main import sq_create_project, sq_create_user
from resources import harbor, kubernetesClient, role, sync_redmine, devops_version
from resources.apiError import DevOpsError
from resources.logger import logger
from resources.rancher import rancher, remove_executions, turn_tags_off
from resources.redmine import redmine
from resources import project
from resources import template

# Each time you add a migration, add a version code here.

VERSIONS = ['0.9.2', '0.9.2.1', '0.9.2.2', '0.9.2.3', '0.9.2.4', '0.9.2.5',
            '0.9.2.6', '0.9.2.a7', '0.9.2.a8', '0.9.2.a9', '0.9.2.a10',
            '1.0.0.1', '1.0.0.2', '1.3.0.1', '1.3.0.2', '1.3.0.3', '1.3.0.4', '1.3.1', '1.3.1.1',
            '1.3.1.2', '1.3.1.3', '1.3.1.4', '1.3.1.5', '1.3.1.6', '1.3.1.7', '1.3.1.8',
            '1.3.1.9', '1.3.1.10', '1.3.1.11', '1.3.1.12', '1.3.1.13', '1.3.1.14', '1.3.2.1', '1.3.2.2',
            '1.3.2.3', '1.3.2.4', '1.3.2.5', '1.3.2.6', '1.3.2.7', '1.3.2.8', '1.3.2.9', '1.4.0.0', '1.4.0.1',
            '1.4.0.2', '1.4.1.0', '1.4.1.1', '1.4.1.2', '1.5.0.0', '1.5.0.1', '1.5.0.2', '1.5.0.3', '1.6.0.1',
            '1.6.0.2', '1.6.0.3', '1.6.0.4', '1.6.0.5', '1.7.0.1', '1.8.0.1', '1.8.0.2', '1.8.0.3', '1.8.0.4',
            "1.8.0.5", "1.8.0.6", "1.8.0.7",
            "1.8.0.8", "1.8.0.9", "1.8.1.0", "1.8.1.1", "1.8.1.2", '1.8.1.3', '1.8.1.4', '1.8.1.5', '1.8.1.6',
            '1.8.1.7', '1.8.1.8', '1.8.1.9', '1.8.2.0', '1.8.2.1', '1.8.2.2', '1.8.2.3', '1.8.2.4', '1.8.2.5',
            '1.8.2.6', '1.8.2.7', '1.8.3.0', '1.8.3.1', '1.8.3.2',
            '1.9.0.1', '1.9.0.2', '1.9.0.3', '1.9.0.4', '1.9.0.5', '1.9.0.6', '1.9.0.7', '1.9.0.8', '1.9.0.9', '1.9.1.0',
            '1.9.1.1', '1.9.1.2', '1.9.1.3', '1.9.1.4', '1.9.1.5', '1.9.1.6', '1.9.1.7', '1.9.1.8', '1.9.1.9', '1.10.0.1',
            '1.10.0.2', '1.10.0.3', '1.10.0.4', '1.10.0.5', '1.10.0.6', '1.10.0.7', '1.10.0.8', '1.10.0.9', '1.10.0.10',
            '1.10.0.11', '1.10.0.12', '1.11.0.1', '1.11.0.2', '1.11.0.3', '1.11.0.4', '1.11.0.5', '1.11.0.6', '1.11.0.7', '1.11.0.8',
            '1.12.0.1', '1.12.0.2', '1.12.0.3', '1.12.0.4', '1.12.0.5', '1.12.0.6', '1.12.0.7', '1.12.0.8', '1.12.0.9', '1.12.1.0', '1.12.1.1',
            '1.12.1.2', '1.12.1.3', '1.13.0.1', '1.13.0.2', '1.13.0.3', '1.13.0.4', '1.13.0.5', '1.13.0.6', '1.13.0.7', '1.13.0.8',
            '1.14.0.1', '1.14.0.2', '1.14.0.3', '1.14.0.4', '1.14.0.5']
ONLY_UPDATE_DB_MODELS = [
    '0.9.2.1', '0.9.2.2', '0.9.2.3', '0.9.2.5', '0.9.2.6', '0.9.2.a8',
    '1.0.0.2', '1.3.0.1', '1.3.0.2', '1.3.0.3', '1.3.0.4', '1.3.1', '1.3.1.1', '1.3.1.2',
    '1.3.1.3', '1.3.1.4', '1.3.1.5', '1.3.1.6', '1.3.1.7', '1.3.1.8', '1.3.1.9', '1.3.1.10',
    '1.3.1.11', '1.3.1.13', '1.3.1.14', '1.3.2.1', '1.3.2.2', '1.3.2.4', '1.3.2.6', '1.3.2.7', '1.3.2.9', '1.4.0.0',
    '1.4.0.1', '1.4.0.2', '1.4.1.0', '1.4.1.1', '1.4.1.2', '1.5.0.0', '1.5.0.1', '1.5.0.2', '1.5.0.3', '1.6.0.1',
    '1.6.0.2', '1.6.0.3', '1.6.0.4', '1.7.0.1', '1.8.0.1', '1.8.0.2', '1.8.0.3', '1.8.0.4', "1.8.0.5", "1.8.0.6",
    "1.8.0.9", "1.8.1.0",
    "1.8.1.2", '1.8.1.5', '1.8.1.7', '1.8.1.9', '1.8.2.0', '1.8.2.2', '1.8.2.3', '1.8.2.4', '1.8.2.5', '1.8.2.6',
    '1.8.2.7', '1.8.3.0', '1.8.3.1', '1.9.0.1', '1.9.0.2', '1.9.0.3', '1.9.0.6', '1.9.0.8', '1.9.0.9', '1.9.1.0', '1.9.1.3', '1.9.1.5',
    '1.9.1.9', '1.10.0.1', '1.10.0.2', '1.10.0.10', '1.10.0.11', '1.11.0.1', '1.11.0.4', '1.11.0.5', '1.11.0.6', '1.12.0.1', '1.12.0.2',
    '1.12.0.3', '1.12.0.4', '1.12.0.5', '1.12.0.6', '1.12.0.7', '1.12.0.8', '1.12.0.9', '1.12.1.0', '1.12.1.1', '1.12.1.2', '1.12.1.3',
    '1.13.0.3', '1.13.0.4', '1.13.0.5', '1.13.0.6', '1.13.0.8', '1.14.0.1', '1.14.0.2', '1.14.0.3', '1.14.0.4']


def upgrade(version):
    '''
    Upgraded function need to check it can handle multi calls situation, 
    just in case multi pods will call it several times.
    ex. Insert data need to check data has already existed or not.
    '''
    if version in ONLY_UPDATE_DB_MODELS:
        alembic_upgrade()
    elif version == '0.9.2':
        cleanup_change_to_orm()
        alembic_upgrade()
        create_harbor_users()
        create_harbor_projects()
    elif version == '0.9.2.4':
        create_k8s_user()
        create_k8s_namespace()
    elif version == '0.9.2.a7':
        alembic_upgrade()
        move_version_to_db(version)
    elif version == '0.9.2.a9':
        create_limitrange_in_namespace()
    elif version == '0.9.2.a10':
        delete_and_recreate_role_in_namespace()
    elif version == '1.0.0.1':
        fill_sonarqube_resources()
    elif version == '1.3.1.12':
        fill_project_owner_by_role()
    elif version == '1.3.2.3':
        init_sync_redmine()
    elif version == '1.3.2.8':
        set_default_user_from_ad_column()
    elif version == '1.4.0.1':
        set_default_project_creator()
    elif version == '1.5.0.2':
        set_default_plugin_software_type()
    elif version == '1.6.0.5':
        alembic_upgrade()
        devops_version.set_deployment_uuid()
    elif version == '1.8.0.7':
        alembic_upgrade()
        set_default_alert_days()
    elif version == '1.8.0.8':
        alembic_upgrade()
        create_alert_in_project()
    elif version == '1.8.1.1':
        alembic_upgrade()
        set_default_trace_order()
    elif version == '1.8.1.3':
        set_default_alert_days()
        create_alert_in_project()
    elif version == '1.8.1.4':
        fix_trace_order()
    elif version == "1.8.1.6":
        alembic_upgrade()
        add_default_in_trace_order()
    elif version == "1.8.1.8":
        refresh_trace_order()
    elif version == "1.8.2.1":
        drop_trace_result()
    elif version == '1.8.3.0':
        set_default_application_restart_number()
    elif version == '1.8.3.2':
        alembic_upgrade()
        create_issue_extension()
    elif version == '1.9.0.4':
        pass
    elif version == '1.9.0.5':
        pass
    elif version == '1.9.0.7':
        pass
    elif version == '1.9.1.1':
        insert_sync_redmine_info_in_table_lock()
    elif version == '1.9.1.2':
        modify_sync_redmine_info()
    elif version == '1.9.1.4':
        delete_table_redmine_project()
    elif version == '1.9.1.6':
        alembic_upgrade()
        insert_pod_restart_times_in_system_type()
    elif version == '1.9.1.7':
        delete_table_redmine_project()
    elif version == '1.9.1.8':
        alembic_upgrade()
        insert_pod_restart_limit_in_system_parameter()
    elif version == '1.10.0.3':
        remove_executions()
    elif version == '1.10.0.4':
        turn_tags_off()
    elif version == '1.10.0.5':
        insert_github_verify_info_in_system_parameter()
    elif version == '1.10.0.6':
        alembic_upgrade()
        insert_default_value_in_module()
    elif version == '1.10.0.7':
        insert_pipline_remain_limit_in_system_parameter()
    elif version == '1.10.0.8':
        fix_uninsert_data_in_system_parameter()
    elif version == '1.10.0.9':
        change_default_value_to_empty_string_in_system_parameter()
    elif version == '1.10.0.12':
        insert_git_commit_history_in_system_parameter()
    elif version == '1.11.0.2':
        remove_duplicate_data_from_upgarde()
    elif version == '1.11.0.3':
        insert_download_issues_in_lock()
    elif version == '1.11.0.7':
        pass
    elif version == '1.11.0.8':
        pass
    elif version == '1.13.0.1':
        add_project_nfs_path_real()
    elif version == '1.13.0.2':
        insert_execute_sync_templ_in_table_lock()
    elif version == '1.13.0.7':
        insert_sync_redmine_project_relation_in_system_parameter()
    elif version == '1.14.0.5':
        insert_notification_message_period_of_validity()


def insert_notification_message_period_of_validity():
    if SystemParameter.query.filter_by(name="notification_message_period_of_validity").first() is None:
        row = SystemParameter(
            name="notification_message_period_of_validity",
            value={"months": 12},
            active=True
        )
        db.session.add(row)
        db.session.commit()


def insert_sync_redmine_project_relation_in_system_parameter():
    if SystemParameter.query.filter_by(name="sync_redmine_project_relation").first() is None:
        row = SystemParameter(
            name="sync_redmine_project_relation",
            value={"hours": 1},
            active=True
        )
        db.session.add(row)
        db.session.commit()


def insert_execute_sync_templ_in_table_lock():
    if Lock.query.filter_by(name="execute_sync_templ").first() is None:
        redmine_info = Lock(name="execute_sync_templ", is_lock=False)
        db.session.add(redmine_info)
        db.session.commit()


def add_project_nfs_path_real():
    for pj in Project.query.all():
        project_nfs_file_path = f"./devops-data/project-data/{pj.name}/pipeline"
        os.makedirs(project_nfs_file_path, exist_ok=True)
        os.chmod(project_nfs_file_path, 0o777)


def add_project_nfs_path():
    for pj in Project.query.all():
        project_nfs_file_path = f"./project-data/{pj.id}"
        os.makedirs(project_nfs_file_path, exist_ok=True)
        os.chmod(project_nfs_file_path, 0o777)


def insert_download_issues_in_lock():
    if Lock.query.filter_by(name="download_pj_issues").first() is None:
        row = Lock(
            name="download_pj_issues",
            is_lock=False,
        )
        db.session.add(row)
        db.session.commit()


def remove_duplicate_data_from_upgarde():
    ServerType.query.filter(ServerType.type == "pod_restart_times", ServerType.id != 1).delete()
    Lock.query.filter(Lock.name == "sync_redmine", Lock.id != 1).delete()
    db.session.commit()


def insert_git_commit_history_in_system_parameter():
    if SystemParameter.query.filter_by(name="git_commit_history").first() is None:
        row = SystemParameter(
            name="git_commit_history",
            value={"keep_days": 30},
            active=False
        )
        db.session.add(row)
        db.session.commit()


def change_default_value_to_empty_string_in_system_parameter():
    github_verify_info = SystemParameter.query.filter_by(name="github_verify_info").first()
    github_verify_info.value = {"token": "", "account": ""}
    db.session.commit()


def fix_uninsert_data_in_system_parameter():
    if SystemParameter.query.filter_by(name="github_verify_info").first() is None:
        row = SystemParameter(
            name="github_verify_info",
            value={"token": None, "account": None},
            active=False
        )
        db.session.add(row)
        db.session.commit()

    k8s_pod_time = SystemParameter.query.filter_by(name="k8s_pod_restart_times_limit").first()
    k8s_pod_time.active = True
    db.session.commit()


def insert_pipline_remain_limit_in_system_parameter():
    if SystemParameter.query.filter_by(name="k8s_pipline_executions_remain_limit").first() is None:
        row = SystemParameter(
            name="k8s_pipline_executions_remain_limit",
            value={"limit_pods": 5},
            active=True
        )
        db.session.add(row)
        db.session.commit()


def insert_default_value_in_module():
    k8s_pod_time = SystemParameter.query.filter_by(name="k8s_pod_restart_times_limit").first()
    github_info = SystemParameter.query.filter_by(name="github_verify_info").first()
    k8s_pod_time.active = True
    github_info.active = False
    db.session.commit()


def insert_github_verify_info_in_system_parameter():
    if SystemParameter.query.filter_by(name="github_verify_info").first() is None:
        row = SystemParameter(
            name="github_verify_info",
            value={"token": None, "account": None},
        )
        db.session.add(row)
        db.session.commit()


def insert_pod_restart_limit_in_system_parameter():
    if SystemParameter.query.filter_by(name="k8s_pod_restart_times_limit").first() is None:
        row = SystemParameter(
            name="k8s_pod_restart_times_limit",
            value={"limit_times": 20},
        )
        db.session.add(row)
        db.session.commit()


def insert_pod_restart_times_in_system_type():
    if ServerType.query.filter_by(type="pod_restart_times").first() is None:
        row = ServerType(
            server="k8s",
            type="pod_restart_times",
        )
        db.session.add(row)
        db.session.commit()


def delete_table_redmine_project():
    try:
        db.session.query(RedmineProject).delete()
        db.session.commit()
    except:
        db.session.rollback()


def modify_sync_redmine_info():
    redmine_info = Lock.query.filter_by(name="sync_redmine").first()
    redmine_info.sync_date = "2000-01-01 00:00:00"
    db.session.commit()


def insert_sync_redmine_info_in_table_lock():
    if Lock.query.filter_by(name="sync_redmine").first() is None:
        redmine_info = Lock(name="sync_redmine", is_lock=False)
        db.session.add(redmine_info)
        db.session.commit()


def create_issue_extension():
    issue_id_list = []
    projects = Project.query.all()
    project_id_list = [pj.id for pj in projects]
    project_id_list.remove(-1)
    for pj_id in project_id_list:
        plan_pj_id = project.get_plan_project_id(pj_id)
        issues = redmine.rm_get_issues_by_project(plan_pj_id)
        issue_id_list.extend([issue["id"] for issue in issues])

    issue_id_list = list(set(issue_id_list))
    for issue_id in issue_id_list:
        issue = IssueExtensions(issue_id=issue_id, point=0)
        db.session.add(issue)
        db.session.commit()


def set_default_application_restart_number():
    rows = db.session.query(Application).all()
    for row in rows:
        row.restart_number = 0
        db.session.commit()


def drop_trace_result():
    db.session.query(TraceResult).delete()
    db.session.commit()


def refresh_trace_order():
    db.session.query(TraceOrder).delete()
    db.session.commit()


def add_default_in_trace_order():
    db.session.query(TraceOrder).delete()
    db.session.commit()

    rows = db.session.query(Project).all()
    for row in rows:
        row.trace_order = [TraceOrder(
            name="標準檢測模組", project_id=row.id, order=["Epic", "Feature", "Test Plan"], default=True)]
        db.session.add(row)
        db.session.commit()


def fix_trace_order():
    db.session.query(TraceOrder).delete()
    db.session.commit()

    rows = db.session.query(Project).all()
    for row in rows:
        row.trace_order = [TraceOrder(
            name="標準檢測模組", project_id=row.id, order=["Epic", "Feature", "Test Plan"])]
        db.session.add(row)
        db.session.commit()


def set_default_trace_order():
    rows = db.session.query(Project).all()
    for row in rows:
        row.trace_order = [TraceOrder(
            name="標準檢測模組", project_id=row.id, order=["Epic", "Feature", "Test Plan"])]
        db.session.add(row)
        db.session.commit()


def create_alert_in_project():
    rows = db.session.query(Project).all()
    for row in rows:
        row.alert = False
        db.session.commit()


def set_default_alert_days():
    row = DefaultAlertDays.query.first()
    if row is None:
        new = DefaultAlertDays(
            unchange_days=30,
            comming_days=7,
        )
        db.session.add(new)
        db.session.commit()


def set_default_plugin_software_type():
    rows = db.session.query(PluginSoftware).all()
    for row in rows:
        row.type_id = 1
        db.session.commit()


def set_default_project_creator():
    rows = db.session.query(Project). \
        filter(
        Project.owner_id is not None,
        Project.creator_id is None
    ).all()
    check = []
    for row in rows:
        if row.id not in check:
            row.creator_id = row.owner_id
            check.append(row.id)
            db.session.commit()


def set_default_user_from_ad_column():
    rows = db.session.query(User). \
        filter(
        User.from_ad is None,
    ).all()
    for row in rows:
        row.from_ad = False
        db.session.commit()


def move_version_to_db(version):
    row = model.NexusVersion.query.first()
    if row is None:
        new = model.NexusVersion(api_version=version)
        db.session.add(new)
        db.session.commit()
    else:
        row.api_version = version
        db.session.commit()
    if os.path.exists('.api_version'):
        os.remove('.api_version')


def create_k8s_user():
    # get db user list
    rows = db.session.query(User, UserPluginRelation) \
        .join(User).all()
    k8s_sa_list = kubernetesClient.list_service_account()
    for row in rows:
        user_sa_name = util.encode_k8s_sa(row.User.login)
        if user_sa_name not in k8s_sa_list:
            print("still not create sa user: {0}".format(
                row.UserPluginRelation.kubernetes_sa_name))
            kubernetesClient.create_service_account(user_sa_name)
            row.UserPluginRelation.kubernetes_sa_name = user_sa_name
        db.session.commit()


def create_k8s_namespace():
    rows = db.session.query(ProjectPluginRelation, Project). \
        join(Project).all()
    namespace_list = kubernetesClient.list_namespace()
    for row in rows:
        if row.Project.name not in namespace_list:
            print("need create k8s namespace project: {0}".format(
                row.Project.name))
            kubernetesClient.create_namespace(row.Project.name)
            kubernetesClient.create_namespace_quota(row.Project.name)
            kubernetesClient.create_role_in_namespace(row.Project.name)
            members = db.session.query(ProjectUserRole, UserPluginRelation). \
                join(UserPluginRelation, ProjectUserRole.user_id == UserPluginRelation.user_id). \
                filter(ProjectUserRole.project_id ==
                       row.ProjectPluginRelation.project_id).all()
            for member in members:
                print("attach member {0} into k8s namespace {1}".format(
                    member, row.Project.name))
                kubernetesClient.create_role_binding(row.Project.name,
                                                     member.UserPluginRelation.kubernetes_sa_name)
            rancher.rc_add_namespace_into_rc_project(row.Project.name)


def create_limitrange_in_namespace():
    rows = db.session.query(ProjectPluginRelation, Project). \
        join(Project).all()
    namespace_list = kubernetesClient.list_namespace()
    for row in rows:
        if row.Project.name in namespace_list:
            limitrange_list = kubernetesClient.list_limitrange_in_namespace(
                row.Project.name)
            if "project-limitrange" not in limitrange_list:
                print(
                    f"project {row.Project.name} don't have limitrange, create one")
                kubernetesClient.create_namespace_limitrange(row.Project.name)


def delete_and_recreate_role_in_namespace():
    rows = db.session.query(ProjectPluginRelation, Project). \
        join(Project).all()
    namespace_list = kubernetesClient.list_namespace()
    for row in rows:
        if row.Project.name in namespace_list:
            role_list = kubernetesClient.list_role_in_namespace(
                row.Project.name)
            if f"{row.Project.name}-user-role" in role_list:
                print(
                    f"namepsace {row.Project.name} has old {row.Project.name}-user-role, delete it")
                kubernetesClient.delete_role_in_namespace(row.Project.name,
                                                          f"{row.Project.name}-user-role")
                new_role_list = kubernetesClient.list_role_in_namespace(
                    row.Project.name)
                print(
                    f"After delete, namepsace {row.Project.name} hrs user-role-list: {new_role_list}")
                kubernetesClient.create_role_in_namespace(row.Project.name)
                finish_role_list = kubernetesClient.list_role_in_namespace(
                    row.Project.name)
                print(
                    f"namespace {row.Project.name} user role list: {finish_role_list}")


def fill_project_owner_by_role():
    roles = [3, 5, 1]
    for role in roles:
        fill_projet_owner(role)


def fill_projet_owner(id):
    rows = db.session.query(Project, ProjectUserRole). \
        join(ProjectUserRole). \
        filter(
        Project.owner_id is None,
        Project.id != -1,
        ProjectUserRole.role_id == id,
        ProjectUserRole.project_id == Project.id
    ).all()
    check = []
    for row in rows:
        if row.Project.id not in check:
            row.Project.owner_id = row.ProjectUserRole.user_id
            check.append(row.Project.id)
            db.session.commit()


def fill_sonarqube_resources():
    projects = model.Project.query.all()
    for c, project in enumerate(projects):
        if project.id < 0:
            continue
        logger.info(f'Filling sonarqube project {c + 1}/{len(projects)}...')
        try:
            sq_create_project(project.name, project.display)
        except DevOpsError as e:
            if 'key already exists' in e.unpack_response()['errors'][0]['msg']:
                continue

    users = model.User.query.all()
    for c, user in enumerate(users):
        args = {
            'login': user.login,
            'name': user.name,
            'password': 'SQDevOps2021',
        }
        logger.info(f'Filling sonarqube user {c + 1}/{len(users)}...')
        try:
            sq_create_user(args)
        except DevOpsError as e:
            if 'already exists' in e.unpack_response()['errors'][0]['msg']:
                continue


def create_harbor_projects():
    rows = db.session.query(ProjectPluginRelation, Project.name). \
        join(Project).all()
    for row in rows:
        if row.ProjectPluginRelation.harbor_project_id is None:
            harbor_project_id = harbor.hb_create_project(row.name)
            row.ProjectPluginRelation.harbor_project_id = harbor_project_id
            members = db.session.query(ProjectUserRole, UserPluginRelation). \
                join(UserPluginRelation, ProjectUserRole.user_id == UserPluginRelation.user_id). \
                filter(ProjectUserRole.project_id == row.ProjectPluginRelation.project_id
                       ).all()
            for m in members:
                harbor.hb_add_member(harbor_project_id,
                                     m.UserPluginRelation.harbor_user_id)
            db.session.commit()


def create_harbor_users():
    rows = db.session.query(UserPluginRelation, User). \
        join(User).all()
    for row in rows:
        if row.UserPluginRelation.harbor_user_id is None:
            args = {
                'login': row.User.login,
                'password': 'HarborFromIIIDevOps2020',
                'name': row.User.name,
                'email': row.User.email
            }
            u = model.ProjectUserRole.query.filter_by(
                user_id=row.user_id, project_id=-1).one()
            hid = harbor.hb_create_user(
                args, is_admin=u.role_id == role.ADMIN.id)
            row.UserPluginRelation.harbor_user_id = hid
            db.session.commit()


def cleanup_project_gone(rows):
    for row in rows:
        p_count = model.Project.query.filter_by(id=row.project_id).count()
        if p_count == 0:
            db.session.delete(row)
    db.session.commit()


def cleanup_change_to_orm():
    # Cleanup corrupted data violating foreign key constraints
    cleanup_project_gone(model.Flows.query.all())
    cleanup_project_gone(model.Parameters.query.all())
    cleanup_project_gone(model.Requirements.query.all())
    cleanup_project_gone(model.TestCases.query.all())
    # Insert dummy project
    p = model.Project.query.filter_by(id=-1).first()
    if p is None:
        new = model.Project(id=-1, name='dummy-project', disabled=False)
        db.session.add(new)
        db.session.commit()


def init_sync_redmine():
    sync_redmine.init_data_first_time()


def init():
    new = model.NexusVersion(api_version=VERSIONS[-1])
    db.session.add(new)
    db.session.commit()


def needs_upgrade(current, target):
    r = current.split('.')
    c = target.split('.')
    if len(r) == 3:
        r.extend(['a0'])
    if len(c) == 3:
        c.extend(['a0'])
    if c[3][0] == 'a':
        c[3] = c[3][1:]
    if r[3][0] == 'a':
        r[3] = r[3][1:]
    for i in range(4):
        if int(c[i]) > int(r[i]):
            return True
        elif int(c[i]) < int(r[i]):
            return False
    return False


def alembic_upgrade():
    # Rewrite ini file
    with open('alembic.ini', 'w') as ini:
        with open('_alembic.ini', 'r') as template:
            for line in template:
                if line.startswith('sqlalchemy.url'):
                    ini.write('sqlalchemy.url = {0}\n'.format(
                        config.get('SQLALCHEMY_DATABASE_URI')))
                else:
                    ini.write(line)
    os_ret = os.system('alembic upgrade head')
    if os_ret != 0:
        raise RuntimeError('Alembic has error, process stop.')


def current_version():
    if db.engine.has_table(model.NexusVersion.__table__.name):
        # Cannot write in ORM here since NexusVersion table itself may be modified
        result = db.engine.execute('SELECT api_version FROM nexus_version')
        row = result.fetchone()
        result.close()
        if row is not None:
            current = row['api_version']
        else:
            # This is a new server, so NexusVersion table scheme should match the ORM
            current = '0.0.0'
            new = model.NexusVersion(api_version='0.0.0')
            db.session.add(new)
            db.session.commit()
    else:
        # Backward compatibility
        if os.path.exists('.api_version'):
            with (open('.api_version', 'r')) as f:
                current = f.read()
        else:
            current = '0.0.0'
    return current


def run():
    current = current_version()
    try:
        for version in VERSIONS:
            if needs_upgrade(current, version):
                current = version
                row = model.NexusVersion.query.first()
                row.api_version = current
                db.session.commit()
                logger.info('Upgrade to {0}'.format(version))
                upgrade(version)
    except Exception as e:
        raise e
