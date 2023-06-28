from util import row_to_dict, write_json_file, check_folder_exist, rows_to_list
from sqlalchemy import inspect, or_, not_, orm
import os
from model import (
    Alert,
    ProjectUserRole,
    Project,
    ProjectResourceStoragelevel,
    ProjectUserRole,
    ProjectParentSonRelation,
    ProjectCommitEndpoint,
    StarredProject,
    User,
    UserMessageType,
    Tag,
    TraceOrder,
    TraceResult,
)


def get_backup_user_all() -> list:
    # 取得除了 sysadmin(在新魕統已經存在的帳號) 及 機器人帳號(建立專案時會自動產生)以外的所有使用者資料。
    return User.query.filter(not_(or_(User.login == 'sysadmin',
                                      User.login.like('project_bot_%')))
                             ).order_by(User.id).all()


def get_project_user_role_by_user_id(user_id: int) -> ProjectUserRole:
    return ProjectUserRole.query.filter(ProjectUserRole.project_id == -1, ProjectUserRole.user_id == user_id).first()


def get_user_message_type(user_id: int) -> UserMessageType:
    return UserMessageType.query.filter_by(user_id=user_id).first()


def write_backup_json(backup_name: str, backup_data: list):
    backup_path = os.path.join("devops-data", "backup")
    check_folder_exist(backup_path, True)
    write_json_file(os.path.join(backup_path, f"{backup_name}.json"), backup_data)


def backup_user_to_json():
    backup_data = []
    # 取得所有使用者資料
    users = get_backup_user_all()
    for user in users:
        user_json = row_to_dict(user)
        # 取得使用者的 role_id (是指使用者建立時的 role_id，而非使用者在專案中的 role_id)。
        pur = get_project_user_role_by_user_id(user.id)
        if pur:
            user_json["role_id"] = pur.role_id
        # 取得使用者接收訊息的類型。
        umt = get_user_message_type(user.id)
        if umt:
            user_json["user_message_type"] = row_to_dict(umt)
        backup_data.append(user_json)
    write_backup_json("backup_user", backup_data)


def get_backup_project_all() -> list:
    return Project.query.filter(Project.id != -1).order_by(Project.id).all()


def get_user_login_by_user_id(user_id: int) -> str:
    return User.query.filter(User.id == user_id).first().login


def get_alert_by_project_id(project_id: int) -> list:
    return Alert.query.filter_by(project_id=project_id).order_by(Alert.id).all()


def get_project_resource_storagelevel_by_project_id(project_id:int) -> list:
    return ProjectResourceStoragelevel.query.filter(ProjectResourceStoragelevel.project_id == project_id).all()


def get_project_user_role_by_project_id(project_id, owner_id, creator_id) -> list:
    return ProjectUserRole.query.with_entities(User.login,
                                               ProjectUserRole.role_id
                                               ).join(User,
                                                      ProjectUserRole.user_id==User.id,
                                                      isouter=True
                                                      ).filter(ProjectUserRole.project_id == project_id,
                                                               ProjectUserRole.user_id != owner_id,
                                                               ProjectUserRole.user_id != creator_id,
                                                               ProjectUserRole.role_id != 6
                                                               ).order_by(ProjectUserRole.user_id
                                                                          ).all()


def get_project_commit_endpoint_by_project_id(project_id: int) -> list:
    return ProjectCommitEndpoint.query.filter_by(project_id=project_id).order_by(ProjectCommitEndpoint.id).all()


def get_project_parent_son_relation() -> list:
    p_p = orm.aliased(Project)
    p_s = orm.aliased(Project)
    return ProjectParentSonRelation.query.with_entities(p_p.name.label("parent_name"),
                                                        p_s.name.label("son_name"),
                                                        ProjectParentSonRelation.created_at
                                                        ).join(p_p,
                                                               ProjectParentSonRelation.parent_id == p_p.id,
                                                               isouter=True
                                                               ).join(p_s,
                                                                      ProjectParentSonRelation.son_id == p_s.id,
                                                                      isouter=True
                                                                      ).all()


def get_starred_project_by_project_id(project_id: int) -> list:
    return User.query.join(StarredProject,
                           User.id == StarredProject.user_id
                           ).filter(StarredProject.project_id == project_id
                                    ).order_by(User.id).all()


def get_tag_by_project_id(project_id: int) -> list:
    return Tag.query.filter_by(project_id=project_id).order_by(Tag.id).all()


def get_trace_order_by_project_id(project_id: int) -> list:
    return TraceOrder.query.filter_by(project_id=project_id).order_by(TraceOrder.id).all()


def get_trace_result_by_project_id(project_id: int) -> list:
    return TraceResult.query.filter_by(project_id=project_id).order_by(TraceResult.id).all()


def backup_project_to_json():
    projects_result = []
    # 取得以專案 id 排序的所有專案資料列表
    projects = get_backup_project_all()
    for project in projects:
        project_json = row_to_dict(project)
        # 取得專案的 creator_id 及 owner_id 使用者的 login 欄位資訊
        if project.owner_id:
            project_json["owner_login"] = get_user_login_by_user_id(project.owner_id)
        if project.creator_id:
            if project.owner_id == project.creator_id:
                project_json["creator_login"] = project_json["owner_login"]
            else:
                project_json["creator_login"] = get_user_login_by_user_id(project.creator_id)
        # 取得專案資源存儲存級別資訊列表
        prs_list = get_project_resource_storagelevel_by_project_id(project.id)
        if prs_list:
            project_json["project_resource_storagelevel"] = rows_to_list(prs_list)
        # 取得專案中除了 owner_id 及 creator_id 以外的使用者 role_id 。
        pur_list = get_project_user_role_by_project_id(project.id, project.owner_id, project.creator_id)
        if pur_list:
            output = []
            for pur in pur_list:
                output.append({"user_login": pur.login, "role_id": pur.role_id})
            project_json["project_user_role"] = output
        # 依 project_id 取得專最後一次 commit 的 id 資訊列表
        pce_list = get_project_commit_endpoint_by_project_id(project.id)
        if pce_list:
            project_json["project_commit_endpoint"] = rows_to_list(pce_list)
        # 依 project_id 取得 StarredProject 的資訊列表
        sps = get_starred_project_by_project_id(project.id)
        if sps:
            output = []
            for sp in sps:
                output.append(sp.login)
            project_json["starred_project"] = output
        # 依 project_id 取得 tag 資訊列表
        tag_list = get_tag_by_project_id(project.id)
        if tag_list:
            project_json["tag"] = rows_to_list(tag_list)
        # 依 project_id 取得 TraceOrder 資訊列表
        to_list = get_trace_order_by_project_id(project.id)
        if to_list:
            project_json["trace_order"] = rows_to_list(to_list)
        # 依 project_id 取得 TraceResult 資訊列表
        tr_list = get_trace_result_by_project_id(project.id)
        if tr_list:
            project_json["trace_result"] = rows_to_list(tr_list)
        projects_result.append(project_json)
    write_backup_json("backup_project", projects_result)
    # 取得父子專案的關聯資訊
    ppsrs = get_project_parent_son_relation()
    parent_son_result = []
    for ppsr in ppsrs:
        parent_son_result.append({"parent_name": ppsr.parent_name,
                                  "son_name": ppsr.son_name,
                                  "created_at": str(ppsr.created_at)})
    write_backup_json("backup_project_parent_son", parent_son_result)
