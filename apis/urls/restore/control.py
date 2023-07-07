# from model import User, UserMessageType
from util import row_to_dict, read_json_file, check_folder_exist, rows_to_list
from resources.logger import logger
from resources.user import (
    get_user_json_by_login,
    get_user_json_by_email,
    create_user,
    update_user,
    update_user_message_types,
)
from resources.project import (
    get_pj_id_by_name,
    create_project,
    pm_update_project,
    get_project_id_by_name,
    project_add_member,
)
from resources import (
    alert,
    resource_storage,
    starred_project,
    trace_order,
    gitlab,
    tag,
)
import model
import os
import json


def restore_user_from_json():
    backup_path = os.path.join("devops-data", "backup")
    logger.info(f'restore user data to db')
    backup_file = os.path.join(backup_path, "backup_user.json")
    if os.path.exists(backup_path):
        users = read_json_file(backup_file)
        for user in users:
            logger.info(f'user: [{user.get("login")}]')
            user["password"] = "D2p_" + user.get("login")
            umt = user.get("user_message_type")
            del user["user_message_type"]
            if user.get("disabled") is not None:
                user["status"] = "disable" if user["disabled"] else "enable"
            user_id = get_user_json_by_email(user.get("email")).get("id")
            if user_id is None:
                user_id = get_user_json_by_login(user.get("login")).get("id")
            if user_id:
                # del user["password"]
                user["old_password"] = ""
                user["id"] = user_id
                update_user(user_id, user, is_restore=True)
            else:
                del user["id"]
                user_id = create_user(user, True).get("user_id")
            update_user_message_types(user_id, umt)
    else:
        logger.info(f"{backup_file} is not exists")


def restore_project_from_json():
    backup_path = os.path.join("devops-data", "backup")
    # 滙入 default_alert_days 資料到 DB
    logger.info(f'restore default_alert_days data to db')
    backup_file = os.path.join(backup_path, "backup_default_alert_days.json")
    if os.path.exists(backup_path):
        dad_list = read_json_file(backup_file)
        for dad_json in dad_list:
            logger.info(f'dad id:[{dad_json.get("id")}]')
            dad = model.DefaultAlertDays.query.filter_by(id=dad_json.get("id")).first()
            if dad is None:
                dad = model.DefaultAlertDays(
                    unchange_days=dad_json.get("unchange_days"),
                    comming_days=dad_json.get("comming_days")
                )
                model.db.session.add(dad)
                model.db.session.commit()
    else:
        logger.info(f"{backup_file} is not exists")
    # 滙入專案資料到DB
    logger.info(f'restore project data to db')
    backup_file = os.path.join(backup_path, "backup_project.json")
    if os.path.exists(backup_path):
        projects = read_json_file(backup_file)
        for project in projects:
            if project.get("disabled") or project.get("is_lock"):
                continue
            logger.info(f'project: {project}' )
            project["owner_id"] = get_user_json_by_login(project.get("owner_login")).get("id")
            project["creator_id"] = get_user_json_by_login(project.get("creator_login")).get("id")
            project["is_lock"] = False
            project["base_template"] = project["base_example"]
            project["tag_name"] = project["example_tag"]
            del project["id"]
            # if project.get("base_example"):
            #     gl_json = gitlab.gitlab.gl_get_project_by_name(project.get("base_example"))
            #     if gl_json:
            #         project["template_id"] = gl_json["id"]
            # 取得專案資源存儲存級別資訊列表
            prs_list = project.get("project_resource_storagelevel")
            if prs_list:
                del project["project_resource_storagelevel"]
            # 取得專案中除了 owner_id 及 creator_id 以外的使用者 role_id 。
            pur_list = project.get("project_user_role")
            if pur_list:
                del project["project_user_role"]
            # 依 project_id 取得專最後一次 commit 的 id 資訊列表
            pce_list = project.get("project_commit_endpoint")
            if pce_list:
                del project["project_commit_endpoint"]
            # 取得 StarredProject 的資訊列表
            sp_list = project.get("starred_project")
            if sp_list:
                del project["starred_project"]
            # 取得 tag 資訊列表
            tag_list = project.get("tag")
            if tag_list:
                del project["tag"]
            # 取得 TraceOrder 資訊列表
            to_list = project.get("trace_order")
            if to_list:
                del project["trace_order"]
            # 取得 TraceResult 資訊列表
            tr_list = project.get("trace_result")
            if tr_list:
                del project["trace_result"]
            project_id = get_pj_id_by_name(project.get("name")).get("id")
            if project_id > 0:
                pm_update_project(project_id, project, True)
            else:
                project_id = create_project(project["creator_id"], project, True).get("project_id")
            alert.create_alert(project_id, {"enable": project.get("alert")})
            if prs_list:
                for prs in prs_list:
                    resource_storage.update_project_resource_storage_level(project_id, prs)
            if pur_list:
                for pur in pur_list:
                    user_id = get_user_json_by_login(pur.get("user_login")).get("id")
                    logger.info(f'pur user :[{user_id}]')
                    project_add_member(project_id, user_id, True)
                    # if user_id:
                    #     new_pur = model.ProjectUserRole.query.filter_by(project_id=project_id, user_id=user_id).first()
                    #     if new_pur:
                    #         new_pur.role_id = pur.get("role_id")
                    #     else:
                    #         new_pur = model.ProjectUserRole(
                    #             user_id=user_id,
                    #             project_id=project_id,
                    #             role_id=pur.get("role_id")
                    #         )
                    #     model.db.session.add(new_pur)
                    #     model.db.session.commit()
            if pce_list:
                for pce in pce_list:
                    logger.info(f'pce commitr :[{pce.get("commit_id")}]')
                    new_pce = model.ProjectCommitEndpoint.query.filter_by(project_id=project_id).first()
                    if new_pce:
                        new_pce.commit_id = pce.get("commit_id")
                        new_pce.updated_at = pce.get("updated_at")
                    else:
                        new_pce = model.ProjectCommitEndpoint(
                            project_id=project_id,
                            commit_id=pce.get("commit_id"),
                            updated_at=pce.get("updated_at")
                        )
                    model.db.session.add(new_pce)
                    model.db.session.commit()
            if sp_list:
                for sp in sp_list:
                    user_id = get_user_json_by_login(sp).get("id")
                    logger.info(f'sp user :[{user_id}]')
                    if user_id:
                        starred_project.spj_set(
                            user_id=user_id,
                            project_id=project_id
                        )
            if tag_list:
                for tag_json in tag_list:
                    logger.info(f'tag name: [{tag_json.get("name")}]')
                    new_tag = model.Tag.query.filter_by(project_id=project_id, name=str(tag_json.get("name"))).first()
                    if new_tag:
                        new_tag.next_tag_id = None
                    else:
                        new_tag = model.Tag(
                            project_id=project_id,
                            name=tag_json.get("name"),
                            next_tag_id=None
                        )
                        model.db.session.add(new_tag)
                    model.db.session.commit()
                tag.order_pj_tags_by_id()
            if to_list:
                tos = trace_order.get_trace_order_by_project(project_id)
                to_names = []
                for to in tos:
                    to_names.append(to.get("name"))
                logger.info(f'to names: {to_names}')
                for to in to_list:
                    logger.info(f'to name:[{to.get("name")}], type:[{type(to.get("name"))}]')
                    if str(to.get("name")) not in to_names:
                        to["project_id"] = project_id
                        trace_order.create_trace_order_by_project(to)
            if tr_list:
                for tr in tr_list:
                    logger.info(f'tr project id: [{project_id}]')
                    trace_result = model.TraceResult.query.filter_by(project_id=project_id,).first()
                    if trace_result:
                        trace_result.current_num=tr.get("current_num"),
                        # trace_result.current_job=tr.get("current_job"),
                        trace_result.results=json.dumps(tr.get("results")),
                        trace_result.execute_time=tr.get("execute_time"),
                        trace_result.finish_time=tr.get("finish_time"),
                        trace_result.exception=tr.get("exception"),
                    else:
                        new_tr = model.TraceResult(
                            project_id=project_id,
                            current_num=tr.get("current_num"),
                            # current_job=tr.get("current_job"),
                            results=json.dumps(tr.get("results")),
                            execute_time=tr.get("execute_time"),
                            finish_time=tr.get("finish_time"),
                            exception=tr.get("exception"),
                        )
                        model.db.session.add(new_tr)
                    model.db.session.commit()
    else:
        logger.info(f"{backup_file} is not exists")
    # 滙入父子專案關聯資料到DB
    logger.info(f'restore project_parent_son_relation data to db')
    backup_file = os.path.join(backup_path, "backup_project_parent_son.json")
    if os.path.exists(backup_path):
        parent_son_list = read_json_file(backup_file)
        for parent_son in parent_son_list:
            logger.info(
                f'id:[{parent_son.get("parent_name")}], '
                f'parent name: [{parent_son.get("parent_name")}], '
                f'son_name: [{parent_son.get("son_name")}]'
            )
            parent_son["parent_id"] = get_project_id_by_name(parent_son.get("parent_name"))
            parent_son["son_id"] = get_project_id_by_name(parent_son.get("son_name"))
            if parent_son["parent_id"] is None or parent_son["son_id"] is None:
                continue
            ps = model.ProjectParentSonRelation.query.filter_by(
                parent_id=parent_son.get("parent_id"),
                son_id=parent_son.get("son_id")
            ).first()
            if not ps:
                ps = model.ProjectParentSonRelation(
                    parent_id=parent_son.get("parent_id"),
                    son_id=parent_son.get("son_id"),
                    created_at=parent_son.get("created_at")
                )
                model.db.session.add(ps)
                model.db.session.commit()
    else:
        logger.info(f"{backup_file} is not exists")
