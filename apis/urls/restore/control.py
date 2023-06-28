# from model import User, UserMessageType
from util import row_to_dict, read_json_file, check_folder_exist, rows_to_list
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
)
from resources import (
    alert,
    resource_storage,
    starred_project,
    trace_order,
    gitlab,
)
import model
import os


def restore_user_from_json():
    backup_path = os.path.join("devops-data", "backup")
    backup_file = os.path.join(backup_path, "backup_user.json")
    if os.path.exists(backup_path):
        users = read_json_file(backup_file)
        for user in users:
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
        print(f"{backup_file} is not exists")


def restore_project_from_json():
    backup_path = os.path.join("devops-data", "backup")
    backup_file = os.path.join(backup_path, "backup_project.json")
    if os.path.exists(backup_path):
        projects = read_json_file(backup_file)
        for project in projects:
            print(project)
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
                    print(f'pur user :[{user_id}]')
                    if user_id:
                        new_pur = model.ProjectUserRole.query.filter_by(project_id=project_id, user_id=user_id).first()
                        if new_pur:
                            new_pur.role_id = pur.get("role_id")
                        else:
                            new_pur = model.ProjectUserRole(
                                user_id=user_id,
                                project_id=project_id,
                                role_id=pur.get("role_id")
                            )
                        model.db.session.add(new_pur)
                        model.db.session.commit()
            if pce_list:
                for pce in pce_list:
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
                    print(f'sp user :[{user_id}]')
                    if user_id:
                        starred_project.spj_set(
                            user_id=user_id,
                            project_id=project_id
                        )
            if tag_list:
                for tag in tag_list:
                    new_tag = model.Tag.query.filter_by(project_id=project_id, name=tag.get("name")).first()
                    if new_tag:
                        new_tag.next_tag_id = tag.get("next_tag_id")
                    else:
                        model.Tag(
                            project_id=project_id,
                            name=tag.get("name"),
                            next_tag_id=tag.ge("next_tag_id")
                        )
                    model.db.session.add(new_tag)
                    model.db.session.commit()
            if to_list:
                to_names = [to.name for to in trace_order.get_trace_order_by_project(project_id)]
                for to in to_list:
                    if to.get("name") not in to_names:
                        to["project_id"] = project_id
                        trace_order.create_trace_order_by_project(to)
            if tr_list:
                for tr in tr_list:
                    trace_result = model.TraceResult.query.filter_by(project_id=project_id,).first()
                    if trace_result:
                        trace_order.TraceList.update_trace_result(
                            current_num=tr.get("current_num"),
                            current_job=tr.get("current_job"),
                            results=tr.get("results"),
                            execute_time=tr.get("execute_time"),
                            finish_time=tr.get("finish_time"),
                            exception=tr.get("exception"),
                        )
                    else:
                        new_tr = model.TraceResult(
                            project_id=project_id,
                            current_num=tr.get("current_num"),
                            current_job=tr.get("current_job"),
                            results=tr.get("results"),
                            execute_time=tr.get("execute_time"),
                            finish_time=tr.get("finish_time"),
                            exception=tr.get("exception"),
                        )
                        model.db.session.add(new_tr)
                        model.db.session.commit()
    else:
        print(f"{backup_file} is not exists")
