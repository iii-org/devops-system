import json
from datetime import datetime, timedelta
import time
from resources.handler.jwt import jwt_required
from flask_restful import Resource, reqparse
from gitlab.v4 import objects
from sqlalchemy import desc
import model
import nexus
import util
from enums.gitlab_enums import FileActions
from resources import role, gitlab
from resources.gitlab import single_file
from resources.test_generated_issue import tgi_feed_sideex
import os
import re
import numpy as np
from nexus import nx_get_project_plugin_relation
from . import router_model
import yaml
from pathlib import Path
import resources.apiError as apiError
import pandas as pd
import subprocess
from resources.handler.jwt import get_jwt_identity
import resources.pipeline as pipeline
from resources.activity import record_activity
from enums.action_type import ActionType
from resources import gitlab
from resources.rancher import rancher
from datetime import date
from flask_apispec import marshal_with, doc, use_kwargs
from flask_apispec.views import MethodResource


def sd_start_test(args):
    # Abort previous scans of the same branch
    prev_scans = model.Sideex.query.filter_by(project_name=args["project_name"], branch=args["branch"]).all()
    for prev in prev_scans:
        if prev.status == "Scanning":
            prev.status = "Aborted"
    model.db.session.commit()

    new = model.Sideex(
        project_name=args["project_name"],
        branch=args["branch"],
        commit_id=args["commit_id"],
        status="Scanning",
        result=None,
        report=None,
        run_at=datetime.utcnow(),
    )
    model.db.session.add(new)
    model.db.session.commit()
    return new.id


def sd_finish_test(args):
    row = model.Sideex.query.filter_by(id=args["test_id"]).one()
    row.status = "Finished"
    row.result = args["result"]
    row.report = args["report"]
    row.finished_at = datetime.utcnow()
    model.db.session.add(row)
    model.db.session.commit()
    tgi_feed_sideex(row)

    # Clean up old reports
    rows = (
        model.Sideex.query.filter(
            model.Sideex.project_name == row.project_name,
            model.Sideex.branch == row.branch,
            model.Sideex.report.isnot(None),
        )
        .order_by(desc(model.Sideex.id))
        .all()
    )
    for index, row in enumerate(rows):
        if index < 5:
            continue
        row.report = None
        model.db.session.commit()


def sd_get_tests(project_id):
    project_name = nexus.nx_get_project(id=project_id).name
    rows = model.Sideex.query.filter_by(project_name=project_name).all()
    ret = []
    for row in rows:
        ret.append(process_row(row, project_id))
    return ret


def sd_get_test_by_commit(project_id, commit_id):
    project_name = nexus.nx_get_project(id=project_id).name
    row = model.Sideex.query.filter_by(project_name=project_name, commit_id=commit_id).first()
    if row is not None:
        return process_row(row, project_id)
    else:
        return {}


def sd_get_latest_test(project_id):
    project_name = nexus.nx_get_project(id=project_id).name
    row = model.Sideex.query.filter_by(project_name=project_name).order_by(desc(model.Sideex.id)).first()
    if row is None:
        return {}
    return process_row(row, project_id)


def process_row(row, project_id):
    # 12 hour timeout
    if row.status == "Scanning" and datetime.utcnow() - row.run_at > timedelta(hours=1):
        row.status = "Failed"
        model.db.session.commit()
    r = json.loads(str(row))
    r["issue_link"] = gitlab.commit_id_to_url(project_id, r["commit_id"])
    return r


def sd_get_report(test_id):
    row = model.Sideex.query.filter_by(id=test_id).one()
    return row.report


# --------------------- Resources ---------------------
class Sideex(Resource):
    @jwt_required
    def post(self):
        parser = reqparse.RequestParser()
        parser.add_argument("project_name", type=str)
        parser.add_argument("branch", type=str)
        parser.add_argument("commit_id", type=str)
        args = parser.parse_args()
        role.require_in_project(project_name=args["project_name"])
        return util.success({"test_id": sd_start_test(args)})

    @jwt_required
    def put(self):
        parser = reqparse.RequestParser()
        parser.add_argument("test_id", type=int)
        parser.add_argument("result", type=str)
        parser.add_argument("report", type=str)
        args = parser.parse_args()
        test_id = args["test_id"]
        project_name = model.Sideex.query.filter_by(id=test_id).one().project_name
        role.require_in_project(project_name=project_name)
        sd_finish_test(args)
        return util.success()

    @jwt_required
    def get(self, project_id):
        role.require_in_project(project_id=project_id)
        return util.success(sd_get_tests(project_id))


class SideexV2(MethodResource):
    @doc(tags=["Sideex"], description="generate test_id.")
    @jwt_required
    @use_kwargs(router_model.SideexPostSch, location="json")
    @marshal_with(router_model.SideexPostRes)
    def post(self, **kwargs):
        role.require_in_project(project_name=kwargs["project_name"])
        return util.success({"test_id": sd_start_test(kwargs)})

    @doc(tags=["Sideex"], description="update sideex testing result")
    @jwt_required
    @use_kwargs(router_model.SideexPutSch, location="json")
    @marshal_with(util.CommonResponse)
    def put(self, **kwargs):
        test_id = kwargs["test_id"]
        project_name = model.Sideex.query.filter_by(id=test_id).one().project_name
        role.require_in_project(project_name=project_name)
        sd_finish_test(kwargs)
        return util.success()

    @doc(tags=["Sideex"], description="update sideex testing result")
    @jwt_required
    @marshal_with(router_model.SideexGetTestResultRes)
    def get(self, project_id):
        role.require_in_project(project_id=project_id)
        return util.success(sd_get_tests(project_id))


def load_file_from_gitlab(repository_id, path):
    f = gitlab.gitlab.gl_get_file_from_lib(repository_id, path)
    decode_dict = yaml.safe_load(f.decode())
    return decode_dict


def get_gitlab_file_todict(project_id, filename):
    configs: dict[str, str] = {
        "software_name": "SideeX",
        "path": "iiidevops/sideex",
        "file_name_key": "",
    }
    repository_id: int = nx_get_project_plugin_relation(nexus_project_id=project_id).git_repository_id
    trees = gitlab.gitlab.ql_get_tree(repository_id, configs["path"], all=True)

    for tree in trees:
        if filename == tree["name"]:
            data = load_file_from_gitlab(repository_id, tree["path"])
            return data


def get_sideex_json_variable(project_id, filename):
    data = get_gitlab_file_todict(project_id, filename)
    if data:
        varibale_list = re.findall("\${.*?\}", json.dumps(data, ensure_ascii=False))
        unique_list = np.unique(varibale_list).tolist()
        if "${target_origin}" in unique_list:
            unique_list.remove("${target_origin}")
        elif "${target_url}" in unique_list:
            unique_list.remove("${target_url}")
        output_list = [i.replace("$", "").replace("{", "").replace("}", "") for i in unique_list]
    else:
        raise apiError.DevOpsError(404, f"{filename} not found")
    return output_list


def get_global_json(project_id, filename):
    variables_data = get_gitlab_file_todict(project_id, "Global Variables.json")
    result_dict = {}
    if variables_data:
        if "target_url" in variables_data:
            variables_data.pop("target_url")
        output_list = get_sideex_json_variable(project_id, filename)
        for k in output_list:
            if k in variables_data.keys():
                result_dict.update({k: [variables_data[k]]})
            else:
                result_dict.update({k: []})
        return result_dict


def get_setting_file(project_id, filename):
    result_list = []
    setting_data = None
    result_dict = get_global_json(project_id, filename)
    output_list = get_sideex_json_variable(project_id, filename)
    project_name = nexus.nx_get_project(id=project_id).name
    if os.path.isfile(f"devops-data/project-data/{project_name}/pict/_setting_sideex.json"):
        with open(f"devops-data/project-data/{project_name}/pict/_setting_sideex.json") as json_data:
            setting_data = json.load(json_data)
    sorted_dict = {}
    if setting_data:
        for var in setting_data["var"]:
            sorted_dict.update({var["name"]: var["value"]})
        for k in output_list:
            if k in sorted_dict.keys():
                result_dict.update({k: sorted_dict[k]})
            else:
                result_dict.update({k: []})
    if result_dict:
        result_list = [
            {
                "name": k,
                "type": str(type(v[0])).replace("<class '", "").replace("'>", "") if v != [] else None,
                "value": v,
            }
            for k, v in result_dict.items()
        ]
    return_dict = {
        "var": result_list,
        "rule": setting_data["rule"] if setting_data else [],
    }
    return return_dict


def check_file_exist(project_id):
    project_name = nexus.nx_get_project(id=project_id).name
    result_file_exist = True if os.path.isfile(f"devops-data/project-data/{project_name}/pict/result.xlsx") else False
    return_dict = {"result_file_exist": result_file_exist}
    return return_dict


def save_to_txt(project_id, kwargs):
    df = pd.DataFrame(kwargs["var"])
    df["name"] = df["name"].apply(lambda x: x + ":")
    df["value"] = df["value"].apply(lambda x: str(x).replace("[", "").replace("]", "").replace("'", ""))
    project_name = nexus.nx_get_project(id=project_id).name
    if not os.path.isdir(f"devops-data/project-data/{project_name}/pict"):
        Path(f"devops-data/project-data/{project_name}/pict").mkdir(parents=True, exist_ok=True)
    np.savetxt(
        f"devops-data/project-data/{project_name}/pict/_{get_jwt_identity()['user_id']}-model.txt",
        df[["name", "value"]].values,
        fmt="%s",
    )
    write_list = kwargs["rule"]
    with open(
        f"devops-data/project-data/{project_name}/pict/_{get_jwt_identity()['user_id']}-model.txt",
        "a+",
    ) as data:
        for i in write_list:
            i = i.replace("'", '"')
            data.write(f"\n{i}")


def update_config_file(project_id, kwargs):
    project_name = nexus.nx_get_project(id=project_id).name
    if not os.path.isdir(f"devops-data/project-data/{project_name}/pict"):
        Path(f"devops-data/project-data/{project_name}/pict").mkdir(parents=True, exist_ok=True)
    with open(
        f'devops-data/project-data/{project_name}/pict/_{get_jwt_identity()["user_id"]}-setting_sideex.json',
        "w+",
        encoding="utf8",
    ) as json_data:
        json_data.write(json.dumps(kwargs, ensure_ascii=False))
    with open(
        f"devops-data/project-data/{project_name}/pict/_setting_sideex.json",
        "w+",
        encoding="utf8",
    ) as json_data:
        json_data.write(json.dumps(kwargs, ensure_ascii=False))
    save_to_txt(project_id, kwargs)


def pict_convert_result(project_id) -> list[str]:
    """
    將 model 透過 pict 轉換成 list

    :param project_id: 專案 id
    :return: 轉換後的 list
    """
    project_name = nexus.nx_get_project(id=project_id).name
    file: str = f"devops-data/project-data/{project_name}/pict/_{get_jwt_identity()['user_id']}-model.txt"

    if os.path.isfile(file):
        # Get pict from https://github.com/microsoft/pict
        std_output: bytes = subprocess.check_output(["pict", file])
        decoded: str = std_output.decode("utf-8")
        concat: str = decoded.replace("\t", "\n").replace("\r\n", "\n")
        result: list[str] = concat.split("\n")
        result.remove("")
        return result
    else:
        raise apiError.DevOpsError(404, f"{file} not found")


def sort_convert_result_to_df(project_id, branch=None, commit_id=None):
    pict_list = pict_convert_result(project_id)
    project_name = nexus.nx_get_project(id=project_id).name
    with open(
        f"devops-data/project-data/{project_name}/pict/_{get_jwt_identity()['user_id']}-setting_sideex.json",
        "r",
        encoding="utf8",
    ) as file:
        txt_content = json.load(file)
    # calculate by setting.json
    cut_num = len(txt_content["var"])
    df_input = pd.DataFrame(pict_list)
    sorted_list = []
    # sort by variable num
    for i in df_input.index:
        i += 1
        if i % int(cut_num) == 0:
            sorted_list.append(df_input.iloc[i - int(cut_num) : i][0].values.tolist())
    df_sorted = pd.DataFrame(sorted_list)
    df_sorted.columns = df_sorted.loc[0]
    df_sorted = df_sorted.drop(0)
    if branch and commit_id:
        extra_path = f"/{branch}/{commit_id}/"
    else:
        extra_path = "/"
    df_sorted.to_excel(f"devops-data/project-data/{project_name}/pict{extra_path}result.xlsx")
    # np.savetxt(f"devops-data/project-data/{project_name}/pict/_{get_jwt_identity()['user_id']}-result.txt", df_sorted, fmt='%s', header=','.join(df_sorted.columns.tolist()))
    return df_sorted


def generate_result(project_id):
    df_sorted = sort_convert_result_to_df(project_id)
    df_dict = df_sorted.fillna("").T.to_dict()
    result_list = [v for k, v in df_dict.items()]
    return result_list


def generate_json_file(project_id, filename, kwargs):
    df_sorted = sort_convert_result_to_df(project_id)
    template_content: dict = get_gitlab_file_todict(project_id, filename)

    repository_id: int = nx_get_project_plugin_relation(nexus_project_id=project_id).git_repository_id
    project: objects.Project = gitlab.gitlab.gl.projects.get(repository_id)

    gitlab_files: list[dict[str, str]] = []
    if not os.path.isdir("iiidevops/sideex"):
        Path("iiidevops/sideex").mkdir(parents=True, exist_ok=True)
    for i in range(1, len(df_sorted) + 1):
        file_path: str = f"iiidevops/sideex/_{get_jwt_identity()['user_id']}-sideex{i}.json"

        for key, value in df_sorted.T.to_dict()[i].items():
            result = re.sub(
                "\${%s\}" % key,
                value,
                json.dumps(template_content, indent=4, ensure_ascii=False),
            )
            with open(file_path, "w+", encoding="utf8") as f:
                f.write(result)

                # Reset cursor
                f.seek(0)

                # Fetch file result
                template_content = json.loads(f.read())

        if i != len(df_sorted):
            next_run = pipeline.get_pipeline_next_run(repository_id)

        # 將變動寫回 file 裡面
        change_suite = re.sub(
            json.loads(result)["suites"][0]["title"],
            f"{get_jwt_identity()['user_id']}_{json.loads(result)['suites'][0]['title']}-{i}",
            json.dumps(json.loads(result), indent=4, ensure_ascii=False),
        )
        with open(file_path, "w", encoding="utf8") as f:
            f.write(change_suite)
        data = get_gitlab_file_todict(project_id, filename)
        template_content = data

        # 將檔案加入等待推送到 GitLab 的清單
        gitlab_files.append(single_file(file_path, file_path))

        if i == len(df_sorted):
            pipeline.stop_and_delete_pipeline(repository_id, next_run, branch="")
    paths = [{"software_name": "SideeX", "path": "iiidevops/sideex", "file_name_key": ""}]
    for path in paths:
        trees = gitlab.gitlab.ql_get_tree(repository_id, path["path"], all=True)
        for tree in trees:
            if f'_{get_jwt_identity()["user_id"]}-sideex' in tree["name"]:
                action = "Update"
                break
            else:
                action = "Create"
    commit_msg = (
        f"{action} sideex file _{get_jwt_identity()['user_id']}-sideex.json, replace variable "
        f"{df_sorted.columns.tolist()} with {df_sorted.values.tolist()}"
    )

    commit_to_gitlab(project, gitlab_files, commit_msg)
    if kwargs.get("record"):
        record_branch_commit_id(project_id)


def commit_to_gitlab(project: objects.Project, files: list[dict[str, str]], commit_msg: str) -> None:
    """
    將檔案通送到 GitLab 並移除本地檔案

    :param project:
    :param files:
    :return:
    """
    # 檢查檔案是否存在
    origin_files: list[dict[str, str]] = gitlab.gitlab.ql_get_tree(project.get_id(), "iiidevops/sideex", all=True)
    origin_files_map: dict[str, dict[str, str]] = {_["name"]: _ for _ in origin_files}

    for file in files:
        if Path(file["file_path"]).name in origin_files_map:
            file["action"] = str(FileActions.UPDATE.value)

        # Clean up local files
        if os.path.isfile(file["file_path"]):
            os.remove(file["file_path"])

    # Push to GitLab
    gitlab.gitlab.create_multiple_file_commit(project, files, commit_message=commit_msg)


def get_current_branch_commit(project_id):
    repository_id: int = nx_get_project_plugin_relation(nexus_project_id=project_id).git_repository_id
    commit_info = gitlab.gitlab.gl_get_latest_commit_from_all_branches(repository_id)

    branch = commit_info["branch_name"]
    commit_id = commit_info["short_id"]
    return branch, commit_id


def get_pict_status(project_id):
    row_pict = model.Pict.query.filter_by(project_id=project_id).order_by(desc(model.Pict.id)).first()
    branch, commit_id = row_pict.branch, row_pict.commit_id
    row = model.Sideex.query.filter_by(branch=branch).filter_by(commit_id=commit_id).first()
    finish = False
    if row:
        finish = True if row.status == "Finished" else False
    status_dict = {
        "finish": finish,
        "branch": branch,
        "commit_id": commit_id,
        "sideex_id": row_pict.sideex_id,
    }
    if finish:
        delete_json_configfile(project_id)
    return status_dict


def delete_json_configfile(project_id):
    project_name = nexus.nx_get_project(id=project_id).name
    if os.path.isfile(f"devops-data/project-data/{project_name}/pict/_{get_jwt_identity()['user_id']}-model.txt"):
        os.remove(f"devops-data/project-data/{project_name}/pict/_{get_jwt_identity()['user_id']}-model.txt")
    if os.path.isfile(
        f"devops-data/project-data/{project_name}/pict/_{get_jwt_identity()['user_id']}-setting_sideex.json"
    ):
        os.remove(f"devops-data/project-data/{project_name}/pict/_{get_jwt_identity()['user_id']}-setting_sideex.json")
        repository_id = nx_get_project_plugin_relation(nexus_project_id=project_id).git_repository_id
        project = gitlab.gitlab.gl.projects.get(repository_id)
        paths = [{"software_name": "SideeX", "path": "iiidevops/sideex", "file_name_key": ""}]
        delete_list = []
        for path in paths:
            trees = gitlab.gitlab.ql_get_tree(repository_id, path["path"], all=True)
            for tree in trees:
                if f'_{get_jwt_identity()["user_id"]}-sideex' in tree["name"]:
                    delete_list.append({"action": "delete", "file_path": tree["path"]})
        gitlab.gitlab.gl_operate_multi_files(
            project,
            delete_list,
            f"delete _{get_jwt_identity()['user_id']}-sideex json file",
            "",
        )


def record_branch_commit_id(project_id):
    branch, commit_id = get_current_branch_commit(project_id)
    commit_id = commit_id[0:7]
    while True:
        time.sleep(10)
        row = model.Sideex.query.filter_by(branch=branch).filter_by(commit_id=commit_id).first()
        if row:
            save_to_project_dir(project_id, branch, commit_id)
            save_to_db(project_id, row, branch, commit_id)
            break


def save_to_db(project_id, row, branch, commit_id):
    new_record = model.Pict(
        project_id=project_id,
        branch=branch,
        commit_id=commit_id,
        run_at=datetime.utcnow(),
        status="finish",
        sideex_id=row.id,
    )
    model.db.session.add(new_record)
    model.db.session.commit()


def save_to_project_dir(project_id, branch, commit_id):
    project_name = nexus.nx_get_project(id=project_id).name
    commit_id = commit_id[0:7]
    path = f"devops-data/project-data/{project_name}/pict/{branch}/{commit_id}"
    if not os.path.isfile(path):
        Path(path).mkdir(parents=True, exist_ok=True)
    sort_convert_result_to_df(project_id, branch, commit_id)


def is_json(string):
    try:
        json.loads(string)
    except ValueError:
        return False
    return True


def row_to_dict(row):
    ret = {}
    if row is None:
        return row
    for key in type(row).__table__.columns.keys():
        value = getattr(row, key)
        if type(value) is datetime or type(value) is date:
            ret[key] = str(value)
        elif isinstance(value, str) and is_json(value):
            ret[key] = json.loads(value)
        else:
            ret[key] = value
    return ret


@record_activity(ActionType.DELETE_SIDEEX_JSONFILE)
def delete_project_all_config_file(project_id):
    role.require_project_owner(get_jwt_identity()["user_id"], project_id)
    project_name = nexus.nx_get_project(id=project_id).name
    path = f"devops-data/project-data/{project_name}/pict"
    files = os.listdir(path)
    # delete project-data file start with "_"
    if files:
        for file in files:
            if str(file)[0] == "_":
                os.remove(f"{path}/{file}")
    # delete gitlab file start with "_"
    repository_id = nx_get_project_plugin_relation(nexus_project_id=project_id).git_repository_id
    project = gitlab.gitlab.gl.projects.get(repository_id)
    delete_list = []
    paths = [{"software_name": "SideeX", "path": "iiidevops/sideex", "file_name_key": ""}]
    for path in paths:
        trees = gitlab.gitlab.ql_get_tree(repository_id, path["path"], all=True)
        for tree in trees:
            if tree["name"][0] == "_":
                delete_list.append({"action": "delete", "file_path": tree["path"]})
    gitlab.gitlab.gl_operate_multi_files(project, delete_list, "delete all the _sideex.json files by api", "")


def history_pict_result(project_id):
    project_name = nexus.nx_get_project(id=project_id).name
    file_path = f"devops-data/project-data/{project_name}/pict"
    file_name = "result.xlsx"
    df = pd.read_excel(f"{file_path}/{file_name}", index_col=0)
    df_dict = df.fillna("").T.to_dict()
    result_list = [v for k, v in df_dict.items()]
    return result_list


class SideexJsonfileVariable(Resource):
    @use_kwargs(router_model.SideexGetVariableSch, location="json")
    @jwt_required
    def post(self, project_id, **kwargs):
        return util.success(get_setting_file(project_id, kwargs["filename"]))

    @use_kwargs(router_model.SideexPutVariableSch, location="json")
    @jwt_required
    def put(self, project_id, **kwargs):
        return util.success(update_config_file(project_id, kwargs))


class SideexJsonfileVariableV2(MethodResource):
    @doc(tags=["Sideex"], description="get pict setting")
    @jwt_required
    @use_kwargs(router_model.SideexGetVariableSch, location="json")
    @marshal_with(router_model.SideexGetVariableRes)
    def post(self, project_id, **kwargs):
        return util.success(get_setting_file(project_id, kwargs["filename"]))

    @doc(tags=["Sideex"], description="update pict setting")
    @jwt_required
    @use_kwargs(router_model.SideexPutVariableSch, location="json")
    @marshal_with(util.CommonResponse)
    def put(self, project_id, **kwargs):
        return util.success(update_config_file(project_id, kwargs))


class SideexGenerateJsonfile(Resource):
    @use_kwargs(router_model.SideexGetVariableSch, location="json")
    @jwt_required
    def post(self, project_id, **kwargs):
        generate_json_file(project_id, kwargs["filename"], kwargs)
        return util.success()

    @jwt_required
    def delete(self, project_id):
        delete_json_configfile(project_id)
        return util.success()


class SideexGenerateJsonfileV2(MethodResource):
    @doc(tags=["Sideex"], description="generate pict jsonfile")
    @jwt_required
    @use_kwargs(router_model.SideexGetVariableSch, location="json")
    @marshal_with(util.CommonResponse)
    def post(self, project_id, **kwargs):
        generate_json_file(project_id, kwargs["filename"], kwargs)
        return util.success()

    @doc(tags=["Sideex"], description="delete pict jsonfile by operate user")
    @jwt_required
    @marshal_with(util.CommonResponse)
    def delete(self, project_id):
        delete_json_configfile(project_id)
        return util.success()


class SideexDeleteAllfile(Resource):
    @jwt_required
    def delete(self, project_id):
        delete_project_all_config_file(project_id)
        return util.success()


@doc(tags=["Sideex"], description="delete pict all jsonfile")
class SideexDeleteAllfileV2(MethodResource):
    @jwt_required
    @marshal_with(util.CommonResponse)
    def delete(self, project_id):
        delete_project_all_config_file(project_id)
        return util.success()


class HistoryPictResult(Resource):
    @jwt_required
    def get(self, project_id):
        return history_pict_result(project_id)


class SideexReport(Resource):
    @jwt_required
    def get(self, test_id):
        project_name = model.Sideex.query.filter_by(id=test_id).one().project_name
        role.require_in_project(project_name=project_name)
        return util.success(sd_get_report(test_id))


@doc(tags=["Sideex"], description="get sideex report")
class SideexReportV2(MethodResource):
    @jwt_required
    @marshal_with(router_model.SideexGetReportRes)
    def get(self, test_id):
        project_name = model.Sideex.query.filter_by(id=test_id).one().project_name
        role.require_in_project(project_name=project_name)
        return util.success(sd_get_report(test_id))


class GenerateResult(Resource):
    @jwt_required
    def get(self, project_id):
        return util.success(generate_result(project_id))


@doc(tags=["Sideex"], description="generate pict result")
class GenerateResultV2(MethodResource):
    @jwt_required
    @marshal_with(router_model.SideexGenerateResultRes)
    def get(self, project_id):
        return util.success(generate_result(project_id))


class PictStatus(Resource):
    @jwt_required
    def get(self, project_id):
        return util.success(get_pict_status(project_id))


@doc(tags=["Sideex"], description="get pict status")
class PictStatusV2(MethodResource):
    @jwt_required
    @marshal_with(router_model.SideexPictStatusRes)
    def get(self, project_id):
        return util.success(get_pict_status(project_id))


class CheckResultFileExist(Resource):
    @jwt_required
    def get(self, project_id):
        return util.success(check_file_exist(project_id))


@doc(tags=["Sideex"], description="check result_file exist.")
class CheckResultFileExistV2(MethodResource):
    @marshal_with(router_model.SideexCheckResultFileRes)
    @jwt_required
    def get(self, project_id):
        return util.success(check_file_exist(project_id))


# --------------------- API router ---------------------
def router(api):
    api.add_resource(Sideex, "/sideex", "/project/<sint:project_id>/sideex")
    api.add_resource(SideexReport, "/sideex_report/<int:test_id>")
