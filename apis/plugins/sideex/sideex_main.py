import json
from datetime import datetime, timedelta

from flask_jwt_extended import jwt_required
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
from flask_apispec import use_kwargs
import yaml
from pathlib import Path
import resources.apiError as apiError
import pandas as pd
import subprocess
import urllib.parse
from flask_jwt_extended import get_jwt_identity
import resources.pipeline as pipeline


def sd_start_test(args):
    # Abort previous scans of the same branch
    prev_scans = model.Sideex.query.filter_by(
        project_name=args['project_name'],
        branch=args['branch']).all()
    for prev in prev_scans:
        if prev.status == 'Scanning':
            prev.status = 'Aborted'
    model.db.session.commit()

    new = model.Sideex(
        project_name=args['project_name'],
        branch=args['branch'],
        commit_id=args['commit_id'],
        status='Scanning',
        result=None,
        report=None,
        run_at=datetime.now()
    )
    model.db.session.add(new)
    model.db.session.commit()
    return new.id


def sd_finish_test(args):
    row = model.Sideex.query.filter_by(
        id=args['test_id']
    ).one()
    row.status = 'Finished'
    row.result = args['result']
    row.report = args['report']
    row.finished_at = datetime.now()
    model.db.session.add(row)
    model.db.session.commit()
    tgi_feed_sideex(row)

    # Clean up old reports
    rows = model.Sideex.query.filter(
        model.Sideex.project_name == row.project_name,
        model.Sideex.branch == row.branch,
        model.Sideex.report.isnot(None)
    ).order_by(desc(model.Sideex.id)).all()
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
    row = model.Sideex.query.filter_by(project_name=project_name,
                                       commit_id=commit_id).first()
    if row is not None:
        return process_row(row, project_id)
    else:
        return {}


def sd_get_latest_test(project_id):
    project_name = nexus.nx_get_project(id=project_id).name
    row = model.Sideex.query.filter_by(
        project_name=project_name).order_by(desc(model.Sideex.id)).first()
    if row is None:
        return {}
    return process_row(row, project_id)


def process_row(row, project_id):
    # 12 hour timeout
    if row.status == 'Scanning' and \
        datetime.now() - row.run_at > timedelta(hours=1):
        row.status = 'Failed'
        model.db.session.commit()
    r = json.loads(str(row))
    r['issue_link'] = gitlab.commit_id_to_url(project_id, r['commit_id'])
    return r


def sd_get_report(test_id):
    row = model.Sideex.query.filter_by(id=test_id).one()
    return row.report


# --------------------- Resources ---------------------
class Sideex(Resource):
    @jwt_required()
    def post(self):
        parser = reqparse.RequestParser()
        parser.add_argument('project_name', type=str)
        parser.add_argument('branch', type=str)
        parser.add_argument('commit_id', type=str)
        args = parser.parse_args()
        role.require_in_project(project_name=args['project_name'])
        return util.success({'test_id': sd_start_test(args)})

    @jwt_required()
    def put(self):
        parser = reqparse.RequestParser()
        parser.add_argument('test_id', type=int)
        parser.add_argument('result', type=str)
        parser.add_argument('report', type=str)
        args = parser.parse_args()
        test_id = args['test_id']
        project_name = model.Sideex.query.filter_by(id=test_id).one().project_name
        role.require_in_project(project_name=project_name)
        sd_finish_test(args)
        return util.success()

    @jwt_required()
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
        "file_name_key": ""
    }
    repository_id: int = nx_get_project_plugin_relation(nexus_project_id=project_id).git_repository_id
    trees = gitlab.gitlab.ql_get_tree(repository_id, configs['path'], all=True)

    for tree in trees:
        if filename == tree['name']:
            data = load_file_from_gitlab(repository_id, tree['path'])
            return data


def get_sideex_json_variable(project_id, filename):
    data = get_gitlab_file_todict(project_id, filename)
    if data:
        varibale_list = re.findall('\${.*?\}',json.dumps(data))
        unique_list = np.unique(varibale_list).tolist()
        if '${target_origin}' in unique_list:
            unique_list.remove('${target_origin}')
        elif '${target_url}' in unique_list:
            unique_list.remove('${target_url}')
        output_list = [i.replace("$", "").replace("{", "").replace("}", "") for i in unique_list]
    else:
        raise apiError.DevOpsError(404, f'{filename} not found')
    return output_list


def get_global_json(project_id, filename):
    variables_data = get_gitlab_file_todict(project_id, 'Global Variables.json')
    result_dict = {}
    if variables_data:
        if 'target_url' in variables_data:
            variables_data.pop('target_url')
        output_list = get_sideex_json_variable(project_id, filename)
        for k in output_list:
            if k in variables_data.keys():
                result_dict.update({k: variables_data[k]})
            else:
                result_dict.update({k: []})
        return result_dict


def get_setting_file(project_id, filename):
    result_list = []
    setting_data = None
    result_dict = get_global_json(project_id, filename)
    output_list = get_sideex_json_variable(project_id, filename)
    paths = [{
        "software_name": "SideeX",
        "path": "iiidevops/sideex/parameter",
        "file_name_key": ""
    }]
    repository_id = nx_get_project_plugin_relation(
        nexus_project_id=project_id).git_repository_id
    for path in paths:
        trees = gitlab.gitlab.ql_get_tree(repository_id, path['path'], all=True)
        for tree in trees:
            if tree['name'] == f'_{get_jwt_identity()["user_id"]}-setting_sideex.json':
                setting_data = load_file_from_gitlab(repository_id, tree['path'])
                break
    if setting_data and type(setting_data) == str:
        setting_data = json.loads(setting_data)
    sorted_dict = {}
    if setting_data:
        for var in setting_data['var']:
            sorted_dict.update({var['name']: var['value']})
        for k in output_list:
            if k in sorted_dict.keys():
                result_dict.update({k: sorted_dict[k]})
            else:
                result_dict.update({k: []})
    if result_dict:
        result_list = [{"name": k, "type": str(type(v[0])).replace('<class \'', '').replace('\'>', '') if v != [] else None, "value": v} for k, v in result_dict.items()]
    return_dict = {
          "var": result_list,
          "rule": setting_data['rule'] if setting_data else []
        }
    return return_dict


def save_to_txt(project_id, kwargs):
    df = pd.DataFrame(kwargs['var'])
    df['name'] = df['name'].apply(lambda x: x + ':')
    df['value'] = df['value'].apply(lambda x: str(x).replace('[', '').replace(']', '').replace("\'", ''))
    project_name = nexus.nx_get_project(id=project_id).name
    if not os.path.isdir(f'devops-data/project-data/{project_name}'):
        Path(f"devops-data/project-data/{project_name}").mkdir(parents=True, exist_ok=True)
    np.savetxt(f"devops-data/project-data/{project_name}/_{get_jwt_identity()['user_id']}-model.txt", df[['name', 'value']].values, fmt='%s')
    write_list = kwargs['rule']
    with open(f"devops-data/project-data/{project_name}/_{get_jwt_identity()['user_id']}-model.txt", 'a+') as data:
        for i in write_list:
            i = i.replace('\'', '\"')
            data.write(f"\n{i}")


def check_variable_not_null(kwargs):
    for variable in kwargs['var']:
        for key, value in variable.items():
            if key == "value":
                if not value or value == "":
                    raise apiError.DevOpsError(404, "value can't be null")


def update_config_file(project_id, kwargs):
    check_variable_not_null(kwargs)
    project_name = nexus.nx_get_project(id=project_id).name
    if not os.path.isdir(f'devops-data/project-data/{project_name}'):
        Path(f"devops-data/project-data/{project_name}").mkdir(parents=True, exist_ok=True)
    with open(f'devops-data/project-data/{project_name}/_{get_jwt_identity()["user_id"]}-setting_sideex.json', "w+") as json_data:
        json_data.write(json.dumps(kwargs))
    save_to_txt(project_id, kwargs)


def pict_convert_result(project_id) -> list[str]:
    """
    將 model 透過 pict 轉換成 list

    :param project_id: 專案 id
    :return: 轉換後的 list
    """
    project_name = nexus.nx_get_project(id=project_id).name
    file: str = f"devops-data/project-data/{project_name}/_{get_jwt_identity()['user_id']}-model.txt"

    if os.path.isfile(file):
        # Get pict from https://github.com/microsoft/pict
        std_output: bytes = subprocess.check_output(['pict', file])
        # std_output = b'abc\tdef\txx2\n10\ta54\t12\n123\tabc\t12\n123\ta54\tab\n3\tabc\t99\n10\tabc\t56\n3\txyz\tab\n3\txyz\t99\n3\ta54\t12\n10\txyz\tab\n123\txyz\t99\n10\ta54\t99\n2\tabc\t99\n123\ta54\t56\n3\tabc\tab\n2\txyz\t12\n2\ta54\t56\n3\txyz\t56\n3\ta54\t12\n2\txyz\tab\n3\tabc\t56\n'
        decoded: str = std_output.decode("ascii")
        concat: str = decoded.replace("\t", "\n").replace("\r\n", "\n")
        result: list[str] = concat.split("\n")
        result.remove("")
        return result
    else:
        raise apiError.DevOpsError(404, f"{file} not found")


def sort_convert_result_to_df(project_id):
    pict_list = pict_convert_result(project_id)
    project_name = nexus.nx_get_project(id=project_id).name
    file = open(f"devops-data/project-data/{project_name}/_{get_jwt_identity()['user_id']}-model.txt", 'r')
    txt_content = file.read()
    cut_num = txt_content.count('\n')
    df_input = pd.DataFrame(pict_list)
    sorted_list = []
    # sort by variable num
    for i in df_input.index:
        i += 1
        if i % int(cut_num) == 0:
            sorted_list.append(df_input.iloc[i - int(cut_num):i][0].values.tolist())
    df_sorted = pd.DataFrame(sorted_list)
    df_sorted.columns = df_sorted.loc[0]
    df_sorted = df_sorted.drop(0)
    return df_sorted


def generate_json_file(project_id, filename):
    df_sorted = sort_convert_result_to_df(project_id)
    template_content: dict = get_gitlab_file_todict(project_id, filename)

    repository_id: int = nx_get_project_plugin_relation(nexus_project_id=project_id).git_repository_id
    project: objects.Project = gitlab.gitlab.gl.projects.get(repository_id)

    gitlab_files: list[dict[str,str]] = []

    for i in range(1, len(df_sorted)):
        file_path: str = f"iiidevops/sideex/*{get_jwt_identity()['user_id']}-sideex{i}.json"

        for key, value in df_sorted.T.to_dict()[i].items():
            result = re.sub('\${%s\}' % key, value, json.dumps(template_content, indent=4))
            with open(file_path, 'w') as f:
                f.write(result)
                file = open(f'iiidevops/sideex/*{get_jwt_identity()["user_id"]}-sideex{i}.json', 'r')
                template_content = json.loads(file.read())

        if i != len(df_sorted):
            next_run = pipeline.get_pipeline_next_run(repository_id)

        # 將變動寫回 file 裡面
        change_suite = re.sub(
            'django-sqlite-todo',
            f'{get_jwt_identity()["user_id"]}_django-sqlite-todo-{i}',
            json.dumps(json.loads(result), indent=4)
        )
        with open(file_path, 'w') as f:
            f.write(change_suite)

        # 將檔案加入等待推送到 GitLab 的清單
        gitlab_files.append(single_file(file_path, file_path))

        if i == len(df_sorted):
            pipeline.stop_and_delete_pipeline(repository_id, next_run, branch="master")

    commit_to_gitlab(project, gitlab_files)


def commit_to_gitlab(project: objects.Project, files: list[dict[str, str]]) -> None:
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
    gitlab.gitlab.create_multiple_file_commit(project, files)


class SideexJsonfileVariable(Resource):
    @jwt_required()
    @use_kwargs(router_model.SideexGetVariableRes, location="json")
    def post(self, project_id, **kwargs):
        return util.success(get_setting_file(project_id, kwargs['filename']))

    @jwt_required()
    @use_kwargs(router_model.SideexPutVariableRes, location="json")
    def put(self, project_id, **kwargs):
        return util.success(update_config_file(project_id, kwargs))


class SideexGenerateJsonfile(Resource):
    @jwt_required()
    @use_kwargs(router_model.SideexGetVariableRes, location="json")
    def post(self, project_id, **kwargs):
        generate_json_file(project_id, kwargs['filename'])
        return util.success()


class SideexReport(Resource):
    @jwt_required()
    def get(self, test_id):
        project_name = model.Sideex.query.filter_by(id=test_id).one().project_name
        role.require_in_project(project_name=project_name)
        return util.success(sd_get_report(test_id))


# --------------------- API router ---------------------
def router(api):
    api.add_resource(Sideex, '/sideex', '/project/<sint:project_id>/sideex')
    api.add_resource(SideexReport, '/sideex_report/<int:test_id>')
