import json
from datetime import datetime, timedelta

from flask_jwt_extended import jwt_required
from flask_restful import Resource, reqparse
from sqlalchemy import desc

import model
import nexus
import util
from resources import role, gitlab
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


# def get_sideex_json_variable():
#     variable_name = []
#     variable_value = []
#     if os.path.isfile('./iiidevops/sideex/sideex.json'):
#         with open('./iiidevops/sideex/sideex.json') as json_data:
#             if json_data is not None:
#                 data = json.load(json_data)
#         for a in data['suites']:
#             for b, c in a.items():
#                 if b == "cases":
#                     for d in c:
#                         for e, f in d.items():
#                             if e == 'records':
#                                 for g in f:
#                                     for h, i in g.items():
#                                         if h == 'name':
#                                             variable_name.append(i)
#                                         elif h == 'value':
#                                             variable_value.append(i['options'][0]['value'])
#     else:
#         return util.respond(404, f"{'sideex.json'} not found")
#     uncheck_set = set(zip(variable_name, variable_value))
#     value_dict = {}
#     variable_unique = np.unique(variable_name).tolist()
#     df2 = pd.DataFrame(uncheck_set)
#     for i in variable_unique:
#         value_dict.update({i: df2.loc[df2[0] == i][1].tolist()})
#     if os.path.isfile('./iiidevops/sideex/global_variables.json'):
#         with open('./iiidevops/sideex/global_variables.json') as json_data:
#             if json_data is not None:
#                 variables_data = json.load(json_data)
#         global_list = [value for key, value in variables_data.items()]
#         for key, value_list in value_dict.items():
#             for value in value_list:
#                 if value in global_list:
#                     value_list.remove(value)
#     else:
#         return util.respond(404, f"{'global_variables.json'} not found")
#     return value_dict
def load_file_from_gitlab(repository_id, path):
    f = gitlab.gitlab.gl_get_file_from_lib(repository_id, path)
    decode_dict = yaml.safe_load(f.decode())
    return decode_dict


def get_gitlab_file_todict(project_id, filename):
    paths = [{
        "software_name": "SideeX",
        "path": "iiidevops/sideex",
        "file_name_key": ""
    }]
    repository_id = nx_get_project_plugin_relation(
        nexus_project_id=project_id).git_repository_id
    for path in paths:
        trees = gitlab.gitlab.ql_get_tree(repository_id, path['path'])
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
    result_dict = get_global_json(project_id, filename)
    output_list = get_sideex_json_variable(project_id, filename)
    setting_data = get_gitlab_file_todict(project_id, f'_{get_jwt_identity()["user_id"]}-setting_sideex.json')
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
          "rule": []
        }
    return return_dict


def save_to_txt(kwargs):
    df = pd.DataFrame(kwargs['var'])
    df['name'] = df['name'].apply(lambda x: x + ':')
    df['value'] = df['value'].apply(lambda x: str(x).replace('[', '').replace(']', '').replace("\'", ''))
    np.savetxt(f"./iiidevops/sideex/_{get_jwt_identity()['user_id']}-model.txt", df[['name', 'value']].values, fmt='%s')


def check_variable_not_null(kwargs):
    for variable in kwargs['var']:
        for key, value in variable.items():
            if key == "value":
                if not value or value == "":
                    raise apiError.DevOpsError(404, "value can't be null")


def update_config_file(project_id, kwargs):
    check_variable_not_null(kwargs)
    f = False
    filename = f'_{get_jwt_identity()["user_id"]}-setting_sideex.json'
    paths = [{
        "software_name": "SideeX",
        "path": "iiidevops/sideex",
        "file_name_key": ""
    }]
    repository_id = nx_get_project_plugin_relation(
        nexus_project_id=project_id).git_repository_id
    if not os.path.isdir('./iiidevops/sideex'):
        Path('./iiidevops/sideex').mkdir(parents=True, exist_ok=True)
    with open(f'./iiidevops/sideex/_{get_jwt_identity()["user_id"]}-setting_sideex.json', "w+") as json_data:
        json_data.write(json.dumps(kwargs))
    save_to_txt(kwargs)
    pj = gitlab.gitlab.gl.projects.get(repository_id)
    if get_gitlab_file_todict(project_id, f"{get_jwt_identity()['user_id']}_model.txt"):
        url = urllib.parse.quote(f"iiidevops/sideex/_{get_jwt_identity()['user_id']}-model.txt", safe='')
        gitlab.gitlab.gl_delete_file(repository_id, url, {"commit_message": "delete _model.txt by sideex_auto_test"}, "master")
    gitlab.gitlab.gl_create_file(pj, f"iiidevops/sideex/_{get_jwt_identity()['user_id']}-model.txt", f"_{get_jwt_identity()['user_id']}-model.txt", "./iiidevops/sideex", "master")
    for path in paths:
        trees = gitlab.gitlab.ql_get_tree(repository_id, path['path'])
        for tree in trees:
            if filename == tree['name']:
                f = gitlab.gitlab.gl_get_file_from_lib(repository_id, tree['path'])
                f.content = json.dumps(kwargs)
                f.save(
                    branch='master',
                    author_email='system@iiidevops.org.tw',
                    author_name='iiidevops',
                    commit_message=f'Add "iiidevops" in branch.rancher-pipeline.yml.')
                break
        if not f:
            gitlab.gitlab.gl_create_file(pj, f"iiidevops/sideex/_{get_jwt_identity()['user_id']}-setting_sideex.json", f"_{get_jwt_identity()['user_id']}-setting_sideex.json",
                                               "./iiidevops/sideex", "master")


def pict_convert_result():
    if os.path.isfile(f"./iiidevops/sideex/_{get_jwt_identity()['user_id']}-model.txt"):
        # std_output = subprocess.check_output(['pict', 'iiidevops/sideex/_model.txt'])
        std_output = b'abc\tdef\txx2\n10\ta54\t12\n123\tabc\t12\n123\ta54\tab\n3\tabc\t99\n10\tabc\t56\n3\txyz\tab\n3\txyz\t99\n3\ta54\t12\n10\txyz\tab\n123\txyz\t99\n10\ta54\t99\n2\tabc\t99\n123\ta54\t56\n3\tabc\tab\n2\txyz\t12\n2\ta54\t56\n3\txyz\t56\n3\ta54\t12\n2\txyz\tab\n3\tabc\t56\n'
        remove_space = std_output.decode("ascii").split('\t')
        concat = '\n'.join(remove_space)
        remove_n = concat.split('\n')
        remove_n.remove('')
        return remove_n
    else:
        raise apiError.DevOpsError(404, f"_{get_jwt_identity()['user_id']}-model.txt not found")


def sort_convert_result_to_df():
    pict_list = pict_convert_result()
    file = open(f"./iiidevops/sideex/_{get_jwt_identity()['user_id']}-model.txt", 'r')
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


def gernerate_json_file(filename):
    df_sorted = sort_convert_result_to_df()
    file = open(f'./iiidevops/sideex/{filename}', 'r')
    txt_content = json.loads(file.read())
    for i in range(1, len(df_sorted)):
        for key, value in df_sorted.T.to_dict()[i].items():
            result = re.sub('\${%s\}' % key, value, json.dumps(txt_content, indent=4))
            with open(f'./iiidevops/sideex/*{get_jwt_identity()["user_id"]}-sideex{i}.json', 'w') as json_writer:
                json_writer.write(result)
                file = open(f'./iiidevops/sideex/*{get_jwt_identity()["user_id"]}-sideex{i}.json', 'r')
                txt_content = json.loads(file.read())
        file = open(f'./iiidevops/sideex/{filename}', 'r')
        txt_content = json.loads(file.read())


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
    def put(self, project_id, **kwargs):
        gernerate_json_file(kwargs['filename'])
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
