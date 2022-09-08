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
def get_sideex_json_variable(project_id, filename):
    find = False
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
                find = True
                break
            else:
                find = False
    if find:
        with open(f'./iiidevops/sideex/{filename}') as json_data:
            if json_data is not None:
                data = json.load(json_data)
        varibale_list = re.findall('\${.*?\}',json.dumps(data))
        unique_list = np.unique(varibale_list).tolist()
        if '${target_origin}' in unique_list:
            unique_list.remove('${target_origin}')
        elif '${target_url}' in unique_list:
            unique_list.remove('${target_url}')
        output_list = [i.replace("$", "").replace("{", "").replace("}", "") for i in unique_list]
    else:
        raise util.respond(404, f'{filename} not found')
    return output_list


def get_global_json(project_id, filename):
    result_dict={}
    if os.path.isfile('./iiidevops/sideex/global_variables.json'):
        with open('./iiidevops/sideex/global_variables.json') as json_data:
            if json_data is not None:
                variables_data = json.load(json_data)
        if 'target_url' in variables_data:
            variables_data.pop('target_url')
        output_list = get_sideex_json_variable(project_id, filename)
        for k in output_list:
            if k in variables_data.keys():
                result_dict.update({k: variables_data[k]})
            else:
                result_dict.update({k: None})
        return result_dict


def get_setting_file(project_id, filename):
    result_dict = get_global_json(project_id, filename)
    with open(f'./iiidevops/sideex/_setting_sideex.json') as json_data:
        if json_data is not None:
            setting_data = json.load(json_data)
    output_list = get_sideex_json_variable(project_id, filename)
    sorted_dict = {}
    for var in setting_data['var']:
        sorted_dict.update({var['name']:var['value']})
    for k in output_list:
        if k in sorted_dict.keys():
            result_dict.update({k: sorted_dict[k]})
        else:
            result_dict.update({k: None})
    result_list = [{"name": k, "type": str(type(v)).replace('<class \'','').replace('\'>',''), "value": v}for k, v in result_dict.items()]
    return_dict = {
          "var": result_list,
          "rule": []
        }
    return return_dict


def update_config_file(project_id, kwargs):
    with open('./iiidevops/sideex/_setting_sideex.json', "w+") as json_data:
        json_data.write(json.dumps(kwargs))


class SideexJsonfileVariable(Resource):
    @jwt_required()
    @use_kwargs(router_model.SideexGetVariableRes, location="json")
    def post(self, project_id, **kwargs):
        return util.success(get_setting_file(project_id, kwargs['filename']))

    @jwt_required()
    @use_kwargs(router_model.SideexPutVariableRes, location="json")
    def put(self, project_id, **kwargs):
        return util.success(update_config_file(project_id, kwargs))


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
