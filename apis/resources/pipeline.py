import base64
import json

import yaml
from flask_jwt_extended import jwt_required
from flask_restful import Resource, reqparse
from sqlalchemy.orm.exc import NoResultFound
from flask_socketio import Namespace, emit

import model
import resources.apiError as apiError
import util as util
from model import db, PipelineLogsCache
from resources.logger import logger
from .gitlab import GitLab, commit_id_to_url
from .rancher import rancher

gitlab = GitLab()


def pipeline_exec_list(repository_id):
    output_array = []
    try:
        relation = model.ProjectPluginRelation.query.filter_by(
            git_repository_id=repository_id).one()
    except NoResultFound:
        raise apiError.DevOpsError(404, 'No such project',
                                   error=apiError.repository_id_not_found(repository_id))
    pipeline_outputs = rancher.rc_get_pipeline_executions(
        relation.ci_project_id,
        relation.ci_pipeline_id)
    for pipeline_output in pipeline_outputs:
        output_dict = {
            'id': pipeline_output['run'],
            'last_test_time': pipeline_output['created']
        }
        if 'message' in pipeline_output:
            output_dict['commit_message'] = pipeline_output['message']
        else:
            output_dict['commit_message'] = None
        output_dict['commit_branch'] = pipeline_output['branch']
        output_dict['commit_id'] = pipeline_output['commit'][0:7]
        output_dict['commit_url'] = commit_id_to_url(relation.project_id,
                                                     pipeline_output['commit'])
        output_dict['execution_state'] = pipeline_output['executionState']
        output_dict['transitioning_message'] = pipeline_output['transitioningMessage']
        stage_status = []
        for stage in pipeline_output['stages']:
            logger.info("stage: {0}".format(stage))
            if 'state' in stage:
                stage_status.append(stage['state'])
        success_time = stage_status.count('Success')
        output_dict['status'] = {'total': len(pipeline_output['stages']),
                                 'success': success_time}
        output_array.append(output_dict)
    logger.info("ci/cd output: {0}".format(output_array))
    return output_array

def pipeline_config(repository_id, args):
    try:
        relation = model.ProjectPluginRelation.query.filter_by(
            git_repository_id=repository_id).one()
    except NoResultFound:
        raise apiError.DevOpsError(
            404, 'No such project.',
            error=apiError.repository_id_not_found(repository_id))
    return rancher.rc_get_pipeline_config(relation.ci_pipeline_id, args['pipelines_exec_run'])

def pipeline_exec_logs(args):
    try:
        relation = model.ProjectPluginRelation.query.filter_by(
            git_repository_id=args['repository_id']).one()
    except NoResultFound:
        raise apiError.DevOpsError(
            404, 'No such project.',
            error=apiError.repository_id_not_found(args['repository_id']))

    # search PipelineLogsCache table log
    log_cache = PipelineLogsCache.query.filter(PipelineLogsCache.project_id == relation.project_id,
                                               PipelineLogsCache.ci_pipeline_id == relation.ci_pipeline_id,
                                               PipelineLogsCache.run == args['pipelines_exec_run']).first()
    if log_cache is None:
        output_array, execution_state = rancher.rc_get_pipeline_executions_logs(
            relation.ci_project_id,
            relation.ci_pipeline_id,
            args['pipelines_exec_run'])

        # if execution status is Failed, Success, Aborted, log will insert into ipelineLogsCache table 
        if execution_state in ['Failed', 'Success', 'Aborted']:
            log = PipelineLogsCache(project_id=relation.project_id,
                                    ci_pipeline_id=relation.ci_pipeline_id,
                                    run=args['pipelines_exec_run'],
                                    logs=output_array)
            db.session.add(log)
            db.session.commit()
        return util.success(output_array)
    else:
        return util.success(log_cache.logs)

def pipeline_websocket_logs():
    pass
    #emit('my response', {'data': data['data']}, broadcast=True)

def pipeline_exec_action(git_repository_id, args):
    try:
        relation = model.ProjectPluginRelation.query.filter_by(
            git_repository_id=git_repository_id).one()
    except NoResultFound:
        raise apiError.DevOpsError(
            404, 'No such project.',
            error=apiError.repository_id_not_found(git_repository_id))

    response = rancher.rc_get_pipeline_executions_action(
        relation.ci_project_id,
        relation.ci_pipeline_id,
        args['pipelines_exec_run'],
        args['action'])
    return util.success()


def pipeline_software():
    result = db.engine.execute(
        "SELECT pp.name as phase_name, ps.name as software_name, "
        "psc.detail as detail FROM public.pipeline_phase as pp, "
        "public.pipeline_software as ps, public.pipeline_software_config as psc "
        "WHERE psc.software_id = ps.id AND ps.phase_id = pp.id AND psc.sample = true;"
    )
    pipe_software = result.fetchall()
    result.close()
    return [dict(row) for row in pipe_software]


def generate_ci_yaml(args, repository_id, branch_name):
    parameter = {}
    logger.debug("generate_ci_yaml detail: {0}".format(args['detail']))
    dict_object = json.loads(args['detail'].replace("'", '"'))
    doc = yaml.dump(dict_object)
    logger.info("generate_ci_yaml documents: {0}".format(doc))
    base_file = base64.b64encode(bytes(doc,
                                       encoding='utf-8')).decode('utf-8')
    logger.info("generate_ci_yaml base_file: {0}".format(base_file))
    parameter['branch'] = branch_name
    parameter['start_branch'] = branch_name
    parameter['encoding'] = 'base64'
    parameter['content'] = base_file
    parameter['author_email'] = "admin@example.com"
    parameter['author_name'] = "admin"
    yaml_file_can_not_find, yml_file_can_not_find, get_yaml_data = \
        _get_rancher_pipeline_yaml(repository_id, parameter)
    if yaml_file_can_not_find and yml_file_can_not_find:
        method = "post"
        parameter['commit_message'] = "add .rancher-pipeline"
    elif yaml_file_can_not_find or yml_file_can_not_find:
        method = "put"
        parameter['commit_message'] = "modify .rancher-pipeline"
    else:
        raise apiError.DevOpsError(400, 'Has both .yaml and .yml files')
    gitlab.gl_create_rancher_pipeline_yaml(repository_id, parameter, method)
    return util.success()


def get_ci_yaml(repository_id, branch_name):
    parameter = {'branch': branch_name}
    yaml_file_can_not_find, yml_file_can_not_find, get_yaml_data = \
        _get_rancher_pipeline_yaml(repository_id, parameter)
    if yaml_file_can_not_find and yml_file_can_not_find:
        return util.respond(204)
    rancher_ci_yaml = base64.b64decode(
        get_yaml_data['content']).decode("utf-8")
    rancher_ci_json = yaml.safe_load(rancher_ci_yaml)
    return {"message": "success", "data": rancher_ci_json}, 200


def get_phase_yaml(repository_id, branch_name):
    parameter = {'branch': branch_name}
    yaml_file_can_not_find, yml_file_can_not_find, get_yaml_data = \
        _get_rancher_pipeline_yaml(repository_id, parameter)
    if yaml_file_can_not_find and yml_file_can_not_find:
        return util.respond(204)

    rancher_ci_yaml = base64.b64decode(
        get_yaml_data['content']).decode("utf-8")
    rancher_ci_json = yaml.safe_load(rancher_ci_yaml)
    phase_name_array = []
    phase_name = None
    for index, rancher_stage in enumerate(rancher_ci_json['stages']):
        if "--" in rancher_stage['name']:
            cut_list = rancher_stage['name'].split('--')
            phase_name = cut_list[0]
            soft_name = cut_list[1]
        else:
            soft_name = rancher_stage['name']
        phase_name_array.append({
            'id': index + 1,
            'phase': phase_name,
            'software': soft_name
        })
    return {'message': "success", "data": phase_name_array}, 200


def _get_rancher_pipeline_yaml(repository_id, parameter):
    yaml_file_can_not_find = None
    yml_file_can_not_find = None
    get_yaml_data = None
    get_file_param = dict(parameter)
    try:
        get_file_param['file_path'] = '.rancher-pipeline.yaml'
        get_yaml_data = gitlab.gl_get_project_file_for_pipeline(repository_id, get_file_param).json()
        parameter['file_path'] = '.rancher-pipeline.yaml'
    except apiError.DevOpsError as e:
        if e.status_code == 404:
            yaml_file_can_not_find = True
    try:
        get_file_param['file_path'] = '.rancher-pipeline.yml'
        get_yaml_data = gitlab.gl_get_project_file_for_pipeline(repository_id, get_file_param).json()
        parameter['file_path'] = '.rancher-pipeline.yml'
    except apiError.DevOpsError as e:
        if e.status_code == 404:
            yml_file_can_not_find = True
    return yaml_file_can_not_find, yml_file_can_not_find, get_yaml_data


# --------------------- Resources ---------------------
class PipelineExec(Resource):
    @jwt_required
    def get(self, repository_id):
        output_array = pipeline_exec_list(repository_id)
        return util.success(output_array)


class PipelineExecAction(Resource):
    @jwt_required
    def post(self, repository_id):
        parser = reqparse.RequestParser()
        parser.add_argument('pipelines_exec_run', type=int, required=True)
        parser.add_argument('action', type=str, required=True)
        args = parser.parse_args()
        return pipeline_exec_action(repository_id, args)


class PipelineExecLogs(Resource):
    @jwt_required
    def get(self):
        parser = reqparse.RequestParser()
        parser.add_argument('repository_id', type=int, required=True)
        parser.add_argument('pipelines_exec_run', type=int, required=True)
        args = parser.parse_args()
        return pipeline_exec_logs(args)


class PipelineSoftware(Resource):
    @jwt_required
    def get(self):
        pipe_out_list = pipeline_software()
        output_list = []
        for pipe_out in pipe_out_list:
            if 'detail' in pipe_out:
                pipe_out['detail'] = json.loads(pipe_out['detail'].replace(
                    "'", '"'))
            output_list.append(pipe_out)
        return util.success(output_list)


class PipelineYaml(Resource):
    @jwt_required
    def get(self, repository_id, branch_name):
        return get_ci_yaml(repository_id, branch_name)

    @jwt_required
    def post(self, repository_id, branch_name):
        parser = reqparse.RequestParser()
        parser.add_argument('detail')
        args = parser.parse_args()
        return generate_ci_yaml(args, repository_id, branch_name)


class PipelinePhaseYaml(Resource):
    @jwt_required
    def get(self, repository_id, branch_name):
        return get_phase_yaml(repository_id, branch_name)


class PipelineConfig(Resource):
    @jwt_required
    def get(self, repository_id):
        parser = reqparse.RequestParser()
        parser.add_argument('pipelines_exec_run', type=int, required=True)
        args = parser.parse_args()
        return pipeline_config(repository_id, args)


class Pipelinelog(Namespace):
    def on_connect(self):
        print('connect')

    def on_disconnect(self):
        print('Client disconnected')

    def on_my_event(self, data):
        print('my broadcast event')
        pipeline_websocket_logs()
