import logging

import yaml
import json
import base64
import os

import config
from model import db
import resources.apiError as apiError
from .rancher import Rancher
import resources.util as util

logger = logging.getLogger(config.get('LOGGER_NAME'))


class Pipeline(object):
    headers = {'Content-Type': 'application/json'}

    def __init__(self, app, pjt):
        self.app = app
        self.pjt = pjt
        self.rancher = Rancher()

    def pipeline_exec_list(self, repository_id):
        output_array = []
        result = db.engine.execute(
            "SELECT * FROM public.project_plugin_relation \
            WHERE git_repository_id = {0};".format(repository_id))
        if result.rowcount == 0:
            return util.respond(404, 'No such project',
                                error=apiError.repository_id_not_found(repository_id))
        project_relationship = result.fetchone()
        result.close()
        pipeline_outputs, response = self.rancher.rc_get_pipeline_executions(
            project_relationship['ci_project_id'],
            project_relationship['ci_pipeline_id'])
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
            output_dict['commit_id'] = pipeline_output['commit']
            stage_status = []
            for stage in pipeline_output['stages']:
                logger.info("stage: {0}".format(stage))
                if 'state' in stage:
                    stage_status.append(stage['state'])
            if 'Failed' in stage_status:
                failed_item = stage_status.index('Failed')
                logger.info("failed_item: {0}".format(failed_item))
                output_dict['status'] = {'total': len(pipeline_output['stages']),
                                         'success': failed_item}
            else:
                output_dict['status'] = {'total': len(pipeline_output['stages']),
                                         'success': len(pipeline_output['stages'])}
            output_array.append(output_dict)
        logger.info("ci/cd output: {0}".format(output_array))
        return output_array

    def pipeline_exec_logs(self, args):
        result = db.engine.execute(
            "SELECT * FROM public.project_plugin_relation \
            WHERE git_repository_id = {0};".format(args['repository_id']))
        project_relationship = result.fetchone()
        result.close()
        try:
            output_array, response = self.rancher.rc_get_pipeline_executions_logs(
                project_relationship['ci_project_id'],
                project_relationship['ci_pipeline_id'],
                args['pipelines_exec_run'])
            if response.status_code / 100 != 2:
                return util.respond(400, "get pipeline history error",
                                    error=apiError.rancher_error(response))
            return {"message": "success", "data": output_array}, 200
        except Exception as e:
            return util.respond(500, "get pipeline history error",
                                error=apiError.uncaught_exception(e))

    def pipeline_software(self):
        result = db.engine.execute(
            "SELECT pp.name as phase_name, ps.name as software_name, "
            "psc.detail as detail FROM public.pipeline_phase as pp, "
            "public.pipeline_software as ps, public.pipeline_software_config as psc "
            "WHERE psc.software_id = ps.id AND ps.phase_id = pp.id AND psc.sample = true;"
        )
        pipe_softs = result.fetchall()
        result.close()
        return [dict(row) for row in pipe_softs]

    def generate_ci_yaml(self, args, repository_id, branch_name):
        '''
        result = db.engine.execute("SELECT git_repository_id FROM public.project_plugin_relation \
            WHERE project_id = {0};".format(project_id))
        project_relationship = result.fetchone()
        result.close()
        logger.info("project_relationship: {0}".format(project_relationship['ci_project_id']))
        '''
        parameter = {}
        logger.debug("generate_ci_yaml detail: {0}".format(args['detail']))
        dict_object = json.loads(args['detail'].replace("'", '"'))
        docum = yaml.dump(dict_object)
        logger.info("generate_ci_yaml documents: {0}".format(docum))
        base_file = base64.b64encode(bytes(docum,
                                           encoding='utf-8')).decode('utf-8')
        logger.info("generate_ci_yaml base_file: {0}".format(base_file))
        parameter['file_path'] = '.rancher-pipeline.yml'
        parameter['branch'] = branch_name
        parameter['start_branch'] = branch_name
        parameter['encoding'] = 'base64'
        parameter['content'] = base_file
        parameter['author_email'] = "admin@example.com"
        parameter['author_name'] = "admin"
        parameter['file_path'] = '.rancher-pipeline.yaml'
        yaml_info = self.pjt.get_git_project_file_for_pipeline(repository_id, parameter)
        parameter['file_path'] = '.rancher-pipeline.yml'
        yml_info = self.pjt.get_git_project_file_for_pipeline(repository_id, parameter)
        if yaml_info.status_code == 404 and yml_info.status_code == 404:
            action = "post"
            parameter['commit_message'] = "add .rancher-pipeline.yml"
        else:
            action = "put"
            parameter['commit_message'] = "modify .rancher-pipeline.yml"
        self.pjt.create_ranhcer_pipline_yaml(repository_id, parameter, action)
        return {"message": "success"}, 200

    def get_ci_yaml(self, repository_id, branch_name):
        parameter = {'branch': branch_name, 'file_path': '.rancher-pipeline.yaml'}
        yaml_info = self.pjt.get_git_project_file_for_pipeline(repository_id, parameter)
        parameter['file_path'] = '.rancher-pipeline.yml'
        yml_info = self.pjt.get_git_project_file_for_pipeline(repository_id, parameter)
        get_yaml_data = None
        if yaml_info.status_code != 404:
            get_yaml_data = yaml_info.json()
        elif yml_info.status_code != 404:
            get_yaml_data = yml_info.json()
        if get_yaml_data is None:
            return {'message': "success", "data": {}}, 200
        rancher_ci_yaml = base64.b64decode(
            get_yaml_data['content']).decode("utf-8")
        rancher_ci_json = yaml.safe_load(rancher_ci_yaml)
        return {"message": "success", "data": rancher_ci_json}, 200

    def get_phase_yaml(self, repository_id, branch_name):
        parameter = {'branch': branch_name, 'file_path': '.rancher-pipeline.yaml'}
        try:
            yaml_info = self.pjt.get_git_project_file_for_pipeline(repository_id, parameter)
            parameter['file_path'] = '.rancher-pipeline.yml'
            yml_info = self.pjt.get_git_project_file_for_pipeline(repository_id, parameter)
        except Exception:
            return {
                       "message": "read yaml to get phase and software name error"
                   }, 400
        get_yaml_data = None
        if yaml_info.status_code != 404:
            get_yaml_data = yaml_info.json()
        elif yml_info.status_code != 404:
            get_yaml_data = yml_info.json()
        if get_yaml_data is None:
            return {'message': "success", "data": []}, 200
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
