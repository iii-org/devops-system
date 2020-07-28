import yaml
import json
import base64
import os

from model import db
from .rancher import Rancher
from .project import Project

class Pipeline(object):
    headers = {'Content-Type': 'application/json'}
    
    def pipeline_info(self, logger, project_id):
        result = db.engine.execute("SELECT id, name, close_at FROM public.ci_cd as ci WHERE ci.project_id = {0} \
            ORDER BY ci.id DESC".format(project_id))
        ci_cd_list = result.fetchone()
        result.close()
        logger.info("get_project_list: ci_cd_list {0}".format(ci_cd_list))
        if ci_cd_list is not None:
            is_closed = True
            if ci_cd_list["close_at"] is None:
                is_closed = False
            output = {"id": project_id, "pipeline_info": [{"id": ci_cd_list["id"], "name": ci_cd_list["name"], "is_closed": is_closed}]}
            logger.info("pipeline_info output: {0}".format(output))
        else:
            output = None
        return output

    def pipeline_exec_list(self, logger, app, repository_id):
        output_array = []
        result = db.engine.execute("SELECT * FROM public.project_plugin_relation \
            WHERE git_repository_Id = {0};".format(repository_id))
        project_relationship = result.fetchone()
        result.close()
        logger.info("project_relationship: {0}".format(project_relationship['ci_project_id']))
        rancher_token = Rancher.get_rancher_token(self, app, logger)
        pipeline_outputs = Rancher.get_rancher_pipelineexecutions(self, app, logger, project_relationship['ci_project_id'], \
        project_relationship['ci_pipeline_id'], rancher_token)
        for pipeline_output in pipeline_outputs:
            output_dict = {}
            output_dict['id'] = pipeline_output['run']
            output_dict['last_test_time'] = pipeline_output['created']
            output_dict['commit_message'] = pipeline_output['message']
            output_dict['commit_branch'] = pipeline_output['branch']
            stage_status = []
            # logger.info(pipeline_output[0]['stages'])
            for stage in pipeline_output['stages']:
                logger.info("stage: {0}".format(stage))
                if 'state' in stage:
                    stage_status.append(stage['state'])
            logger.info(stage_status)
            failed_item = -1
            if 'Failed' in stage_status:
                failed_item = stage_status.index('Failed')
                logger.info("failed_item: {0}".format(failed_item))
                output_dict['status']={'total': len(pipeline_output['stages']),\
                    'success': failed_item }
            else:
                output_dict['status']={'total': len(pipeline_output['stages']),\
                    'success': len(pipeline_output['stages'])}
            output_array.append(output_dict)
        logger.info("ci/cd output: {0}".format(output_array))
        return output_array

    def pipeline_exec_logs(self, logger, app, args):
        result = db.engine.execute("SELECT * FROM public.project_plugin_relation \
            WHERE project_id = {0};".format(args['project_id']))
        project_relationship = result.fetchone()
        result.close()
        rancher_token = Rancher.get_rancher_token(self, app, logger)
        output_array = pipeline_outputs = Rancher.get_rancher_pipelineexecutions_logs(self, app, logger, \
            project_relationship['ci_project_id'], project_relationship['ci_pipeline_id'], 
            args['pipelines_exec_run'], rancher_token)
        return output_array

    def pipeline_software(self, logger):
        result = db.engine.execute("SELECT pp.name as phase_name, ps.name as software_name, \
            psc.detail as detail FROM public.pipeline_phase as pp, \
            public.pipeline_software as ps, public.pipeline_software_config as psc \
            WHERE psc.software_id = ps.id AND ps.phase_id = pp.id AND psc.sample = true;")
        pipe_softs = result.fetchall()
        result.close()
        return [dict(row) for row in pipe_softs]
        # message = os.popen('ls -al ../../../')
        # logger.info("message: {0}".format(message.read()))
        '''
        with open(r'../../../.rancher-pipeline.yml') as file:
            document = yaml.load(file, Loader=yaml.FullLoader)
        logger.info("document: {0}".format(document))
        document['stage']
        '''
        # Rancher.gererate_pipeline_ci_yml(self)

    
    def generate_ci_yaml(self, logger, args, app, repository_id, branch_name):
        '''
        result = db.engine.execute("SELECT git_repository_id FROM public.project_plugin_relation \
            WHERE project_id = {0};".format(project_id))
        project_relationship = result.fetchone()
        result.close()
        logger.info("project_relationship: {0}".format(project_relationship['ci_project_id']))
        '''
        parameter = {}
        dict_object = json.loads(args['detail'].replace("'",'"'))
        docum = yaml.dump(dict_object)
        logger.info("generate_ci_yaml documents: {0}".format(docum))
        base_file = base64.b64encode(bytes(docum, encoding= 'utf-8')).decode('utf-8')
        logger.info("generate_ci_yaml base_file: {0}".format(base_file))
        parameter['file_path'] = '.rancher-pipeline.yml'
        parameter['branch'] = branch_name
        parameter['start_branch'] = branch_name
        parameter['encoding'] = 'base64'
        parameter['content'] = base_file
        parameter['author_email'] = "admin@example.com"
        parameter['author_name'] = "admin"
        parameter['file_path'] = '.rancher-pipeline.yaml'
        yaml_info = Project.get_git_project_file(self, logger, app, repository_id, parameter)
        parameter['file_path'] = '.rancher-pipeline.yml'
        yml_info = Project.get_git_project_file(self, logger, app, repository_id, parameter)
        if yaml_info.status_code == 404 and yml_info.status_code == 404:
            action = "post"
            parameter['commit_message'] = "add .rancher-pipeline.yml"
        else:
            action = "put"
            parameter['commit_message'] = "modify .rancher-pipeline.yml"
        Project.create_ranhcer_pipline_yaml(self, logger, app, repository_id, parameter, action)
    
    def get_ci_yaml(self, logger, app, repository_id, branch_name):
        parameter={}
        parameter['branch'] = branch_name
        parameter['file_path'] = '.rancher-pipeline.yaml'
        yaml_info = Project.get_git_project_file(self, logger, app, repository_id, parameter)
        parameter['file_path'] = '.rancher-pipeline.yml'
        yml_info = Project.get_git_project_file(self, logger, app, repository_id, parameter)
        get_yaml_data = None
        if yaml_info.status_code != 404:
            get_yaml_data = yaml_info.json()
        elif yml_info.status_code != 404:
            get_yaml_data = yml_info.json()
        logger.info('get_yaml_data: {0}'.format(get_yaml_data['content']))
        rancher_ci_yaml = base64.b64decode(get_yaml_data['content']).decode("utf-8") 
        logger.info('rancher_ci_yaml: {0}'.format(rancher_ci_yaml))
        rancher_ci_json = yaml.load(rancher_ci_yaml)
        logger.info('rancher_ci_json: {0}'.format(rancher_ci_json))
        return rancher_ci_json