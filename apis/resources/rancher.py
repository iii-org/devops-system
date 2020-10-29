import ssl

import json
import requests
import websocket
from flask_restful import abort

import config
from .util import util


class Rancher(object):
    headers = {'Content-Type': 'application/json'}

    def __init__(self, logger):
        self.logger = logger
        self.token = 'dummy string to make API returns 401'

    def auth_headers(self, headers, with_token):
        if headers is not None:
            ret = headers.copy()
        else:
            ret = {}
        if with_token:
            ret['Authorization'] = "Bearer {0}".format(self.token)
        return ret

    def api_request(self, method, url, headers, parameter=None, with_token=True, retried=False):
        try:
            final_headers = self.auth_headers(headers, with_token)
            if method.upper() == 'GET':
                response = requests.get(url, headers=final_headers, verify=False)
            elif method.upper() == 'POST':
                response = requests.post(url,
                                         data=json.dumps(parameter),
                                         headers=final_headers,
                                         verify=False)
            else:
                return None

            self.logger.info("api {1} headers is : {0}".format(headers, method))
            self.logger.info("api {1} status code is : {0}".format(
                response.status_code, method))
            if response.status_code == 401 and retried is False:
                self.token = self.generate_token()
                return self.api_request(method, url, headers, parameter, with_token, True)
            return response

        except Exception as e:
            self.logger.error("callgetapi error : {0}".format(e))
            return e

    def api_post(self, url, parameter, headers, with_token=True):
        return self.api_request('POST', url=url, parameter=parameter,
                                headers=headers, with_token=with_token)

    def api_get(self, url, headers=None, with_token=True):
        return self.api_request('GET', url=url, headers=headers, with_token=with_token)

    def generate_token(self):
        url = "https://{0}/{1}-public/localProviders/local?action=login"\
              .format(config.get('RANCHER_IP_PORT'), config.get('RANCHER_API_VERSION'))
        parameter = {
            "username": "{0}".format(config.get('RANCHER_ADMIN_ACCOUNT')),
            "password": "{0}".format(config.get('RANCHER_ADMIN_PASSWORD'))
        }
        output = self.api_post(url, parameter, self.headers)
        return output.json()['token']

    def get_rancher_token(self, app, logger):
        url="https://{0}/{1}-public/localProviders/local?action=login"\
            .format(config.get('RANCHER_IP_PORT'), config.get('RANCHER_API_VERSION'))
        parameter = {
            "username": "{0}".format(config.get('RANCHER_ADMIN_ACCOUNT')),
            "password": "{0}".format(config.get('RANCHER_ADMIN_PASSWORD'))
        }
        output = util.callpostapi(self, url, parameter, logger,
                                  Rancher.headers)
        return output.json()['token']

    def get_rancher_pipelineexecutions(self, ci_project_id, ci_pipeline_id):
        url= "https://{0}/{1}/projects/{2}/pipelineexecutions?order=desc&sort=started&pipelineId={3}".format(
            config.get('RANCHER_IP_PORT'),
            config.get('RANCHER_API_VERSION'),
            ci_project_id,
            ci_pipeline_id)
        self.logger.info("rancher_pipelineexecutions url: {0}".format(url))
        response = self.api_get(url, self.headers)
        output_array = response.json()['data']
        # logger.info ("get_rancher_pipelineexecutions output: {0}".format(output_array))
        return output_array

    def get_rancher_pipelineexecutions_logs(self, ci_project_id, ci_pipeline_id,
        pipelines_exec_run):
        output_dict = []
        headersandtoken = "Authorization: Bearer {0}".format(self.token)
        pipelineexecutions_output = self.get_rancher_pipelineexecutions(
            ci_project_id, ci_pipeline_id)
        for pipelineexecution_output in pipelineexecutions_output:
            if pipelines_exec_run == pipelineexecution_output['run']:
                for index, stage in enumerate(
                        pipelineexecution_output['pipelineConfig']['stages']):
                    tmp_step_message = []
                    for stepindex, step in enumerate(stage['steps']):
                        ws = websocket.WebSocket(
                            sslopt={"cert_reqs": ssl.CERT_NONE})
                        url = "wss://{0}/{1}/project/{2}/pipelineExecutions/{3}-{4}/log?stage={5}&step={6}"\
                            .format(config.get('RANCHER_IP_PORT'), config.get('RANCHER_API_VERSION'), \
                                    ci_project_id, ci_pipeline_id, pipelines_exec_run, index, stepindex)
                        self.logger.info("wss url: {0}".format(url))
                        ws.connect(url, header=[headersandtoken])
                        result = ws.recv()
                        # logger.info("Received :'%s'" % result)
                        step_datail = pipelineexecution_output['stages'][
                            index]['steps'][stepindex]
                        if 'state' in step_datail:
                            tmp_step_message.append({
                                "state": step_datail['state'],
                                "message": result
                            })
                        else:
                            tmp_step_message.append({
                                "state": None,
                                "message": result
                            })
                        ws.close()
                    stage_state = pipelineexecution_output['stages'][index]
                    if 'state' in stage_state:
                        output_dict.append({
                            "name": stage['name'],
                            "state": stage_state['state'],
                            "steps": tmp_step_message
                        })
                    else:
                        output_dict.append({
                            "name": stage['name'],
                            "state": None,
                            "steps": tmp_step_message
                        })
        self.logger.debug("output_dict: {0}".format(output_dict))
        return output_dict[1:]

    def get_rancher_cluster_id(self, app, logger, rancher_token):
        url= "https://{0}/{1}/clusters".format(\
            config.get('RANCHER_IP_PORT'), config.get('RANCHER_API_VERSION'))
        logger.info("get_rancher_cluster_id url: {0}".format(url))
        headersandtoken = Rancher.headers
        headersandtoken['Authorization'] = "Bearer {0}".format(rancher_token)
        rancher_output = util.callgetapi(self, url, logger,
                                                    headersandtoken)
        output_array = rancher_output.json()['data']
        for output in output_array:
            logger.debug("get_rancher_cluster output: {0}".format(output['name']))
            if output['name'] == config.get('RANCHER_CLUSTER_NAME'):
                return output['id']

    def get_rancher_project_id(self, app, logger, rancher_token):
        cluster_id = Rancher.get_rancher_cluster_id(self, app, logger, rancher_token)
        logger.debug("get rancher cluster_id: {0}".format(cluster_id))
        url= "https://{0}/{1}/clusters/{2}/projects".format(\
            config.get('RANCHER_IP_PORT'), config.get('RANCHER_API_VERSION'), cluster_id)
        logger.info("get_rancher_project_id url: {0}".format(url))
        headersandtoken = Rancher.headers
        headersandtoken['Authorization'] = "Bearer {0}".format(rancher_token)
        rancher_output = util.callgetapi(self, url, logger,
                                                    headersandtoken)
        output_array = rancher_output.json()['data']
        for output in output_array:
            if output['name'] == "Default":
                return output['id']

    def get_rancher_admin_user_id(self, app, logger, rancher_token):
        url= "https://{0}/{1}/users".format(\
            config.get('RANCHER_IP_PORT'), config.get('RANCHER_API_VERSION'))
        logger.info("get_rancher_admin_user_id url: {0}".format(url))
        headersandtoken = Rancher.headers
        headersandtoken['Authorization'] = "Bearer {0}".format(rancher_token)
        rancher_output = util.callgetapi(self, url, logger,
                                                    headersandtoken)
        output_array = rancher_output.json()['data']
        for output in output_array:
            if output['username'] == 'admin':
                return output['id']

    def enable_rancher_projejct_pipline(self, app, logger, repository_url, rancher_token):
        project_id = Rancher.get_rancher_project_id(self, app, logger, rancher_token)
        pipeline_list = Rancher.get_rancher_projejct_pipline(self, app, logger, repository_url, rancher_token)
        for pipline in pipeline_list:
            if pipline['repositoryUrl'] == repository_url:
                logger.info("repository_url {0} rancher pipeline already enable".format(repository_url))
                abort(400, message='rancher pipline already enable this repository {0}'.format(repository_url))
        user_id = Rancher.get_rancher_admin_user_id(self, app, logger, rancher_token)
        url="https://{0}/{1}/projects/{2}/pipelines"\
            .format(config.get('RANCHER_IP_PORT'), config.get('RANCHER_API_VERSION'), project_id)
        headersandtoken = Rancher.headers
        headersandtoken['Authorization'] = "Bearer {0}".format(rancher_token)
        parameter = {
            "type": "pipeline",
            "sourceCodeCredentialId": "{0}:{1}-gitlab-root".format(user_id, project_id.split(':')[1]),
            "repositoryUrl": repository_url,
            "triggerWebhookPr": False,
            "triggerWebhookPush": True,
            "triggerWebhookTag": False
        }
        output = util.callpostapi(self, url, parameter, logger,
                                headersandtoken)
        logger.debug("enable_rancher_projejct_pipline output: {0}".format(output.json()))
        return output.json()['id']

    def disable_rancher_projejct_pipline(self, app, logger, project_id, pipeline_id, rancher_token):
        url="https://{0}/{1}/projects/{2}/pipelines/{3}"\
            .format(config.get('RANCHER_IP_PORT'), config.get('RANCHER_API_VERSION'), project_id,
                    pipeline_id)
        headersandtoken = Rancher.headers
        headersandtoken['Authorization'] = "Bearer {0}".format(rancher_token)
        rancher_output = util.calldeleteapi(self, url, logger,
                                                    headersandtoken)
        if rancher_output.status_code == 200:
            logger.info("disable_rancher_projejct_pipline successful !")
        elif rancher_output.status_code == 404:
            logger.info("project does not exist, don't need to delete.")
        else:
            logger.info("disable_rancher_projejct_pipline error, error message: {0}".format(rancher_output.text))
            abort(400, message='"disable_rancher_projejct_pipline error, error message: {0}'.format(rancher_output.text))

    def get_rancher_projejct_pipline(self, app, logger, repository_url, rancher_token):
        project_id = Rancher.get_rancher_project_id(self, app, logger, rancher_token)
        url="https://{0}/{1}/projects/{2}/pipelines"\
            .format(config.get('RANCHER_IP_PORT'), config.get('RANCHER_API_VERSION'), project_id)
        headersandtoken = Rancher.headers
        headersandtoken['Authorization'] = "Bearer {0}".format(rancher_token)
        output = util.callgetapi(self, url, logger, headersandtoken)
        logger.debug("enable_rancher_projejct_pipline output: {0}".format(output.json()))
        return output.json()['data']