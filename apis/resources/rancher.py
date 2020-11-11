import logging
import ssl

import websocket
from flask_restful import abort

import config
import resources.apiError as apiError
import resources.util as util

logger = logging.getLogger(config.get('LOGGER_NAME'))


class Rancher(object):
    def __init__(self):
        self.token = 'dummy string to make API returns 401'

    def __api_request(self, method, path, headers, params=None, data=None,
                      with_token=True, retried=False):
        url = 'https://{0}/{1}{2}'.format(
            config.get('RANCHER_IP_PORT'),
            config.get('RANCHER_API_VERSION'),
            path)
        if headers is None:
            headers = {'Content-Type': 'application/json'}
        final_headers = self.__auth_headers(headers, with_token)

        try:
            response = util.api_request(method, url, headers=final_headers, params=params, data=data)
            if response.status_code == 401 and not retried:
                self.token = self.__generate_token()
                return self.__api_request(method, path, headers=headers, params=params, data=data,
                                          with_token=True, retried=True)
            logger.info('Rancher api {0} {1}, params={2}, body={5}, response={3} {4}'.format(
                method, url, params.__str__(), response.status_code, response.text, data))
            return response
        except Exception as e:
            return util.respond_request_style(500, "Error in rancher API request {0} {1}".format(
                method, url
            ), error=apiError.uncaught_exception(e))

    def __auth_headers(self, headers, with_token):
        if headers is not None:
            ret = headers.copy()
        else:
            ret = {}
        if with_token:
            ret['Authorization'] = "Bearer {0}".format(self.token)
        return ret

    def __api_get(self, path, params=None, headers=None, with_token=True):
        return self.__api_request('GET', path=path, params=params,
                                  headers=headers, with_token=with_token)

    def __api_post(self, path, params=None, headers=None, data=None, with_token=True):
        return self.__api_request('POST', path=path, params=params, data=data,
                                  headers=headers, with_token=with_token)

    def __api_delete(self, path, params=None, headers=None, with_token=True):
        return self.__api_request('DELETE', path=path, params=params,
                                  headers=headers, with_token=with_token)

    def __generate_token(self):
        body = {
            "username": config.get('RANCHER_ADMIN_ACCOUNT'),
            "password": config.get('RANCHER_ADMIN_PASSWORD')
        }
        params = {'action': 'login'}
        output = self.__api_post('-public/localProviders/local', params=params,
                                              data=body, with_token=False)
        return output.json()['token']

    def rc_get_pipeline_executions(self, ci_project_id, ci_pipeline_id):
        path = '/projects/{0}/pipelineexecutions'.format(ci_project_id)
        params = {
            'order': 'desc',
            'sort': 'started',
            'pipelineId': ci_pipeline_id
        }
        response, status_code = self.__api_get(path, params=params)
        output_array = response.json()['data']
        return output_array, response

    def rc_get_pipeline_executions_logs(self, ci_project_id, ci_pipeline_id,
                                        pipelines_exec_run):
        output_dict = []
        output_executions, response = self.rc_get_pipeline_executions(
            ci_project_id, ci_pipeline_id)
        for output_execution in output_executions:
            if pipelines_exec_run == output_execution['run']:
                for index, stage in enumerate(
                        output_execution['pipelineConfig']['stages']):
                    tmp_step_message = []
                    for step_index, step in enumerate(stage['steps']):
                        ws = websocket.WebSocket(
                            sslopt={"cert_reqs": ssl.CERT_NONE})
                        url = ("wss://{0}/{1}/project/{2}/pipelineExecutions/"
                               "{3}-{4}/log?stage={5}&step={6}").format(
                            config.get('RANCHER_IP_PORT'), config.get('RANCHER_API_VERSION'), ci_project_id,
                            ci_pipeline_id, pipelines_exec_run, index, step_index)
                        logger.info("wss url: {0}".format(url))
                        ws.connect(url, header=["Authorization: Bearer {0}".format(self.token)])
                        result = ws.recv()
                        # logger.info("Received :'%s'" % result)
                        step_detail = output_execution['stages'][
                            index]['steps'][step_index]
                        if 'state' in step_detail:
                            tmp_step_message.append({
                                "state": step_detail['state'],
                                "message": result
                            })
                        else:
                            tmp_step_message.append({
                                "state": None,
                                "message": result
                            })
                        ws.close()
                    stage_state = output_execution['stages'][index]
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
        return output_dict[1:], response

    def rc_get_cluster_id(self):
        rancher_output = self.__api_get('/clusters')
        output_array = rancher_output.json()['data']
        for output in output_array:
            logger.debug("get_rancher_cluster output: {0}".format(output['name']))
            if output['name'] == config.get('RANCHER_CLUSTER_NAME'):
                return output['id']

    def rc_get_project_id(self):
        cluster_id = self.rc_get_cluster_id()
        rancher_output = self.__api_get('/clusters/{0}/projects'.format(cluster_id))
        output_array = rancher_output.json()['data']
        for output in output_array:
            if output['name'] == "Default":
                return output['id']

    def rc_get_admin_user_id(self):
        rancher_output = self.__api_get('/users')
        output_array = rancher_output.json()['data']
        for output in output_array:
            if output['username'] == 'admin':
                return output['id']

    def rc_enable_project_pipeline(self, repository_url):
        project_id = self.rc_get_project_id()
        pipeline_list = self.rc_get_project_pipeline()
        for pipeline in pipeline_list:
            if pipeline['repositoryUrl'] == repository_url:
                logger.info("repository_url {0} rancher pipeline already enable".format(repository_url))
                abort(400, message='rancher pipeline already enable this repository {0}'.format(repository_url))
        user_id = self.rc_get_admin_user_id()
        parameter = {
            "type": "pipeline",
            "sourceCodeCredentialId": "{0}:{1}-gitlab-root".format(user_id, project_id.split(':')[1]),
            "repositoryUrl": repository_url,
            "triggerWebhookPr": True,
            "triggerWebhookPush": True,
            "triggerWebhookTag": True
        }
        output = self.__api_post(
            '/projects/{0}/pipelines'.format(project_id), data=parameter)
        logger.debug("enable_rancher_project_pipeline output: {0}".format(output.json()))
        return output.json()['id']

    def rc_disable_project_pipeline(self, project_id, pipeline_id):
        rancher_output = self.__api_delete('/projects/{0}/pipelines/{1}'.format(
            project_id, pipeline_id
        ))
        status_code = rancher_output.status_code
        if status_code == 200:
            logger.info("disable_rancher_project_pipeline successful !")
        elif status_code == 404:
            logger.info("project does not exist, don't need to delete.")
        else:
            logger.info("disable_rancher_project_pipeline error, error message: {0}".format(rancher_output.text))
            abort(400,
                  message='"disable_rancher_project_pipeline error, error message: {0}'.format(rancher_output.text))

    def rc_get_project_pipeline(self):
        project_id = self.rc_get_project_id()
        output = self.__api_get('/projects/{0}/pipelines'.format(project_id))
        return output.json()['data']
