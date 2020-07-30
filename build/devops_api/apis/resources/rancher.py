import websocket
import ssl

from .util import util

class Rancher(object):

    redmine_key = None
    headers = {'Content-Type': 'application/json'}

    def __init__(self):
        pass
        
    def get_rancher_token(self, app, logger):
        url="https://{0}/{1}-public/localProviders/local?action=login"\
            .format(app.config['RANCHER_IP_PORT'], app.config['RANCHER_API_VERSION'])
        parameter ={
            "username":"{0}".format(app.config['RANCHER_ADMIN_ACCOUNT']),
            "password":"{0}".format(app.config['RANCHER_ADMIN_PASSWORD'])
        }
        output = util.callpostapi(self, url, parameter, logger, Rancher.headers)
        return output.json()['token']
    
    def get_rancher_pipelineexecutions(self, app, logger, ci_project_id, ci_pipeline_id,\
        rancher_token):
        url= "https://{0}/{1}/projects/{2}/pipelineexecutions?order=desc&pipelineId={3}".format(\
            app.config['RANCHER_IP_PORT'], app.config['RANCHER_API_VERSION'], ci_project_id,\
            ci_pipeline_id)
        logger.info("rancher_pipelineexecutions url: {0}".format(url))
        headersandtoken = Rancher.headers
        headersandtoken['Authorization']= "Bearer {0}".format(rancher_token)
        pipelineexecutions_output = util.callgetapi(self, url, logger, headersandtoken)
        output_array = pipelineexecutions_output.json()['data']
        # logger.info ("get_rancher_pipelineexecutions output: {0}".format(output_array))
        return output_array

    def get_rancher_pipelineexecutions_logs(self, app, logger, ci_project_id, ci_pipeline_id,\
        pipelines_exec_run, rancher_token):
        output_array = []
        headersandtoken = "Authorization: Bearer {0}".format(rancher_token)
        pipelineexecutions_output = Rancher.get_rancher_pipelineexecutions(self, app, logger, ci_project_id, ci_pipeline_id,\
        rancher_token)
        stages_steps_numbers = []
        for pipelineexecution_output in pipelineexecutions_output:
            if pipelines_exec_run == pipelineexecution_output['run']:
                for stage in  pipelineexecution_output['pipelineConfig']['stages']:
                    stages_steps_numbers.append(len(stage['steps']))
        logger.info("config_stages_steps_number: {0}".format(stages_steps_numbers))
        i=0
        while i < len(stages_steps_numbers):
            j = 0
            while j < stages_steps_numbers[i]:
                ws = websocket.WebSocket(sslopt={"cert_reqs": ssl.CERT_NONE})
                url = "wss://{0}/{1}/project/{2}/pipelineExecutions/{3}-{4}/log?stage={5}&step={6}"\
                    .format(app.config['RANCHER_IP_PORT'], app.config['RANCHER_API_VERSION'], \
                    ci_project_id, ci_pipeline_id, pipelines_exec_run, i, j)
                logger.info("wss url: {0}".format(url))
                ws.connect(url , header=[headersandtoken])
                result =  ws.recv()
                if 'Log is unavailable.' not in result:
                    output_array.append(result)
                    logger.info("Received :'%s'" % result)
                ws.close()
                j+=1
            i+=1
        return output_array