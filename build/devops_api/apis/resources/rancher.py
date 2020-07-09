from .util import util

class Rancher(object):

    redmine_key = None
    headers = {'Content-Type': 'application/json'}

    def __init__(self):
        pass

    def get_rancher_token(self, app, logger):
        url="https://{0}/{1}-public/localProviders/local?action=login"\
            .format(app.config['RANCHER_IP_PORT'], app.config['RANCHER_API_VERSION'])
        headers = {
            'Content-Type': 'application/json'
        }
        parameter ={
            "username":"{0}".format(app.config['RANCHER_ADMIN_ACCOUNT']),
            "password":"{0}".format(app.config['RANCHER_ADMIN_PASSWORD'])
        }
        output = util.callpostapi(self, url, parameter, logger, headers)
        return output.json()['token']
    
    def get_rancher_pipelineexecutions(self, app, logger, ci_project_id, ci_pipeline_id,\
        rancher_token):
        url= "https://{0}/{1}/projects/{2}/pipelineexecutions?order=desc&pipelineId={3}".format(\
            app.config['RANCHER_IP_PORT'], app.config['RANCHER_API_VERSION'], ci_project_id,\
            ci_pipeline_id)
        logger.info("rancher_pipelineexecutions url: {0}".format(url))
        headersandtoken = self.headers
        headersandtoken['Authorization']= "Bearer {0}".format(rancher_token)
        pipelineexecutions_output = util.callgetapi(self, url, logger, headersandtoken)
        output_array = pipelineexecutions_output.json()['data']
        logger.info ("get_rancher_pipelineexecutions output: {0}".format(output_array))
        return output_array
