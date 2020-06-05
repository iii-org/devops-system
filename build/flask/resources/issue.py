from .util import util
import requests


class Issue(object):
    redmine_key = None
    headers = {'Content-Type': 'application/json'}
    
    def __init__(self, logger, app):        
        # get redmine_key
        url = "http://{0}:{1}@{2}/users/current.json".format(app.config['REDMINE_ADMIN_ACCOUNT'],\
             app.config['REDMINE_ADMIN_PASSWORD'], app.config['REDMINE_IP_PORT'])
        output = requests.get(url, headers=self.headers, verify=False)
        self.redmine_key = output.json()['user']['api_key']
        logger.info("redmine_key: {0}".format(self.redmine_key))

    def get_issue(self, logger, app, user_id):
        logger.info("redmine_key in get_issue function: {0}".format(self.redmine_key))
        logger.info("self.headers: {0}".format(self.headers))

        url = "http://{0}/issues.json?key={1}&assigned_to_id={2}".format(\
            app.config['REDMINE_IP_PORT'], self.redmine_key, user_id)
        output = requests.get(url, headers=self.headers, verify=False)
        logger.info("get issues output: {0}".format(output))
        return output
        
