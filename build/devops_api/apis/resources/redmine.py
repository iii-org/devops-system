import requests
import json

# from model import db, Project_relationship
# from .util import util


class Redmine(object):

    redmine_key = None
    headers = {'Content-Type': 'application/json'}

    def __init__(self, logger, app):
        # get redmine_key
        url = "http://{0}:{1}@{2}/users/current.json".format(app.config['REDMINE_ADMIN_ACCOUNT'],\
            app.config['REDMINE_ADMIN_PASSWORD'], app.config['REDMINE_IP_PORT'])
        output = requests.get(url, headers=self.headers, verify=False)
        self.redmine_key = output.json()['user']['api_key']
        logger.info("redmine_key: {0}".format(self.redmine_key))

    def get_redmine_key(self, logger, app):
        # get redmine_key
        url = "http://{0}:{1}@{2}/users/current.json".format(app.config['REDMINE_ADMIN_ACCOUNT'],\
            app.config['REDMINE_ADMIN_PASSWORD'], app.config['REDMINE_IP_PORT'])
        output = requests.get(url, headers=self.headers, verify=False)
        self.redmine_key = output.json()['user']['api_key']
        logger.info("redmine_key: {0}".format(self.redmine_key))
        return self.redmine_key

    def redmine_get_issues_by_user(self, logger, app, user_id):

        url = "http://{0}/issues.json?key={1}&assigned_to_id={2}".format(\
            app.config['REDMINE_IP_PORT'], self.redmine_key, user_id)
        output = requests.get(url, headers=self.headers, verify=False)
        logger.info("get issues by output: {0}".format(output.json()))
        return output.json()

    def redmine_get_issues_by_project(self, logger, app, project_id,
                                      redmine_key):
        url = "http://{0}/issues.json?key={1}&project_id={2}".format(\
            app.config['REDMINE_IP_PORT'], redmine_key, project_id)
        output = requests.get(url, headers=self.headers, verify=False)
        logger.info("get issues by project&user output: {0}".format(
            output.json()))
        return output.json()

    def redmine_get_issues_by_project_and_user(self, logger, app, user_id,
                                               project_id, redmine_key):
        url = "http://{0}/issues.json?key={1}&assigned_to_id={2}&project_id={3}".format(\
            app.config['REDMINE_IP_PORT'], redmine_key, user_id, project_id)
        output = requests.get(url, headers=self.headers, verify=False)
        logger.info("get issues by project&user output: {0}".format(
            output.json()))
        return output.json()

    def redmine_get_issue(self, logger, app, issue_id):
        url = "http://{0}/issues/{1}.json?key={2}&include=journals".format(\
            app.config['REDMINE_IP_PORT'], issue_id, self.redmine_key)
        output = requests.get(url, headers=self.headers, verify=False)
        logger.info("get issues output: {0}".format(output))
        return output

    def redmine_get_statistics(self, logger, app, args):
        args['key'] = self.redmine_key
        url = "http://{0}/issues.json".format(app.config['REDMINE_IP_PORT'])
        logger.info("args: {0}".format(args))
        output = requests.get(url,
                              headers=self.headers,
                              verify=False,
                              params=args)
        logger.info("get issues output: {0}".format(output.json()))
        return output.json(), output.status_code

    def redmine_create_issue(self, logger, app, args):
        url = "http://{0}/issues.json?key={1}".format(\
            app.config['REDMINE_IP_PORT'], self.redmine_key)
        param = {"issue": args}
        logger.info("create issues param: {0}".format(param))
        output = requests.post(url,
                               data=json.dumps(param),
                               headers=self.headers,
                               verify=False)
        logger.info("create issues output: {0}".format(output.json()))
        return output

    def redmine_update_issue(self, logger, app, issue_id, args):
        url = "http://{0}/issues/{1}.json?key={2}".format(\
            app.config['REDMINE_IP_PORT'], issue_id, self.redmine_key)
        param = {"issue": args}
        logger.info("update issues param: {0}".format(param))
        output = requests.put(url,
                              data=json.dumps(param),
                              headers=self.headers,
                              verify=False)
        logger.info("update issues output: {0}".format(output))
        return output

    def redmine_delete_issue(self, logger, app, issue_id):
        url = "http://{0}/issues/{1}.json?key={2}&include=journals".format(\
            app.config['REDMINE_IP_PORT'], issue_id, self.redmine_key)
        output = requests.delete(url, headers=self.headers, verify=False)
        logger.info("get issues output: {0}".format(output))
        return output

    def redmine_get_issue_status(self, logger, app):
        url="http://{0}/issue_statuses.json?key={1}".format(\
            app.config['REDMINE_IP_PORT'], self.redmine_key,)
        output = requests.get(url, headers=self.headers, verify=False)
        logger.info("get issues stauts list output: {0}".format(output.json()))
        return output.json()

    def redmine_get_priority(self, logger, app):
        url="http://{0}/enumerations/issue_priorities.json?key={1}".format(\
            app.config['REDMINE_IP_PORT'], self.redmine_key)
        output = requests.get(url, headers=self.headers, verify=False)
        logger.info("get issues stauts list output: {0}".format(output.json()))
        return output.json()

    def redmine_get_trackers(self, logger, app):
        url="http://{0}/trackers.json?key={1}".format(\
            app.config['REDMINE_IP_PORT'], self.redmine_key)
        output = requests.get(url, headers=self.headers, verify=False)
        logger.info("get issues stauts list output: {0}".format(output.json()))
        return output.json()

    def redmine_post_user(self, logger, app, args, user_source_password):
        url = "http://{0}/users.json?key={1}".format(
            app.config['REDMINE_IP_PORT'], self.redmine_key)
        param = {
            "user": {
                "login": args["login"],
                "firstname": args["name"],
                "lastname": args["name"],
                "mail": args["email"],
                "password": user_source_password
            }
        }
        logger.info("post user param: {0}".format(param))
        output = requests.post(url,
                               data=json.dumps(param),
                               headers=self.headers,
                               verify=False)
        logger.info(
            "redmine create user api output: status_code: {0}, message: {1}".
            format(output.status_code, output.json()))
        return output