import requests
import json

class Project(object):
    private_token = None
    headers = {'Content-Type': 'application/json'}

    def __init__(self, logger, app):
        if app.config["GITLAB_API_VERSION"] == "v3":
            # get gitlab admin token
            url = "http://{0}/api/v3/session".format(\
                app.config["GITLAB_IP_PORT"])
            parame = {}
            parame["login"] = app.config["GITLAB_ADMIN_ACCOUNT"]
            parame["password"] = app.config["GITLAB_ADMIN_PASSWORD"]

            output = requests.post(url, data=json.dumps(parame), headers=self.headers, verify=False)
            # logger.info("private_token api output: {0}".format(output)) 
            self.private_token = output.json()['private_token']
        else:
            self.private_token = app.config["GITLAB_PRIVATE_TOKEN"]
        logger.info("private_token: {0}".format(self.private_token))
    
    def get_all_git_project(self, logger, app):
        url = "http://{0}/api/{1}/projects?private_token={2}".format(\
            app.config["GITLAB_IP_PORT"], app.config["GITLAB_API_VERSION"], self.private_token)
        logger.info("get all project url: {0}".format(url))
        output = requests.get(url, headers=self.headers, verify=False)
        logger.info("get all project output: {0}".format(output.json()))
        return output

    # 用project_id查詢單一project
    def get_one_git_project(self, logger, app, project_id):
        url = "http://{0}/api/{1}/projects/{2}?private_token={3}".format(\
            app.config["GITLAB_IP_PORT"], app.config["GITLAB_API_VERSION"], project_id, self.private_token)
        logger.info("get one project url: {0}".format(url))
        output = requests.get(url, headers=self.headers, verify=False)
        logger.info("get one project output: {0}".format(output.json()))
        return output

    # 用project_id修改單一project（name/visibility）
    def update_project(self, logger, app, project_id, args):
        url = "http://{0}/api/{1}/projects/{2}?private_token={3}&name={4}&visibility={5}".format(\
            app.config["GITLAB_IP_PORT"], app.config["GITLAB_API_VERSION"], project_id, self.private_token, args["name"], args["visibility"])
        logger.info("update project url: {0}".format(url))
        output = requests.put(url, headers=self.headers, verify=False)
        logger.info("update project output: {0}".format(output))
        return output

    # 用project_id刪除單一project
    def delete_project(self, logger, app, project_id):
        url = "http://{0}/api/{1}/projects/{2}?private_token={3}".format(\
            app.config["GITLAB_IP_PORT"], app.config["GITLAB_API_VERSION"], project_id, self.private_token)
        logger.info("delete project url: {0}".format(url))
        output = requests.delete(url, headers=self.headers, verify=False)
        logger.info("delete project output: {0}".format(output.json()))
        return output

    # 新增單一project
    def create_project(self, logger, app, args):
        url = "http://{0}/api/{1}/projects?private_token={2}&name={3}&visibility={4}".format(\
            app.config["GITLAB_IP_PORT"], app.config["GITLAB_API_VERSION"], self.private_token, args["name"], args["visibility"])
        logger.info("create project url: {0}".format(url))
        output = requests.post(url, headers=self.headers, verify=False)
        logger.info("create project output: {0}".format(output))
        return output