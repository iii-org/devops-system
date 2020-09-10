import requests
import json


class GitLab(object):
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

            output = requests.post(url,
                                   data=json.dumps(parame),
                                   headers=self.headers,
                                   verify=False)
            self.private_token = output.json()['private_token']
        else:
            self.private_token = app.config["GITLAB_PRIVATE_TOKEN"]
        logger.info("private_token: {0}".format(self.private_token))

    def create_user(self, logger, app, args, user_source_password):
        gitlab = GitLab(logger, app)
        url = "http://{0}/api/{1}/users?private_token={2}"\
            .format(app.config["GITLAB_IP_PORT"], app.config["GITLAB_API_VERSION"], \
            gitlab.private_token)
        logger.info("gitlab create user url: {0}".format(url))
        parame = {
            "name": args['login'],
            "email": args['email'],
            "username": args['name'],
            "password": user_source_password
        }
        output = requests.post(url,
                               data=json.dumps(parame),
                               headers=self.headers,
                               verify=False)
        logger.info(
            "gitlab create user api output: status_code: {0}, message: {1}".
            format(output.status_code, output.json()))
        return output

    def project_add_member(self, logger, app, project_id, user_id):
        gitlab = GitLab(logger, app)
        url = "http://{0}/api/{1}/projects/{2}/members?private_token={3}"\
            .format(app.config["GITLAB_IP_PORT"], app.config["GITLAB_API_VERSION"], \
            project_id, gitlab.private_token)
        parame = {
            "user_id": user_id,
            "access_level": 40,
        }
        output = requests.post(url,
                               data=json.dumps(parame),
                               headers=self.headers,
                               verify=False)
        logger.info(
            "gitlab project add member api output: status_code: {0}, message: {1}"
            .format(output.status_code, output.text))
        return output, output.status_code

    def project_delete_member(self, logger, app, project_id, user_id):
        gitlab = GitLab(logger, app)
        url = "http://{0}/api/{1}/projects/{2}/members/{3}?private_token={4}"\
            .format(app.config["GITLAB_IP_PORT"], app.config["GITLAB_API_VERSION"], \
            project_id, user_id, gitlab.private_token)
        output = requests.delete(url, headers=self.headers, verify=False)
        logger.info(
            "gitlab project delete member api output: status_code: {0}, message: {1}"
            .format(output.status_code, output.text))
        return output, output.status_code