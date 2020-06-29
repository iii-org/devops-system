import requests
import json
import datetime

from model import db

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
    
    # 查詢所有projects
    def get_all_git_projects(self, logger, app):
        url = "http://{0}/api/{1}/projects?private_token={2}".format(\
            app.config["GITLAB_IP_PORT"], app.config["GITLAB_API_VERSION"], self.private_token)
        logger.info("get all projects url: {0}".format(url))
        output = requests.get(url, headers=self.headers, verify=False)
        logger.info("get all projects output: {0}".format(output.json()))
        return output

    # 新增單一project（name/visibility）
    def create_git_project(self, logger, app, args):
        url = "http://{0}/api/{1}/projects?private_token={2}&name={3}&visibility={4}".format(\
            app.config["GITLAB_IP_PORT"], app.config["GITLAB_API_VERSION"], self.private_token, args["name"], args["visibility"])
        logger.info("create project url: {0}".format(url))
        output = requests.post(url, headers=self.headers, verify=False)
        logger.info("create project output: {0}".format(output.json()))
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
    def update_git_project(self, logger, app, project_id, args):
        url = "http://{0}/api/{1}/projects/{2}?private_token={3}&name={4}&visibility={5}".format(\
            app.config["GITLAB_IP_PORT"], app.config["GITLAB_API_VERSION"], project_id, self.private_token, args["name"], args["visibility"])
        logger.info("update project url: {0}".format(url))
        output = requests.put(url, headers=self.headers, verify=False)
        logger.info("update project output: {0}".format(output))
        return output

    # 用project_id刪除單一project
    def delete_git_project(self, logger, app, project_id):
        url = "http://{0}/api/{1}/projects/{2}?private_token={3}".format(\
            app.config["GITLAB_IP_PORT"], app.config["GITLAB_API_VERSION"], project_id, self.private_token)
        logger.info("delete project url: {0}".format(url))
        output = requests.delete(url, headers=self.headers, verify=False)
        logger.info("delete project output: {0}".format(output.json()))
        return output

    # 用project_id查詢project的webhooks
    def get_git_project_webhooks(self, logger, app, project_id):
        url = "http://{0}/api/{1}/projects/{2}/hooks?private_token={3}".format(\
            app.config["GITLAB_IP_PORT"], app.config["GITLAB_API_VERSION"], project_id, self.private_token)
        logger.info("get project webhooks url: {0}".format(url))
        output = requests.get(url, headers=self.headers, verify=False)
        logger.info("get project webhooks output: {0}".format(output.json()))
        return output

    # 用project_id新增project的webhook
    def create_git_project_webhook(self, logger, app, project_id, args):
        url = "http://{0}/api/{1}/projects/{2}/hooks?private_token={3}&url={4}&push_events={5}&push_events_branch_filter={6}&enable_ssl_verification={7}&token={8}".format(\
            app.config["GITLAB_IP_PORT"], app.config["GITLAB_API_VERSION"], project_id, self.private_token, \
            args["url"], args["push_events"], args["push_events_branch_filter"], args["enable_ssl_verification"], \
            args["token"])
        logger.info("create project webhook url: {0}".format(url))
        output = requests.post(url, headers=self.headers, verify=False)
        logger.info("create project webhook output: {0}".format(output.json()))
        return output

    # 用project_id & hook_id修改project的webhook
    def update_git_project_webhook(self, logger, app, project_id, args):
        url = "http://{0}/api/{1}/projects/{2}/hooks/{3}?private_token={4}&url={5}&push_events={6}&push_events_branch_filter={7}&enable_ssl_verification={8}&token={9}".format(\
            app.config["GITLAB_IP_PORT"], app.config["GITLAB_API_VERSION"], project_id, args["hook_id"], self.private_token, \
            args["url"], args["push_events"], args["push_events_branch_filter"], args["enable_ssl_verification"], \
            args["token"])
        logger.info("update project webhook url: {0}".format(url))
        output = requests.put(url, headers=self.headers, verify=False)
        logger.info("update project webhook output: {0}".format(output.json()))
        return output

    # 用project_id & hook_id刪除project的webhook
    def delete_git_project_webhook(self, logger, app, project_id, args):
        url = "http://{0}/api/{1}/projects/{2}/hooks/{3}?private_token={4}".format(\
            app.config["GITLAB_IP_PORT"], app.config["GITLAB_API_VERSION"], project_id, args["hook_id"], self.private_token)
        logger.info("delete project webhook url: {0}".format(url))
        output = requests.delete(url, headers=self.headers, verify=False)
        logger.info("delete project webhook output: {0}".format(output))
        return output
    
    def get_project_list(self, logger, user_id):
        result = db.engine.execute("SELECT pj.id, pj.name FROM public.projects_has_users as pju, public.projects as pj \
            WHERE pju.user_id = {0} AND pju.project_id = pj.id; ".format(user_id))
        project = result.fetchall()
        result.close()
        outupt_array = []
        for raw in project:
            output = {}
            logger.info("get_project_list SQL project_id, project_name: {0}, {1}".format(raw["id"], raw["name"]))
            output["name"] = raw["name"]

            # get branch number by project
            result = db.engine.execute("SELECT COUNT(1) FROM public.branches WHERE project_id = {0};".format(raw["id"]))
            branch_count = result.fetchone()
            result.close()
            logger.info("get_project_list SQL branch count: {0}".format(branch_count))
            output["branch"] = branch_count[0]

            # get issues number and job dayline.
            result = db.engine.execute("SELECT id, due_date FROM public.issues WHERE project_id = {0};".format(raw["id"]))
            issue_list = result.fetchall()
            result.close()
            logger.info("get_project_list SQL issue_list: {0}".format(issue_list))
            the_most_close_day = datetime.date(9999, 12, 31)
            for issue in issue_list:
                logger.info("get_project_list SQL due_date type: {0}".format(issue[1]))
                if the_most_close_day > issue[1]:
                    the_most_close_day = issue[1]
            logger.info("get_project_list: issue number {0}".format(len(issue_list)))
            logger.info("get_project_list: the_most_close_daylist: {0}".format(the_most_close_day))
            output["issues"] = len(issue_list)
            output["next_d_time"] = the_most_close_day.isoformat()

            # get CI/CD record.
            result = db.engine.execute("SELECT ci_li.id, ci_li.create_at, ci_li.success_stage_number, ci_li.total_stage_number\
                FROM public.ci_cd as ci, public.ci_cd_execution_list as ci_li \
                WHERE ci.project_id = {0} AND ci.id = ci_li.ci_cd_id ORDER BY ci_li.id DESC;".format(raw["id"]))
            ci_cd_list = result.fetchone()
            result.close()
            logger.info("get_project_list: ci_cd_list {0}".format(ci_cd_list))
            if ci_cd_list is not None: 
                output["last_test_time"] = ci_cd_list["create_at"].isoformat()
                output["last_test_result"] = { "total": ci_cd_list["total_stage_number"], "success": ci_cd_list["success_stage_number"]}
            logger.info("get_project_list: output: {0}".format(output))
            outupt_array.append(output)
        logger.info("get_project_list: output: {0}".format(outupt_array))
        return outupt_array

    # 用project_id查詢project的branches
    def get_git_project_branches(self, logger, app, project_id):
        url = "http://{0}/api/{1}/projects/{2}/repository/branches?private_token={3}".format(\
            app.config["GITLAB_IP_PORT"], app.config["GITLAB_API_VERSION"], project_id, self.private_token)
        logger.info("get project branches url: {0}".format(url))
        output = requests.get(url, headers=self.headers, verify=False)
        logger.info("get project branches output: {0}".format(output.json()))
        return output

    # 用project_id新增project的branch
    def create_git_project_branch(self, logger, app, project_id, args):
        url = "http://{0}/api/{1}/projects/{2}/repository/branches?private_token={3}&branch={4}&ref={5}".format(\
            app.config["GITLAB_IP_PORT"], app.config["GITLAB_API_VERSION"], project_id, self.private_token, args["branch"], args["ref"])
        logger.info("create project branch url: {0}".format(url))
        output = requests.post(url, headers=self.headers, verify=False)
        logger.info("create project branch output: {0}".format(output.json()))
        return output

    # 用project_id及branch_name查詢project的branch
    def get_git_project_branch(self, logger, app, project_id, branch):
        url = "http://{0}/api/{1}/projects/{2}/repository/branches/{3}?private_token={4}".format(\
            app.config["GITLAB_IP_PORT"], app.config["GITLAB_API_VERSION"], project_id, branch, self.private_token)
        logger.info("get project branch url: {0}".format(url))
        output = requests.get(url, headers=self.headers, verify=False)
        logger.info("get project branch output: {0}".format(output.json()))
        return output

    # 用project_id及branch_name刪除project的branch
    def delete_git_project_branch(self, logger, app, project_id, branch):
        url = "http://{0}/api/{1}/projects/{2}/repository/branches/{3}?private_token={4}".format(\
            app.config["GITLAB_IP_PORT"], app.config["GITLAB_API_VERSION"], project_id, branch, self.private_token)
        logger.info("delete project branch url: {0}".format(url))
        output = requests.delete(url, headers=self.headers, verify=False)
        logger.info("delete project branch output: {0}".format(output))
        return output
    
    # 用project_id查詢project的repositories
    def get_git_project_repositories(self, logger, app, project_id, branch):
        url = "http://{0}/api/{1}/projects/{2}/repository/tree?private_token={3}&ref={4}".format(\
            app.config["GITLAB_IP_PORT"], app.config["GITLAB_API_VERSION"], project_id, self.private_token, branch)
        logger.info("get project repositories url: {0}".format(url))
        output = requests.get(url, headers=self.headers, verify=False)
        logger.info("get project repositories output: {0}".format(output.json()))
        return output

    # 用project_id及branch_name及file_path查詢project的file
    def get_git_project_file(self, logger, app, project_id, branch, file_path):
        url = "http://{0}/api/{1}/projects/{2}/repository/files/{3}?private_token={4}&ref={5}".format(\
            app.config["GITLAB_IP_PORT"], app.config["GITLAB_API_VERSION"], project_id, file_path, self.private_token, branch)
        logger.info("get project file url: {0}".format(url))
        output = requests.get(url, headers=self.headers, verify=False)
        logger.info("get project file output: {0}".format(output.json()))
        return output
