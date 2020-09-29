import requests
import json
from datetime import datetime

from model import db, ProjectUserRole, ProjectPluginRelation, TableProjects
from .redmine import Redmine
from .rancher import Rancher
from .util import util

import urllib


class Project(object):
    private_token = None
    headers = {'Content-Type': 'application/json'}

    def __init__(self, logger, app, au):
        self.au = au
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
            # logger.info("private_token api output: {0}".format(output))
            self.private_token = output.json()['private_token']
        else:
            self.private_token = app.config["GITLAB_PRIVATE_TOKEN"]
        logger.info("private_token: {0}".format(self.private_token))

    def verify_project_user(self, logger, project_id, user_id):
        select_project_user_role_command = db.select([ProjectUserRole.stru_project_user_role])\
            .where(db.and_(ProjectUserRole.stru_project_user_role.c.project_id==project_id, \
            ProjectUserRole.stru_project_user_role.c.user_id==user_id))
        logger.debug("select_project_user_role_command: {0}".format(
            select_project_user_role_command))
        reMessage = util.callsqlalchemy(select_project_user_role_command,
                                        logger)
        match_list = reMessage.fetchall()
        logger.info("reMessage: {0}".format(match_list))
        logger.info("reMessage len: {0}".format(len(match_list)))
        if len(match_list) > 0:
            return True
        else:
            return False

    @staticmethod
    def get_project_plugin_relation(logger, project_id):
        select_project_relation_command = db.select([ProjectPluginRelation.stru_project_plug_relation])\
            .where(db.and_(ProjectPluginRelation.stru_project_plug_relation.c.project_id==project_id))
        reMessage = util.callsqlalchemy(select_project_relation_command,
                                        logger).fetchone()
        return reMessage

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

    def get_project_by_plan_project_id(self, logger, plan_project_id):
        result = db.engine.execute(
            "SELECT * FROM public.project_plugin_relation \
            WHERE plan_project_id = {0}".format(plan_project_id))
        project = result.fetchone()
        result.close()
        return project

    @staticmethod
    def get_plan_project_id(project_id):
        result = db.engine.execute(
            "SELECT plan_project_id FROM public.project_plugin_relation"
            " WHERE project_id = {0}".format(project_id))
        if result.rowcount > 0:
            project = result.fetchone()
            ret = project['plan_project_id']
        else:
            ret = -1
        result.close()
        return ret

    def get_projects_by_user(self, logger, app, user_id):
        output_array = []
        result = db.engine.execute(
            "SELECT pj.id, pj.name, ppl.plan_project_id, \
            ppl.git_repository_id, ppl.ci_project_id, ppl.ci_pipeline_id\
            FROM public.project_user_role as pur, public.projects as pj, public.project_plugin_relation as ppl\
            WHERE pur.user_id = {0} AND pur.project_id = pj.id AND pj.id = ppl.project_id;"
            .format(user_id))
        project_list = result.fetchall()
        result.close()
        logger.debug("project list: {0}".format(project_list))
        if len(project_list) > 0:
            # get user ids
            result = db.engine.execute(
                "SELECT plan_user_id, repository_user_id \
                FROM public.user_plugin_relation WHERE user_id = {0}; ".format(
                    user_id))
            userid_list_output = result.fetchone()
            if userid_list_output is not None:
                plan_user_id = userid_list_output[0]
                result.close()
                logger.info("get user_ids SQL: {0}".format(plan_user_id))
                redmine_key = Redmine.get_redmine_key(self, logger, app)
                for project in project_list:
                    output_dict = {}
                    output_dict['name'] = project['name']
                    output_dict['project_id'] = project['id']

                    output_dict['repository_ids'] = project[
                        'git_repository_id']
                    output_dict['issues'] = None
                    output_dict['branch'] = None
                    output_dict['tag'] = None
                    output_dict['next_d_time'] = None
                    output_dict['last_test_time'] = ""
                    output_dict['last_test_result'] = {}

                    # get issue total cont
                    total_issue = Redmine.redmine_get_issues_by_project_and_user(self, logger, app, \
                        plan_user_id, project['plan_project_id'] ,redmine_key)
                    logger.info("issue total count by user: {0}".format(
                        total_issue['total_count']))
                    output_dict['issues'] = total_issue['total_count']

                    # get next_d_time
                    issue_due_date_list = []
                    for issue in total_issue['issues']:
                        if issue['due_date'] is not None:
                            issue_due_date_list.append(
                                datetime.strptime(issue['due_date'],
                                                  "%Y-%m-%d"))
                    logger.info(
                        "issue_due_date_list: {0}".format(issue_due_date_list))
                    next_d_time = None
                    if len(issue_due_date_list) != 0:
                        next_d_time = min(
                            issue_due_date_list,
                            key=lambda d: abs(d - datetime.now()))
                    logger.info("next_d_time: {0}".format(next_d_time))
                    if next_d_time is not None:
                        output_dict['next_d_time'] = next_d_time.isoformat()

                    if project['git_repository_id'] is not None:
                        # branch bumber
                        branch_number = 0
                        output, status_code = self.get_git_project_branches(
                            logger, app, project['git_repository_id'])
                        if status_code == 200:
                            branch_number = len(output['data']['branch_list'])
                        logger.info(
                            "get_git_project_branches number: {0}".format(
                                branch_number))
                        output_dict['branch'] = branch_number
                        # tag nubmer
                        tag_number = 0
                        output, status_code = self.get_git_project_tags(
                            logger, app, project['git_repository_id'])
                        if status_code == 200:
                            tag_number = len(output['data']['tag_list'])
                        logger.info("get_git_project_tags number: {0}".format(
                            tag_number))
                        output_dict['tag'] = tag_number

                    if project['ci_project_id'] is not None:
                        output_dict = self.get_ci_last_test_result(
                            app, logger, output_dict, project)
                    logger.debug("output_dict: {0}".format(output_dict))
                    output_array.append(output_dict)
                logger.debug("output_array: {0}".format(output_array))
                return {"message": "success", "data": output_array}, 200
            else:
                return {
                    "message": "could not get plan_user_id and repository_id"
                }, 400
        else:
            return {"message": "success", "data": []}, 200

    def get_ci_last_test_result(self, app, logger, output_dict, project):
        # get rancher pipeline
        rancher_token = Rancher.get_rancher_token(self, app, logger)
        pipeline_output = Rancher.get_rancher_pipelineexecutions(self, app, logger, project["ci_project_id"],\
            project["ci_pipeline_id"], rancher_token)
        if len(pipeline_output) != 0:
            logger.info(pipeline_output[0]['name'])
            logger.info(pipeline_output[0]['created'])
            output_dict['last_test_time'] = pipeline_output[0]['created']
            stage_status = []
            # logger.info(pipeline_output[0]['stages'])
            for stage in pipeline_output[0]['stages']:
                logger.info("stage: {0}".format(stage))
                if 'state' in stage:
                    stage_status.append(stage['state'])
            logger.info(stage_status)
            failed_item = -1
            if 'Failed' in stage_status:
                failed_item = stage_status.index('Failed')
                logger.info("failed_item: {0}".format(failed_item))
                output_dict['last_test_result']={'total': len(pipeline_output[0]['stages']),\
                    'success': failed_item }
            else:
                output_dict['last_test_result']={'total': len(pipeline_output[0]['stages']),\
                    'success': len(pipeline_output[0]['stages'])}
        return output_dict

    # 用project_id查詢project的branches
    def get_git_project_branches(self, logger, app, project_id):
        url = "http://{0}/api/{1}/projects/{2}/repository/branches?private_token={3}".format(\
            app.config["GITLAB_IP_PORT"], app.config["GITLAB_API_VERSION"], project_id, self.private_token)
        logger.info("get project branches url: {0}".format(url))
        logger.info("get project branches headers: {0}".format(self.headers))
        output = requests.get(url, headers=self.headers, verify=False)
        logger.info("get project branches output: {0} / {1}".format(
            output, output.json()))
        if output.status_code == 200:
            branch_list = []
            for branch_info in output.json():
                branch = {
                    "name": branch_info["name"],
                    "last_commit_message": branch_info["commit"]["message"],
                    "last_commit_time":
                    branch_info["commit"]["committed_date"],
                    "short_id": branch_info["commit"]["short_id"]
                }
                branch_list.append(branch)
            return {
                "message": "success",
                "data": {
                    "branch_list": branch_list
                }
            }, 200
        else:
            logger.info("gitlab repository get branch list error: {0}".format(output.json()["message"]))
            return {"message": "gitlab don't has this repository project id"}, 400

    # 用project_id新增project的branch
    def create_git_project_branch(self, logger, app, project_id, args):
        url = "http://{0}/api/{1}/projects/{2}/repository/branches?private_token={3}&branch={4}&ref={5}".format(\
            app.config["GITLAB_IP_PORT"], app.config["GITLAB_API_VERSION"], project_id, self.private_token, args["branch"], args["ref"])
        logger.info("create project branch url: {0}".format(url))
        output = requests.post(url, headers=self.headers, verify=False)
        logger.info("create project branch output: {0} / {1}".format(
            output, output.json()))
        if output.status_code == 201:
            return {"message": "success", "data": output.json()}, 200
        else:
            return {"message": output.json()["message"]}, output.status_code

    # 用project_id及branch_name查詢project的branch
    def get_git_project_branch(self, logger, app, project_id, branch):
        url = "http://{0}/api/{1}/projects/{2}/repository/branches/{3}?private_token={4}".format(\
            app.config["GITLAB_IP_PORT"], app.config["GITLAB_API_VERSION"], project_id, branch, self.private_token)
        logger.info("get project branch url: {0}".format(url))
        output = requests.get(url, headers=self.headers, verify=False)
        logger.info("get project branch output: {0} / {1}".format(
            output, output.json()))
        if output.status_code == 200:
            return {"message": "success", "data": output.json()}, 200
        else:
            return {"message": output.json()["message"]}, output.status_code

    # 用project_id及branch_name刪除project的branch
    def delete_git_project_branch(self, logger, app, project_id, branch):
        url = "http://{0}/api/{1}/projects/{2}/repository/branches/{3}?private_token={4}".format(\
            app.config["GITLAB_IP_PORT"], app.config["GITLAB_API_VERSION"], project_id, branch, self.private_token)
        logger.info("delete project branch url: {0}".format(url))
        output = requests.delete(url, headers=self.headers, verify=False)
        logger.info("delete project branch output: {0}".format(output))
        if output.status_code == 204:
            return {"message": "success"}, 200
        else:
            return {"message": output.json()["message"]}, output.status_code

    # 用project_id查詢project的repositories
    def get_git_project_repositories(self, logger, app, project_id, branch):
        url = "http://{0}/api/{1}/projects/{2}/repository/tree?private_token={3}&ref={4}".format(\
            app.config["GITLAB_IP_PORT"], app.config["GITLAB_API_VERSION"], project_id, self.private_token, branch)
        logger.info("get project repositories url: {0}".format(url))
        output = requests.get(url, headers=self.headers, verify=False)
        logger.info("get project repositories output: {0} / {1}".format(
            output, output.json()))
        if output.status_code == 200:
            return {
                "message": "success",
                "data": {
                    "file_list": output.json()
                }
            }, 200
        else:
            return {"message": output.json()["message"]}, output.status_code

    # 用project_id及branch_name及file_path查詢project的file
    def get_git_project_file(self, logger, app, project_id, branch, file_path):
        url = "http://{0}/api/{1}/projects/{2}/repository/files/{3}?private_token={4}&ref={5}".format(\
            app.config["GITLAB_IP_PORT"], app.config["GITLAB_API_VERSION"], project_id, file_path, self.private_token, branch)
        logger.info("get project file url: {0}".format(url))
        output = requests.get(url, headers=self.headers, verify=False)
        logger.info("get project file output: {0} / {1}".format(
            output, output.json()))
        if output.status_code == 200:
            return {
                "message": "success",
                "data": {
                    "file_name": output.json()["file_name"],
                    "file_path": output.json()["file_path"],
                    "size": output.json()["size"],
                    "encoding": output.json()["encoding"],
                    "content": output.json()["content"],
                    "content_sha256": output.json()["content_sha256"],
                    "ref": output.json()["ref"],
                    "last_commit_id": output.json()["last_commit_id"]
                }
            }, 200
        else:
            error_code = output.status_code
            return {"message": output.json()["message"]}, error_code

    # 用project_id及branch_name及file_path新增project的file
    def create_git_project_file(self, logger, app, project_id, args):
        url = "http://{0}/api/{1}/projects/{2}/repository/files/{3}?private_token={4}&branch={5}&start_branch={6}&encoding={7}&author_email={8}&author_name={9}&content={10}&commit_message={11}".format(\
            app.config["GITLAB_IP_PORT"], app.config["GITLAB_API_VERSION"], project_id, args["file_path"], self.private_token, args["branch"], args["start_branch"], args["encoding"], args["author_email"], args["author_name"], args["content"], args["commit_message"])
        logger.info("post project file url: {0}".format(url))
        output = requests.post(url, headers=self.headers, verify=False)
        logger.info("post project file output: {0} / {1}".format(
            output, output.json()))
        if output.status_code == 201:
            return {
                "message": "success",
                "data": {
                    "file_path": output.json()["file_path"],
                    "branch_name": output.json()["branch"]
                }
            }, 200
        else:
            error_code = output.status_code
            return {"message": output.json()["message"]}, error_code

    # 用project_id及branch_name及file_path修改project的file
    def update_git_project_file(self, logger, app, project_id, args):
        url = "http://{0}/api/{1}/projects/{2}/repository/files/{3}?private_token={4}&branch={5}&start_branch={6}&encoding={7}&author_email={8}&author_name={9}&content={10}&commit_message={11}".format(\
            app.config["GITLAB_IP_PORT"], app.config["GITLAB_API_VERSION"], project_id, args["file_path"], self.private_token, args["branch"], args["start_branch"], args["encoding"], args["author_email"], args["author_name"], args["content"], args["commit_message"])
        logger.info("put project file url: {0}".format(url))
        output = requests.put(url, headers=self.headers, verify=False)
        logger.info("put project file output: {0}".format(output))
        if output.status_code == 200:
            return {
                "message": "success",
                "data": {
                    "file_path": output.json()["file_path"],
                    "branch_name": output.json()["branch"]
                }
            }, 200
        else:
            error_code = output.status_code
            return {"message": output.json()["message"]}, error_code

    # 用project_id及branch_name及file_path刪除project的file
    def delete_git_project_file(self, logger, app, project_id, branch,
                                file_path, args):
        url = "http://{0}/api/{1}/projects/{2}/repository/files/{3}?private_token={4}&branch={5}&commit_message={6}".format(\
            app.config["GITLAB_IP_PORT"], app.config["GITLAB_API_VERSION"], project_id, file_path, self.private_token, branch, args["commit_message"])
        logger.info("delete project file url: {0}".format(url))
        output = requests.delete(url, headers=self.headers, verify=False)
        logger.info("delete project file output: {0}".format(output))
        if output.status_code == 204:
            return {"message": "success"}, 200
        else:
            error_code = output.status_code
            return {"message": output.json()["message"]}, error_code

    # 用project_id查詢project的tags
    def get_git_project_tags(self, logger, app, project_id):
        url = "http://{0}/api/{1}/projects/{2}/repository/tags?private_token={3}".format(\
            app.config["GITLAB_IP_PORT"], app.config["GITLAB_API_VERSION"], project_id, self.private_token)
        logger.info("get project tags url: {0}".format(url))
        output = requests.get(url, headers=self.headers, verify=False)
        logger.info("get project tags output: {0} / {1} ".format(
            output, output.json()))
        if output.status_code == 200:
            return {
                "message": "success",
                "data": {
                    "tag_list": output.json()
                }
            }, 200
        else:
            return {
                "message": output.json()["message"],
            }, output.status_code

    # 用project_id新增project的tag
    def create_git_project_tags(self, logger, app, project_id, args):
        url = "http://{0}/api/{1}/projects/{2}/repository/tags?private_token={3}&tag_name={4}&ref={5}&message={6}&release_description={7}".format(\
            app.config["GITLAB_IP_PORT"], app.config["GITLAB_API_VERSION"], project_id, self.private_token, args["tag_name"], args["ref"], args["message"], args["release_description"])
        logger.info("create project tag url: {0}".format(url))
        output = requests.post(url, headers=self.headers, verify=False)
        logger.info("create project tag output: {0} / {1}".format(
            output, output.json()))
        if output.status_code == 201:
            return {"message": "success", "data": output.json()}, 200
        else:
            return {"message": output.json()["message"]}, output.status_code

    # 用project_id及tag_name刪除project的tag
    def delete_git_project_tag(self, logger, app, project_id, tag_name):
        url = "http://{0}/api/{1}/projects/{2}/repository/tags/{3}?private_token={4}".format(\
            app.config["GITLAB_IP_PORT"], app.config["GITLAB_API_VERSION"], project_id, tag_name, self.private_token)
        logger.info("delete project tag url: {0}".format(url))
        output = requests.delete(url, headers=self.headers, verify=False)
        logger.info("delete project tag output: {0}".format(output))
        if output.status_code == 204:
            return {"message": "success"}, 200
        else:
            return {"message": output.json()["message"]}, output.status_code

    # 用project_id及directory_path新增project的directory
    def create_git_project_directory(self, logger, app, project_id,
                                     directory_path, args):
        url = "http://{0}/api/{1}/projects/{2}/repository/files/{3}?private_token={4}&branch={5}&commit_message={6}&content={7}".format(\
            app.config["GITLAB_IP_PORT"], app.config["GITLAB_API_VERSION"], project_id, directory_path, self.private_token, args["branch"], args["commit_message"], "")
        logger.info("create project directory url: {0}".format(url))
        output = requests.post(url, headers=self.headers, verify=False)
        logger.info("create project directory output: {0} / {1}".format(
            output, output.json()))
        if output.status_code == 201:
            return {"message": "success", "data": output.json()}, 200
        else:
            return {"message": output.json()["message"]}, output.status_code

    # 用project_id及directory_path修改project的directory
    def update_git_project_directory(self, logger, app, project_id,
                                     directory_path, args):
        url = "http://{0}/api/{1}/projects/{2}/repository/files/{3}?private_token={4}&branch={5}&commit_message={6}&author_name={7}&author_email={8}&encoding={9}&content={10}".format(\
            app.config["GITLAB_IP_PORT"], app.config["GITLAB_API_VERSION"], project_id, directory_path, self.private_token, args["branch"], args["commit_message"], args["author_name"], args["author_email"], args["encoding"], args["content"])
        logger.info("update project directory url: {0}".format(url))
        output = requests.put(url, headers=self.headers, verify=False)
        logger.info("update project directory output: {0} / {1}".format(
            output, output.json()))
        if output.status_code == 200:
            return {"message": "success", "data": output.json()}, 200
        else:
            return {"message": output.json()["message"]}, output.status_code

    # 用project_id及directory_path刪除project的directory
    def delete_git_project_directory(self, logger, app, project_id,
                                     directory_path, args):
        # 查詢directory的files
        url = "http://{0}/api/{1}/projects/{2}/repository/tree?private_token={3}&ref={4}&path={5}".format(\
            app.config["GITLAB_IP_PORT"], app.config["GITLAB_API_VERSION"], project_id, self.private_token, args["branch"], directory_path)
        logger.info("get project directoryfiles url: {0}".format(url))
        output1 = requests.get(url, headers=self.headers, verify=False)
        logger.info("get project directoryfiles output: {0} / {1}".format(
            output1, output1.json()))
        if output1.status_code == 200:
            # 依序刪除directory的files
            try:
                for file in output1.json():
                    path_encode = urllib.parse.quote(file["path"], safe='')
                    print(path_encode)
                    url = "http://{0}/api/{1}/projects/{2}/repository/files/{3}?private_token={4}&branch={5}&commit_message={6}".format(\
                        app.config["GITLAB_IP_PORT"], app.config["GITLAB_API_VERSION"], project_id, path_encode, self.private_token, args["branch"], args["commit_message"])
                    logger.info(
                        "delete project directory url: {0}".format(url))
                    output2 = requests.delete(url,
                                              headers=self.headers,
                                              verify=False)
                    logger.info(
                        "delete project directory output: {0}".format(output2))
                if output2.status_code == 204:
                    return {"message": "success"}, 200
                else:
                    return {
                        "message": output2.json()["message"]
                    }, output2.status_code
            except Exception as error:
                return {"message": str(error)}, 400
        else:
            return {"message": output1.json()["message"]}, output1.status_code

    # 用project_id合併project的任兩個branches
    def create_git_project_mergebranch(self, logger, app, project_id, args):
        # 新增merge request
        url = "http://{0}/api/{1}/projects/{2}/merge_requests?private_token={3}&source_branch={4}&target_branch={5}&title={6}".format(\
            app.config["GITLAB_IP_PORT"], app.config["GITLAB_API_VERSION"], project_id, self.private_token, args["source_branch"], args["target_branch"], args["title"])
        logger.info("post project mergerequest url: {0}".format(url))
        output = requests.post(url, headers=self.headers, verify=False)
        logger.info("post project mergerequest output:{0} / {1}".format(
            output, output.json()))

        if output.status_code == 201:
            # 同意merge request
            merge_request_iid = output.json()["iid"]
            url = "http://{0}/api/{1}/projects/{2}/merge_requests/{3}/merge?private_token={4}".format(\
                app.config["GITLAB_IP_PORT"], app.config["GITLAB_API_VERSION"], project_id, merge_request_iid, self.private_token)
            logger.info("post project acceptmerge url: {0}".format(url))
            output = requests.put(url, headers=self.headers, verify=False)
            logger.info("post project acceptmerge output:{0} / {1}".format(
                output, output.json()))
            if output.status_code == 200:
                return {"message": "success"}, 200
            else:
                # 刪除merge request
                url = "http://{0}/api/{1}/projects/{2}/merge_requests/{3}?private_token={4}".format(\
                    app.config["GITLAB_IP_PORT"], app.config["GITLAB_API_VERSION"], project_id, merge_request_iid, self.private_token)
                logger.info("delete project mergerequest url: {0}".format(url))
                output_extra = requests.delete(url,
                                               headers=self.headers,
                                               verify=False)
                logger.info("delete project mergerequest output:{0}".format(
                    output_extra))
                if output_extra.status_code == 204:
                    return {
                        "message":
                        "merge failed and already delete your merge request."
                    }, 400
                else:
                    return {
                        "message": "merge failed."
                    }, output_extra.status_code
        else:
            return {"message": output.json()["message"]}, output.status_code

    def create_ranhcer_pipline_yaml(self, logger, app, project_id, args,
                                    action):
        pro = Project(logger, app)
        url = "http://{0}/api/{1}/projects/{2}/repository/files/{3}?private_token={4}&branch={5}&\
start_branch={6}&encoding={7}&author_email={8}&author_name={9}&content={10}&commit_message={11}" \
            .format( app.config["GITLAB_IP_PORT"], app.config["GITLAB_API_VERSION"], project_id, \
            args["file_path"], pro.private_token, args["branch"], args["start_branch"], \
            args["encoding"], args["author_email"], args["author_name"], args["content"], \
            args["commit_message"])
        if action == 'post':
            logger.info("post project file url: {0}".format(url))
            output = requests.post(url, headers=self.headers, verify=False)
            logger.info("post project file output: {0}".format(output.json()))
        else:
            logger.info("put project file url: {0}".format(url))
            output = requests.put(url, headers=self.headers, verify=False)
            logger.info("put project file output: {0}".format(output.json()))
        return output

    def get_git_project_file_for_pipeline(self, logger, app, project_id, args):
        pro = Project(logger, app)
        url = "http://{0}/api/{1}/projects/{2}/repository/files/{3}?private_token={4}&ref={5}"\
            .format(app.config["GITLAB_IP_PORT"], app.config["GITLAB_API_VERSION"], project_id, \
            args["file_path"], pro.private_token, args["branch"])
        logger.info("get project file url: {0}".format(url))
        output = requests.get(url, headers=self.headers, verify=False)
        logger.info("get project file output: {0}".format(output.json()))
        return output

    # 用project_id查詢project的commits
    def get_git_project_branch_commits(self, logger, app, project_id, args):
        url = "http://{0}/api/{1}/projects/{2}/repository/commits?private_token={3}&ref_name={4}&per_page=100".format(\
            app.config["GITLAB_IP_PORT"], app.config["GITLAB_API_VERSION"], project_id, self.private_token, args["branch"])
        logger.info("get project branch commits url: {0}".format(url))
        output = requests.get(url, headers=self.headers, verify=False)
        logger.info("get project branch commits output: {0} / {1}".format(
            output, output.json()))
        if output.status_code == 200:
            return {"message": "success", "data": output.json()}, 200
        else:
            return {"message": output.json()["message"]}, output.status_code

    # 用project_id查詢project的網路圖
    def get_git_project_network(self, logger, app, project_id):
        try:
            branch_commit_list = []
            tag_list = []

            # 整理各branches的commit_list
            branches = self.get_git_project_branches(logger, app, project_id)
            for branch in branches[0]["data"]["branch_list"]:
                args = {}
                args["branch"] = branch["name"]
                branch_commits = self.get_git_project_branch_commits(
                    logger, app, project_id, args)

                commit_list = []
                for branch_commit in branch_commits[0]["data"]:
                    obj = {
                        "id": branch_commit["id"],
                        "message": branch_commit["message"],
                        "author_name": branch_commit["author_name"],
                        "committed_date": branch_commit["committed_date"]
                    }

                    commit_list.append(obj)

                branch_obj = {
                    "branch": branch["name"],
                    "commit_list": commit_list
                }

                branch_commit_list.append(branch_obj)

            # 整理tags
            tags = self.get_git_project_tags(logger, app, project_id)
            for tag in tags[0]["data"]["tag_list"]:
                tag_obj = {
                    "tag": tag["name"],
                    "message": tag["message"],
                    "commit_id": tag["commit"]["id"],
                    "commit_message": tag["commit"]["message"],
                    "author_name": tag["commit"]["author_name"],
                    "created_at": tag["commit"]["created_at"]
                }

                tag_list.append(tag_obj)

            return {
                "message": "success",
                "data": {
                    "branch_commit_list": branch_commit_list,
                    "tag_list": tag_list
                }
            }, 200
        except Exception as error:
            return {"message": str(error)}, 400

    # 查詢pm的project list
    def get_pm_project_list(self, logger, app, user_id):
        # 查詢db該pm負責的project_id並存入project_ids array
        result = db.engine.execute(
            "SELECT project_id FROM public.project_user_role WHERE user_id = '{0}'"
            .format(user_id))
        project_ids = result.fetchall()
        result.close()
        print(project_ids)
        if project_ids:
            output_array = []
            # 用project_id依序查詢redmine的project_id
            for project_id in project_ids:
                project_id = project_id[0]
                if project_id is not None and project_id != -1:
                    result = db.engine.execute(
                        "SELECT plan_project_id FROM public.project_plugin_relation WHERE project_id = '{0}'"
                        .format(project_id))
                    plan_project_id = result.fetchone()[0]
                    result.close()

                    ## 用redmine api查詢相關資訊
                    # 抓專案最近更新時間
                    url1 = "http://{0}/projects/{1}.json?key={2}&limit=1000".format(
                        app.config["REDMINE_IP_PORT"], plan_project_id,
                        app.config["REDMINE_API_KEY"])
                    output1 = requests.get(url1,
                                           headers=self.headers,
                                           verify=False).json()
                    # 抓專案狀態＆專案工作進度＆進度落後數目
                    url2 = "http://{0}/issues.json?key={1}&project_id={2}&limit=1000".format(
                        app.config["REDMINE_IP_PORT"],
                        app.config["REDMINE_API_KEY"], plan_project_id)
                    output2 = requests.get(url2,
                                           headers=self.headers,
                                           verify=False).json()

                    closed_count = 0
                    overdue_count = 0
                    for issue in output2["issues"]:
                        if issue["status"]["name"] == "Closed":
                            closed_count += 1
                        if issue["due_date"] != None:
                            if (datetime.today() > datetime.strptime(
                                    issue["due_date"], "%Y-%m-%d")) == True:
                                overdue_count += 1

                    project_status = "進行中"
                    if output2["total_count"] == 0: project_status = "未開始"
                    if closed_count == output2[
                            "total_count"] and output2["total_count"] != 0:
                        project_status = "已結案"

                    # 查詢專案名稱＆專案說明＆專案狀態
                    result = db.engine.execute(
                        "SELECT * FROM public.projects WHERE id = '{0}'".
                        format(project_id))
                    project_info = result.fetchone()
                    result.close()

                    # 查詢專案負責人id & name
                    result = db.engine.execute(
                        "SELECT user_id FROM public.project_user_role WHERE project_id = '{0}' AND role_id = '{1}'"
                        .format(project_id, 3))
                    user_id = result.fetchone()[0]
                    result.close()

                    result = db.engine.execute(
                        "SELECT name FROM public.user WHERE id = '{0}'".format(
                            user_id))
                    user_name = result.fetchone()[0]
                    result.close()

                    # 查詢sonar_quality_score
                    project_name = project_info["name"]
                    # print(project_name)
                    # project_name = "devops-flask"
                    url = "http://{0}/api/measures/component?component={1}&metricKeys=reliability_rating,security_rating,security_review_rating,sqale_rating".format(\
                        app.config["SONAR_IP_PORT"], project_name)
                    logger.info("get sonar report url: {0}".format(url))
                    output = requests.get(url,
                                          headers=self.headers,
                                          verify=False)
                    logger.info("get sonar report output: {0} / {1}".format(
                        output, output.json()))
                    quality_score = None
                    if output.status_code == 200:
                        quality_score = 0
                        data_list = output.json()["component"]["measures"]
                        for data in data_list:
                            # print(type(data["value"]))
                            rating = float(data["value"])
                            quality_score += (
                                6 - rating) * 5  # A-25, B-20, C-15, D-10, E-5

                    redmine_url = "http://{0}/projects/{1}".format(app.config["REDMINE_IP_PORT"], plan_project_id)
                    project_output = {
                        "id": project_id,
                        "name": project_info["name"],
                        "description": project_info["description"],
                        "git_url": project_info["http_url"],
                        "redmine_url": redmine_url,
                        "disabled": project_info["disabled"],
                        "pm_user_id": user_id,
                        "pm_user_name": user_name,
                        "updated_time": output1["project"]["updated_on"],
                        "project_status": project_status,
                        "closed_count": closed_count,
                        "total_count": output2["total_count"],
                        "overdue_count": overdue_count,
                        "quality_score": quality_score
                    }

                    output_array.append(project_output)

            return {
                "message": "success",
                "data": {
                    "project_list": output_array
                }
            }, 200
        else:
            return {"message": "Could not get data from db"}, 400

    # 用project_id查詢redmine的單一project
    def get_redmine_one_project(self, logger, app, project_id):
        url = "http://{0}/projects/{1}.json?key={2}".format(
            app.config["REDMINE_IP_PORT"], project_id,
            app.config["REDMINE_API_KEY"])
        logger.info("get redmine one project url: {0}".format(url))
        output = requests.get(url, headers=self.headers, verify=False)
        logger.info("get redmine one project output: {0} / {1}".format(
            output, output.json()))
        return output

    # 新增redmine & gitlab的project並將db相關table新增資訊
    def pm_create_project(self, logger, app, user_id, args):
        from .auth import auth
        if args["description"] == None: args["description"] = ""

        identifier = args["name"].replace(' ', '_').lower()

        # 建立redmine project
        redmine_url = "http://{0}/projects.json?key={1}".format(
            app.config["REDMINE_IP_PORT"], app.config["REDMINE_API_KEY"])
        logger.info("create redmine project url: {0}".format(redmine_url))
        xml_body = """<?xml version="1.0" encoding="UTF-8"?>\
                    <project>\
                    <name>{0}</name>\
                    <identifier>{1}</identifier>\
                    <description>{2}</description>\
                    </project>""".format(args["name"], identifier,
                                         args["description"])
        logger.info("create redmine project body: {0}".format(xml_body))
        headers = {'Content-Type': 'application/xml'}
        redmine_output = requests.post(redmine_url,
                                       headers=headers,
                                       data=xml_body,
                                       verify=False)
        logger.info("create redmine project output: {0} / {1}".format(
            redmine_output, redmine_output.json()))

        # 建立gitlab project
        if redmine_output.status_code == 201:
            gitlab_url = "http://{0}/api/{1}/projects?private_token={2}&name={3}&description={4}".format(\
                app.config["GITLAB_IP_PORT"], app.config["GITLAB_API_VERSION"], self.private_token, args["name"], args["description"])
            logger.info("create gitlab project url: {0}".format(gitlab_url))
            gitlab_output = requests.post(gitlab_url,
                                          headers=self.headers,
                                          verify=False)
            logger.info("create gitlab project output: {0} / {1}".format(
                gitlab_output, gitlab_output.json()))

            # 寫入db
            if gitlab_output.status_code == 201:
                redmine_pj_id = redmine_output.json()["project"]["id"]
                gitlab_pj_id = gitlab_output.json()["id"]
                gitlab_pj_name = gitlab_output.json()["name"]
                gitlab_pj_ssh_url = gitlab_output.json()["ssh_url_to_repo"]
                gitlab_pj_http_url = gitlab_output.json()["http_url_to_repo"]

                # 寫入projects
                db.engine.execute(
                    "INSERT INTO public.projects (name, description, ssh_url, http_url, disabled) VALUES ('{0}', '{1}', '{2}', '{3}', '{4}')"
                    .format(gitlab_pj_name, args["description"],
                            gitlab_pj_ssh_url, gitlab_pj_http_url,
                            args["disabled"]))

                # 查詢寫入projects的project_id
                result = db.engine.execute(
                    "SELECT id FROM public.projects WHERE name = '{0}'".format(
                        gitlab_pj_name))
                project_id = result.fetchone()[0]
                result.close()

                # 加關聯project_plugin_relation
                db.engine.execute(
                    "INSERT INTO public.project_plugin_relation (project_id, plan_project_id, git_repository_id) VALUES ('{0}', '{1}', '{2}')"
                    .format(project_id, redmine_pj_id, gitlab_pj_id))

                # 加關聯project_user_role
                # db.engine.execute(
                #     "INSERT INTO public.project_user_role (project_id, user_id, role_id) VALUES ('{0}', '{1}', '{2}')"
                #     .format(project_id, user_id, 3))

                args["user_id"] = user_id
                output = self.au.project_add_member(logger, app, project_id,
                                                 args)
                logger.info("project add member output: {0}".format(output))
                print(output)

                return {
                    "message": "success",
                    "data": {
                        "project_id": project_id,
                        "plan_project_id": redmine_pj_id,
                        "git_repository_id": gitlab_pj_id
                    }
                }, 200

            else:
                error_code = gitlab_output.status_code
                return {
                    "message": {
                        "gitlab": {
                            "errors": gitlab_output.json()
                        }
                    }
                }, error_code

        else:
            error_code = redmine_output.status_code
            return {
                "message": {
                    "redmine": {
                        "errors": redmine_output.json()
                    }
                }
            }, error_code

    # 用project_id查詢db的相關table欄位資訊
    def pm_get_project(self, logger, app, project_id):
        # 查詢專案名稱＆專案說明＆＆專案狀態
        result = db.engine.execute(
            "SELECT * FROM public.projects as pj, public.project_plugin_relation as ppr\
                WHERE pj.id = '{0}' AND pj.id = ppr.project_id".format(
                project_id))
        project_info = result.fetchone()
        result.close()
        redmine_url = "http://{0}/projects/{1}".format(app.config["REDMINE_IP_PORT"], plan_project_id)
        output = {
            "project_id": project_info["project_id"],
            "name": project_info["name"],
            "description": project_info["description"],
            "disabled": project_info["disabled"],
            "git_url": project_info["http_url"],
            "redmine_url": redmine_url,
            "ssh_url": project_info["ssh_url"],
            "repository_id": project_info["git_repository_id"],
        }
        # 查詢專案負責人
        result = db.engine.execute(
            "SELECT user_id FROM public.project_user_role WHERE project_id = '{0}' AND role_id = '{1}'"
            .format(project_id, 3))
        user_id = result.fetchone()[0]
        result.close()

        result = db.engine.execute(
            "SELECT name FROM public.user WHERE id = '{0}'".format(user_id))
        user_name = result.fetchone()[0]
        result.close()
        output["pm_user_id"] = user_id
        output["pm_user_name"] = user_name

        return {"message": "success", "data": output}, 200

    # 修改redmine & gitlab的project資訊
    def pm_update_project(self, logger, app, project_id, args):
        result = db.engine.execute(
            "SELECT * FROM public.project_plugin_relation WHERE project_id = '{0}'"
            .format(project_id))
        project_relation = result.fetchone()
        result.close()

        redmine_project_id = project_relation["plan_project_id"]
        gitlab_project_id = project_relation["git_repository_id"]

        if args["name"] == None:
            result = db.engine.execute(
                "SELECT name FROM public.projects WHERE id = '{0}'".format(
                    project_id))
            args["name"] = result.fetchone()[0]
            result.close()
        if args["description"] == None:
            result = db.engine.execute(
                "SELECT description FROM public.projects WHERE id = '{0}'".
                format(project_id))
            args["description"] = result.fetchone()[0]
            result.close()

        # 更新gitlab project
        gitlab_url = "http://{0}/api/{1}/projects/{2}?private_token={3}&name={4}&description={5}".format(\
            app.config["GITLAB_IP_PORT"], app.config["GITLAB_API_VERSION"], gitlab_project_id, self.private_token, args["name"], args["description"])
        logger.info("update gitlab project url: {0}".format(gitlab_url))
        gitlab_output = requests.put(gitlab_url,
                                     headers=self.headers,
                                     verify=False)
        logger.info("update gitlab project output: {0} / {1}".format(
            gitlab_output, gitlab_output.json()))

        # 更新redmine project
        if gitlab_output.status_code == 200:
            redmine_url = "http://{0}/projects/{1}.json?key={2}".format(\
                app.config["REDMINE_IP_PORT"], redmine_project_id, app.config["REDMINE_API_KEY"])
            logger.info("update redmine project url: {0}".format(redmine_url))
            xml_body = """<?xml version="1.0" encoding="UTF-8"?>\
                    <project>\
                    <name>{0}</name>\
                    <description>{1}</description>\
                    </project>""".format(args["name"], args["description"])
            logger.info("update redmine project body: {0}".format(xml_body))
            headers = {'Content-Type': 'application/xml'}
            redmine_output = requests.put(redmine_url,
                                          headers=headers,
                                          data=xml_body,
                                          verify=False)
            logger.info(
                "update redmine project output: {0}".format(redmine_output))

            # 修改db
            if redmine_output.status_code == 204:
                # 修改projects
                if args["name"] != None:
                    db.engine.execute(
                        "UPDATE public.projects SET name = '{0}' WHERE id = '{1}'"
                        .format(args["name"], project_id))
                if args["description"] != None:
                    db.engine.execute(
                        "UPDATE public.projects SET description = '{0}' WHERE id = '{1}'"
                        .format(args["description"], project_id))
                if args["disabled"] != None:
                    db.engine.execute(
                        "UPDATE public.projects SET disabled = '{0}' WHERE id = '{1}'"
                        .format(args["disabled"], project_id))

                # 修改project_user_role
                if args["user_id"] != None:
                    db.engine.execute(
                        "UPDATE public.project_user_role SET user_id = '{0}' WHERE project_id = '{1}' AND role_id = '{2}'"
                        .format(args["user_id"], project_id, 3))

                return {
                    "message": "success",
                    "data": {
                        "result": "success update"
                    }
                }, 200

            else:
                error_code = redmine_output.status_code
                return {
                    "message": {
                        "redmine": {
                            "errors": redmine_output.json()
                        }
                    }
                }, error_code

        else:
            error_code = gitlab_output.status_code
            return {
                "message": {
                    "gitlab": {
                        "errors": gitlab_output.json()
                    }
                }
            }, error_code

    # 用project_id刪除redmine & gitlab的project並將db的相關table欄位一併刪除
    def pm_delete_project(self, logger, app, project_id):
        # 取得gitlab & redmine project_id
        result = db.engine.execute(
            "SELECT * FROM public.project_plugin_relation WHERE project_id = '{0}'"
            .format(project_id))
        project_relation = result.fetchone()
        result.close()
        if project_relation is not None:
            redmine_project_id = project_relation["plan_project_id"]
            gitlab_project_id = project_relation["git_repository_id"]
            # 刪除gitlab project
            gitlab_url = "http://{0}/api/{1}/projects/{2}?private_token={3}".format(\
                app.config["GITLAB_IP_PORT"], app.config["GITLAB_API_VERSION"], gitlab_project_id, self.private_token)
            logger.info("delete gitlab project url: {0}".format(gitlab_url))
            gitlab_output = requests.delete(gitlab_url,
                                            headers=self.headers,
                                            verify=False)
            logger.info("delete gitlab project output: {0} / {1}".format(
                gitlab_output, gitlab_output.json()))
            # 如果gitlab project成功被刪除則繼續刪除redmine project
            if gitlab_output.status_code == 202:
                redmine_url = "http://{0}/projects/{1}.json?key={2}".format(\
                    app.config["REDMINE_IP_PORT"], redmine_project_id, app.config["REDMINE_API_KEY"])
                logger.info(
                    "delete redmine project url: {0}".format(redmine_url))
                redmine_output = requests.delete(redmine_url,
                                                 headers=self.headers,
                                                 verify=False)
                logger.info("delete redmine project output: {0}".format(
                    redmine_output))
                # 如果gitlab & redmine project都成功被刪除則繼續刪除db內相關tables欄位
                if redmine_output.status_code == 204:
                    db.engine.execute(
                        "DELETE FROM public.project_plugin_relation WHERE project_id = '{0}'"
                        .format(project_id))
                    db.engine.execute(
                        "DELETE FROM public.project_user_role WHERE project_id = '{0}'"
                        .format(project_id))
                    db.engine.execute(
                        "DELETE FROM public.projects WHERE id = '{0}'".format(
                            project_id))

                    return {
                        "message": "success",
                        "data": {
                            "result": "success delete"
                        }
                    }, 200

                else:
                    error_code = redmine_output.status_code
                    return {
                        "message": {
                            "redmine": {
                                "errors": redmine_output.json()
                            }
                        }
                    }, error_code

            else:
                error_code = redmine_output.status_code
                return {
                    "message": {
                        "gitlab": {
                            "errors": gitlab_output.json()
                        }
                    }
                }, error_code
        else:
            return {"message": "can not find this project."}

        # db.engine.execute(
        #     "UPDATE public.projects SET disabled = '{0}' WHERE id = '{1}'".
        #     format(True, project_id))

        # output = {"result": "success delete"}

    def get_git_project_id(self, logger, app, repository_id):
        result = db.engine.execute(
            "SELECT project_id FROM public.project_plugin_relation WHERE git_repository_id = '{0}'"
            .format(repository_id))
        project_relation = result.fetchone()
        result.close()
        if project_relation:
            project_id = project_relation['project_id']
            return {"message": "success", "data": project_id}, 200
        else:
            return {
                "message": "error",
                "data": "No such repository_id found!"
            }, 404

    def get_project_info(self, logger, project_id):
        select_project_cmd = db.select([TableProjects.stru_projects])\
            .where(db.and_(TableProjects.stru_projects.c.id==project_id ))
        reMessage = util.callsqlalchemy(select_project_cmd,
                                        logger).fetchone()
        return reMessage

    def get_sonar_report(self, logger, app, project_id):
        result = db.engine.execute(
            "SELECT name FROM public.projects WHERE id = '{0}'".format(
                project_id))
        project_name = result.fetchone()[0]
        result.close()
        # project_name = "devops-flask"
        url = "http://{0}/api/measures/component?component={1}&metricKeys=bugs,vulnerabilities,security_hotspots,code_smells,coverage,duplicated_blocks,sqale_index,duplicated_lines_density,reliability_rating,security_rating,security_review_rating,sqale_rating,security_hotspots_reviewed,lines_to_cover".format(\
            app.config["SONAR_IP_PORT"], project_name)
        logger.info("get sonar report url: {0}".format(url))
        output = requests.get(url, headers=self.headers, verify=False)
        logger.info("get sonar report output: {0} / {1}".format(
            output, output.json()))
        if output.status_code == 200:
            data_list = output.json()["component"]["measures"]
            reliability = []
            security = []
            security_review = []
            maintainability = []
            coverage = []
            duplications = []

            for data in data_list:
                if data["metric"] == "bugs":
                    reliability.append({
                        "metric": "Bugs",
                        "value": data["value"]
                    })
                if data["metric"] == "reliability_rating":
                    reliability.append({
                        "metric": "Rating",
                        "value": data["value"]
                    })

                if data["metric"] == "vulnerabilities":
                    security.append({
                        "metric": "Vulnerabilities",
                        "value": data["value"]
                    })
                if data["metric"] == "security_rating":
                    security.append({
                        "metric": "Rating",
                        "value": data["value"]
                    })

                if data["metric"] == "security_hotspots":
                    security_review.append({
                        "metric": "Security Hotspots",
                        "value": data["value"]
                    })
                if data["metric"] == "security_hotspots_reviewed":
                    security_review.append({
                        "metric": "Reviewed",
                        "value": data["value"]
                    })
                if data["metric"] == "security_review_rating":
                    security_review.append({
                        "metric": "Rating",
                        "value": data["value"]
                    })

                if data["metric"] == "sqale_index":
                    maintainability.append({
                        "metric": "Debt",
                        "value": data["value"]
                    })
                if data["metric"] == "code_smells":
                    maintainability.append({
                        "metric": "Code Smells",
                        "value": data["value"]
                    })
                if data["metric"] == "sqale_rating":
                    maintainability.append({
                        "metric": "Rating",
                        "value": data["value"]
                    })

                if data["metric"] == "coverage":
                    coverage.append({
                        "metric": "Coverage",
                        "value": data["value"]
                    })
                if data["metric"] == "lines_to_cover":
                    coverage.append({
                        "metric": "Lines to cover",
                        "value": data["value"]
                    })

                if data["metric"] == "duplicated_lines_density":
                    duplications.append({
                        "metric": "Duplications",
                        "value": data["value"]
                    })
                if data["metric"] == "duplicated_blocks":
                    duplications.append({
                        "metric": "Duplicated Blocks",
                        "value": data["value"]
                    })

            return {
                "message": "success",
                "data": {
                    "Reliability": reliability,
                    "Security": security,
                    "Security Review": security_review,
                    "Maintainability": maintainability,
                    "Coverage": coverage,
                    "Duplications": duplications
                }
            }, 200
        else:
            error_msg_list = []
            for error in output.json()["errors"]:
                error_msg_list.append(error["msg"])
            return {"message": {"errors": error_msg_list}}, output.status_code

    def get_test_summary(self, logger, app, project_id, cm):
        ret = {}

        # newman
        cursor = db.engine.execute(
            'SELECT total, fail FROM public.test_results '
            ' WHERE project_id={0}'
            ' ORDER BY run_at DESC'
            ' LIMIT 1'
            .format(project_id))
        if cursor.rowcount > 0:
            row = cursor.fetchone()
            total = row['total']
            fail = row['fail']
            passed = total - fail
            ret['postman'] = {
                "passed": passed,
                "failed": fail,
                "total": total
            }
        else:
            ret['postman'] = {}

        # checkmarx
        scan_id = cm.get_latest('scan_id', project_id)
        if scan_id > 0:
            stats = cm.get_scan_statistics(scan_id)
            ret['checkmarx'] = {
                'high': stats['highSeverity'],
                'medium': stats['mediumSeverity'],
                'low': stats['lowSeverity'],
                'info': stats['infoSeverity']
            }
        else:
            ret['checkmarx'] = {}

        # sonarqube
        # qube = self.get_sonar_report(logger, app, project_id)
        # FIXME: Fill qube values after connected
        ret["sonarqube"] = {
            "bug": 1,
            "security": 1,
            "security_review": 1,
            "maintainability": 1
        }

        return {'message': 'success', 'data': {'test_results': ret}}, 200
