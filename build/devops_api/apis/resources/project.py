import requests
import json
from datetime import datetime

from model import db
from .redmine import Redmine
from .rancher import Rancher

import urllib

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
    
    def get_project_by_plan_project_id(self, logger, app, plan_project_id):
        result = db.engine.execute("SELECT * FROM public.project_plugin_relation \
            WHERE plan_project_id = {0}".format(plan_project_id))
        project = result.fetchone()
        result.close()
        return project

    def get_project_list(self, logger, app, user_id):
        output_array = []
        result = db.engine.execute("SELECT pj.id, pj.name, ppl.plan_project_id, \
            ppl.git_repository_id, ppl.ci_project_id, ppl.ci_pipeline_id\
            FROM public.project_user_role as pur, public.projects as pj, public.project_plugin_relation as ppl\
            WHERE pur.user_id = {0} AND pur.project_id = pj.id AND pj.id = ppl.project_id; ".format(user_id))
        project_list = result.fetchall()
        result.close()

        # get user ids
        result = db.engine.execute("SELECT plan_user_id, repository_user_id \
            FROM public.user_plugin_relation WHERE user_id = {0}; ".format(user_id))
        plan_user_id = result.fetchone()[0]
        result.close()
        logger.info("get user_ids SQL: {0}".format(plan_user_id))
        redmine_key = Redmine.get_redmine_key(self, logger, app)
        for project in  project_list:
            output_dict = {}
            output_dict['name'] = project['name']
            output_dict['project_id'] = project['id']

            output_dict['repository_ids'] = [project['git_repository_id']]

            # get issue total cont
            total_issue = Redmine.redmine_get_issues_by_project_and_user(self, logger, app, \
                plan_user_id, project['plan_project_id'] ,redmine_key)
            logger.info("issue total count by user: {0}".format(total_issue['total_count']))
            output_dict['issues'] = total_issue['total_count']

            # get next_d_time
            issue_due_date_list = []
            for issue in total_issue['issues']:
                if issue['due_date'] is not None:
                    issue_due_date_list.append(datetime.strptime(issue['due_date'], "%Y-%m-%d"))
            logger.info("issue_due_date_list: {0}".format(issue_due_date_list))
            next_d_time = None
            if len(issue_due_date_list) != 0:
                next_d_time = min(issue_due_date_list, key=lambda d: abs(d - datetime.now()))
            logger.info("next_d_time: {0}".format(next_d_time))
            output_dict['next_d_time'] = next_d_time

            # branch bumber
            branch_number = 0
            output = self.get_git_project_branches(logger, app, project['git_repository_id'])
            logger.info("get_git_project_branches output: {0}".format(type(output.json())))
            if output.status_code == 200:
                branch_number = len(output.json())
            logger.info("get_git_project_branches number: {0}".format(branch_number))
            output_dict['branch'] = branch_number
            # tag nubmer
            tag_number = 0
            output = self.get_git_project_tags(logger, app, project['git_repository_id'])
            logger.info("get_git_project_tags output: {0}".format(type(output.json())))
            if output.status_code == 200:
                tag_number = len(output.json())
            logger.info("get_git_project_tags number: {0}".format(branch_number))
            output_dict['tag'] = tag_number

            output_dict = self.get_ci_last_test_result(app, logger, output_dict, project)
            output_array.append(output_dict)
        return output_array

    def get_ci_last_test_result(self, app, logger, output_dict, project):
        # get rancher pipeline
        output_dict['last_test_time'] = ""
        output_dict['last_test_result'] = {}
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

    # 用project_id及branch_name及file_path新增project的file
    def create_git_project_file(self, logger, app, project_id, args):
        url = "http://{0}/api/{1}/projects/{2}/repository/files/{3}?private_token={4}&branch={5}&start_branch={6}&encoding={7}&author_email={8}&author_name={9}&content={10}&commit_message={11}".format(\
            app.config["GITLAB_IP_PORT"], app.config["GITLAB_API_VERSION"], project_id, args["file_path"], self.private_token, args["branch"], args["start_branch"], args["encoding"], args["author_email"], args["author_name"], args["content"], args["commit_message"])
        logger.info("post project file url: {0}".format(url))
        output = requests.post(url, headers=self.headers, verify=False)
        logger.info("post project file output: {0}".format(output.json()))
        return output

    # 用project_id及branch_name及file_path修改project的file
    def update_git_project_file(self, logger, app, project_id, args):
        url = "http://{0}/api/{1}/projects/{2}/repository/files/{3}?private_token={4}&branch={5}&start_branch={6}&encoding={7}&author_email={8}&author_name={9}&content={10}&commit_message={11}".format(\
            app.config["GITLAB_IP_PORT"], app.config["GITLAB_API_VERSION"], project_id, args["file_path"], self.private_token, args["branch"], args["start_branch"], args["encoding"], args["author_email"], args["author_name"], args["content"], args["commit_message"])
        logger.info("put project file url: {0}".format(url))
        output = requests.put(url, headers=self.headers, verify=False)
        logger.info("put project file output: {0}".format(output))
        return output

    # 用project_id及branch_name及file_path刪除project的file
    def delete_git_project_file(self, logger, app, project_id, branch, file_path, args):
        url = "http://{0}/api/{1}/projects/{2}/repository/files/{3}?private_token={4}&branch={5}&commit_message={6}".format(\
            app.config["GITLAB_IP_PORT"], app.config["GITLAB_API_VERSION"], project_id, file_path, self.private_token, branch, args["commit_message"])
        logger.info("delete project file url: {0}".format(url))
        output = requests.delete(url, headers=self.headers, verify=False)
        logger.info("delete project file output: {0}".format(output))
        return output

    # 用project_id查詢project的tags
    def get_git_project_tags(self, logger, app, project_id):
        url = "http://{0}/api/{1}/projects/{2}/repository/tags?private_token={3}".format(\
            app.config["GITLAB_IP_PORT"], app.config["GITLAB_API_VERSION"], project_id, self.private_token)
        logger.info("get project tags url: {0}".format(url))
        output = requests.get(url, headers=self.headers, verify=False)
        logger.info("get project tags output: {0}".format(output.json()))
        return output

    # 用project_id新增project的tag
    def create_git_project_tags(self, logger, app, project_id, args):
        url = "http://{0}/api/{1}/projects/{2}/repository/tags?private_token={3}&tag_name={4}&ref={5}&message={6}&release_description={7}".format(\
            app.config["GITLAB_IP_PORT"], app.config["GITLAB_API_VERSION"], project_id, self.private_token, args["tag_name"], args["ref"], args["message"], args["release_description"])
        logger.info("create project tag url: {0}".format(url))
        output = requests.post(url, headers=self.headers, verify=False)
        logger.info("create project tag output: {0}".format(output.json()))
        return output

    # 用project_id及tag_name刪除project的tag
    def delete_git_project_tag(self, logger, app, project_id, tag_name):
        url = "http://{0}/api/{1}/projects/{2}/repository/tags/{3}?private_token={4}".format(\
            app.config["GITLAB_IP_PORT"], app.config["GITLAB_API_VERSION"], project_id, tag_name, self.private_token)
        logger.info("delete project tag url: {0}".format(url))
        output = requests.delete(url, headers=self.headers, verify=False)
        logger.info("delete project tag output: {0}".format(output))
        return output

    # 用project_id及directory_path新增project的directory
    def create_git_project_directory(self, logger, app, project_id, directory_path, args):
        url = "http://{0}/api/{1}/projects/{2}/repository/files/{3}?private_token={4}&branch={5}&commit_message={6}&content={7}".format(\
            app.config["GITLAB_IP_PORT"], app.config["GITLAB_API_VERSION"], project_id, directory_path, self.private_token, args["branch"], args["commit_message"], "")
        logger.info("create project directory url: {0}".format(url))
        output = requests.post(url, headers=self.headers, verify=False)
        logger.info("create project directory output: {0}".format(output.json()))
        return output

    # 用project_id及directory_path修改project的directory
    def update_git_project_directory(self, logger, app, project_id, directory_path, args):
        url = "http://{0}/api/{1}/projects/{2}/repository/files/{3}?private_token={4}&branch={5}&commit_message={6}&author_name={7}&author_email={8}&encoding={9}&content={10}".format(\
            app.config["GITLAB_IP_PORT"], app.config["GITLAB_API_VERSION"], project_id, directory_path, self.private_token, args["branch"], args["commit_message"], args["author_name"], args["author_email"], args["encoding"], args["content"])
        logger.info("update project directory url: {0}".format(url))
        output = requests.put(url, headers=self.headers, verify=False)
        logger.info("update project directory output: {0}".format(output.json()))
        return output

    # 用project_id及directory_path刪除project的directory
    def delete_git_project_directory(self, logger, app, project_id, directory_path, args):
        # 查詢directory的files
        url = "http://{0}/api/{1}/projects/{2}/repository/tree?private_token={3}&ref={4}&path={5}".format(\
            app.config["GITLAB_IP_PORT"], app.config["GITLAB_API_VERSION"], project_id, self.private_token, args["branch"], directory_path)
        logger.info("get project directoryfiles url: {0}".format(url))
        output1 = requests.get(url, headers=self.headers, verify=False)
        logger.info("get project directoryfiles output: {0} / {1}".format(output1, output1.json()))
        if str(output1) == "<Response [200]>":
            # 依序刪除directory的files
            for i in range(len(output1.json())):
                path_encode = urllib.parse.quote(output1.json()[i]["path"], safe='')
                url = "http://{0}/api/{1}/projects/{2}/repository/files/{3}?private_token={4}&branch={5}&commit_message={6}".format(\
                    app.config["GITLAB_IP_PORT"], app.config["GITLAB_API_VERSION"], project_id, path_encode, self.private_token, args["branch"], args["commit_message"])
                logger.info("delete project directory url: {0}".format(url))
                output2 = requests.delete(url, headers=self.headers, verify=False)
                logger.info("delete project directory output: {0}".format(output2))
        return output2

    # 用project_id合併project的任兩個branches
    def create_git_project_mergebranch(self, logger, app, project_id, args):
        # 新增merge request
        url = "http://{0}/api/{1}/projects/{2}/merge_requests?private_token={3}&source_branch={4}&target_branch={5}&title={6}".format(\
            app.config["GITLAB_IP_PORT"], app.config["GITLAB_API_VERSION"], project_id, self.private_token, args["source_branch"], args["target_branch"], args["title"])
        logger.info("post project mergerequest url: {0}".format(url))
        output = requests.post(url, headers=self.headers, verify=False)
        logger.info("post project mergerequest output:{0} / {1}".format(output, output.json()))
        
        if str(output) == "<Response [201]>":
            # 同意merge request
            merge_request_iid = output.json()["iid"]
            url = "http://{0}/api/{1}/projects/{2}/merge_requests/{3}/merge?private_token={4}".format(\
                app.config["GITLAB_IP_PORT"], app.config["GITLAB_API_VERSION"], project_id, merge_request_iid, self.private_token)
            logger.info("post project acceptmerge url: {0}".format(url))
            output = requests.put(url, headers=self.headers, verify=False)
            logger.info("post project acceptmerge output:{0} / {1}".format(output, output.json()))
            if str(output) != "<Response [200]>":
                # 刪除merge request
                url = "http://{0}/api/{1}/projects/{2}/merge_requests/{3}?private_token={4}".format(\
                    app.config["GITLAB_IP_PORT"], app.config["GITLAB_API_VERSION"], project_id, merge_request_iid, self.private_token)
                logger.info("delete project mergerequest url: {0}".format(url))
                output_extra = requests.delete(url, headers=self.headers, verify=False)
                logger.info("delete project mergerequest output:{0}".format(output_extra))                
    
        return output

    def create_ranhcer_pipline_yaml(self, logger, app, project_id, args, action):
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
        
    # 用project_id查詢project的commits
    def get_git_project_branch_commits(self, logger, app, project_id, args):
        url = "http://{0}/api/{1}/projects/{2}/repository/commits?private_token={3}&ref_name={4}&per_page=100".format(\
            app.config["GITLAB_IP_PORT"], app.config["GITLAB_API_VERSION"], project_id, self.private_token, args["branch"])
        logger.info("get project branch commits url: {0}".format(url))
        output = requests.get(url, headers=self.headers, verify=False)
        logger.info("get project branch commits output: {0}".format(output))
        return output