import requests
import json
from model import db, Project_relationship


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

    def get_user_id(self, logger, app, user_account):
        
        url = "http://{0}/users.json?key={1}".format(app.config['REDMINE_IP_PORT']\
            , self.redmine_key)
        output = requests.get(url, headers=self.headers, verify=False)
        for user in output.json()["users"]:
            if user["login"] == user_account:
                logger.info("user {0} detail: {1}".format(user_account, user))
                return user

    def get_issues_by_user(self, logger, app, user_account):
        user_info = self.get_user_id(logger, app, user_account)

        url = "http://{0}/issues.json?key={1}&assigned_to_id={2}".format(\
            app.config['REDMINE_IP_PORT'], self.redmine_key, user_info["id"])
        output = requests.get(url, headers=self.headers, verify=False)
        logger.info("get issues by output: {0}".format(output.json()))
        return output

    def get_issue(self, logger, app, issue_id ):
        url = "http://{0}/issues/{1}.json?key={2}".format(\
            app.config['REDMINE_IP_PORT'], issue_id, self.redmine_key)
        output = requests.get(url, headers=self.headers, verify=False)
        logger.info("get issues output: {0}".format(output.json()))
        return output

    
    def update_issue(self, logger, app, issue_id, args):
        url = "http://{0}/issues/{1}.json?key={2}".format(\
            app.config['REDMINE_IP_PORT'], issue_id, self.redmine_key)
        param = {
            "issue": {
                "status_id": args["status_id"],
                "done_ratio": args["done_ratio"],
                "notes": args["notes"]
            }
        }
        logger.info("update issues param: {0}".format(param))
        output = requests.put(url, data=json.dumps(param), headers=self.headers, verify=False)
        logger.info("update issues output: {0}".format(output))
        return output

    
    def get_issue_status(self, logger, app):
        url="http://{0}/issue_statuses.json?key={1}".format(\
            app.config['REDMINE_IP_PORT'], self.redmine_key,)
        output = requests.get(url, headers=self.headers, verify=False)
        logger.info("get issues stauts list output: {0}".format(output.json()))
        return output
        
    def get_project(self, logger, app, user_account):
        user_info = self.get_user_id(logger, app, user_account)

        url = "http://{0}/users/{1}.json?include=memberships&key={2}".format(
            app.config['REDMINE_IP_PORT'], user_info["id"], self.redmine_key
        )
        output = requests.get(url, headers=self.headers, verify=False)
        logger.info("get issues output: {0}".format(output))
        return output
    
    def create_data_into_project_relationship(self, logger):
        # 示範function，示範如何CRUD Table
        # Create data
        project1 = Project_relationship(rm_project_id=1, rm_project_name="project1", \
            gl_project_id=1, gl_project_name="project1",\
                ran_project_id=1, ran_project_name="project1")
        db.session.add(project1)
        db.session.commit()
        # Read data
        oneData = Project_relationship.query.first()
        logger.info("Check db data: {0}".format(oneData.rm_project_name))
        # Update data
        oneData = Project_relationship.query.first()
        oneData.rm_project_name = "project2_update"
        db.session.commit()
        logger.info("Check db data: {0}".format(Project_relationship.query.first().rm_project_name))
        # Delete data
        logger.info("before delete table data number: {0}".format(Project_relationship.query.count()))
        firstData = Project_relationship.query.first()
        db.session.delete(firstData)
        db.session.commit()
        logger.info("after delete table data number: {0}".format(Project_relationship.query.count()))

    def get_issuesId_List(self, logger, project_id):
        result = db.engine.execute("SELECT id FROM public.issues WHERE project_id = {0}\
            ".format(project_id))
        issuesid_sql_output_list = result.fetchall()
        result.close()
        #logger.info("issuesid_list: {0}".format(issuesid_sql_output_list))
        output_array= []
        if issuesid_sql_output_list is not None:
            for issuesid_sql_output in issuesid_sql_output_list:
                logger.info("issuesid_list: {0}".format(issuesid_sql_output[0]))
                output_array.append(issuesid_sql_output[0])
            return output_array




