import requests
import json

from model import db, Project_relationship
from .util import util


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

    def redmine_get_user_id(self, logger, app, user_account):
        
        url = "http://{0}/users.json?key={1}".format(app.config['REDMINE_IP_PORT']\
            , self.redmine_key)
        output = requests.get(url, headers=self.headers, verify=False)
        for user in output.json()["users"]:
            if user["login"] == user_account:
                logger.info("user {0} detail: {1}".format(user_account, user))
                return user

    def redmine_get_issues_by_user(self, logger, app, user_account):
        user_info = self.redmine_get_user_id(logger, app, user_account)

        url = "http://{0}/issues.json?key={1}&assigned_to_id={2}".format(\
            app.config['REDMINE_IP_PORT'], self.redmine_key, user_info["id"])
        output = requests.get(url, headers=self.headers, verify=False)
        logger.info("get issues by output: {0}".format(output.json()))
        return output

    def redmine_get_issue(self, logger, app, issue_id ):
        url = "http://{0}/issues/{1}.json?key={2}".format(\
            app.config['REDMINE_IP_PORT'], issue_id, self.redmine_key)
        output = requests.get(url, headers=self.headers, verify=False)
        logger.info("get issues output: {0}".format(output.json()))
        return output

    
    def redmine_update_issue(self, logger, app, issue_id, args):
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

    
    def redmine_get_issue_status(self, logger, app):
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

    def get_issue_rd(self, logger, issue_id):
        result = db.engine.execute("SELECT iss.project_id as pjid, pjt.name as pjnm, iss.tracker_id as trid, trk.name as trnm, \
            iss.status_id as stid, sta.name as stnm, iss.priority_id as prid, pri.name as prnm, iss.description as desc, \
                iss.author_id as auid, ur.name as aunm, iss.name as isnm, iss.start_date as stda, iss.due_date as duda, \
                    iss.done_ratio as rati, iss.create_at as crti, iss.update_at as upti\
            FROM public.issues as iss, public.projects as pjt, public.trackers as trk, \
                public.statuses as sta, public.priorities as pri, public.user as ur\
            WHERE iss.id = {0} AND iss.project_id = pjt.id AND iss.status_id = sta.id AND iss.tracker_id = trk.id \
                AND iss.priority_id = pri.id AND iss.author_id = ur.id".format(issue_id))
        issue_info_sql_output = result.fetchone()
        result.close()
        logger.info("issuesid_list: {0}".format(issue_info_sql_output))
        result = db.engine.execute("SELECT issue_parent_id FROM public.issue_parent_child WHERE issue_child_id = {0}\
            ".format(issue_id))
        issues_parent_child_sql_output = result.fetchone()
        result.close()
        logger.info("issues_parent_child_sql_output: {0}".format(issues_parent_child_sql_output))
        output = {"id":issue_id,"project":{"id":issue_info_sql_output["pjid"],"name":issue_info_sql_output["pjnm"]},\
            "tracker":{"id":issue_info_sql_output['trid'],"name":issue_info_sql_output['trnm']},"status":{"id":issue_info_sql_output['stid'],\
            "name":issue_info_sql_output['stnm']},"priority":{"id":issue_info_sql_output['prid'],"name":issue_info_sql_output['prnm']},\
            "description":issue_info_sql_output['desc'],"author":{"id":issue_info_sql_output['auid'],"name":issue_info_sql_output['aunm']},\
            "parent_id":util.fetchone_output(issues_parent_child_sql_output),"subject":issue_info_sql_output['isnm'],\
            "start_date":util.add_iso_format(issue_info_sql_output['stda']),"due_date":util.add_iso_format(issue_info_sql_output['duda']),"done_ratio":issue_info_sql_output['rati'],\
            "created_date":util.add_iso_format(issue_info_sql_output['crti']),"updated_date":util.add_iso_format(issue_info_sql_output['upti']),"custom_fields":[]}
        logger.info("json output: {0}".format(output))
        return output
    
    def update_issue_rd(self, logger, issue_id, args):
        set_string = ""
        if args["tracker"] is not None:
            set_string += "tracker_id = {0}".format(args["tracker"])
            set_string += ","
        if args["status"] is not None:
            set_string += "status_id = {0}".format(args["status"])
            set_string += ","
        logger.info("set_string[:-1]: {0}".format(set_string[:-1]))
        try:
            result = db.engine.execute("UPDATE public.issues SET {0} WHERE id = {1}".format(set_string[:-1], issue_id))
            return None, 200
        except Exception as error:
            return str(error), 400

    def get_issue_status(self, logger):
        try:
            result = db.engine.execute("SELECT * FROM public.statuses")
            issue_status_list_sql_output = result.fetchall()
            result.close()
            logger.info("issue_status_list_sql_output: {0}".format(issue_status_list_sql_output))
            issue_status_list = []
            for issue_status_sql_output in issue_status_list_sql_output:
                issue_status_list.append({
                    'id': issue_status_sql_output['id'],
                    'name': issue_status_sql_output['name'],
                    'is_closed': issue_status_sql_output['is_closed']
                })
            return issue_status_list, 200
        except Exception as error:
            return str(error), 400


