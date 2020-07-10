from model import db
from .util import util
from .redmine import Redmine

class Issue(object):
    headers = {'Content-Type': 'application/json'}

    def __init__(self):
        pass

    def __get_dict_issueid(self, logger):
        result = db.engine.execute("SELECT issue_id, plan_issue_id FROM public.issue_plugin_relation")
        issue_id_output = result.fetchall()
        result.close()
        issue_to_plan = {}
        plan_to_issue = {}
        for issue in  issue_id_output:
            issue_to_plan[str(issue['issue_id'])] = issue['plan_issue_id']
            plan_to_issue[str(issue['plan_issue_id'])] = issue['issue_id']
        logger.debug("issue_to_plan: {0}".format(issue_to_plan))
        logger.debug("plan_to_issue: {0}".format(plan_to_issue))
        return issue_to_plan, plan_to_issue

    def __get_dict_userid(self, logger):
        result = db.engine.execute("SELECT user_id, plan_user_id FROM public.user_plugin_relation")
        user_id_output = result.fetchall()
        result.close()
        user_to_plan = {}
        plan_to_user = {}
        for user in  user_id_output:
            user_to_plan[str(user['user_id'])] = user['plan_user_id']
            plan_to_user[str(user['plan_user_id'])] = user['user_id']
        logger.debug("user_to_plan: {0}".format(user_to_plan))
        logger.debug("plan_to_user: {0}".format(plan_to_user))
        return user_to_plan, plan_to_user
    
    def __dealwith_issue_redmine_output(self, logger, redmine_output, plan_to_issue):
        logger.info("redmine get redmine_output: {0}".format(redmine_output))
        redmine_output['project']['id'] = plan_to_issue[str(redmine_output['id'])]
        if 'assigned_to' in redmine_output:
            redmine_output['author'] = redmine_output['assigned_to']
            redmine_output.pop('assigned_to', None)
        redmine_output.pop('is_private', None)
        redmine_output.pop('estimated_hours', None)
        redmine_output.pop('total_estimated_hours', None)
        redmine_output.pop('spent_hours', None)
        redmine_output.pop('total_spent_hours', None)
        if 'created_on' in redmine_output:
            redmine_output['created_date'] = redmine_output.pop('created_on')
        if 'updated_on' in redmine_output:
            redmine_output['updated_date'] = redmine_output.pop('updated_on')
        redmine_output.pop('closed_on', None)
        if 'parent' in redmine_output:
            redmine_output['parent_id'] = plan_to_issue[str(redmine_output['parent']['id'])]
            redmine_output.pop('parent', None)
        logger.info("redmine issue redmine_output: {0}".format(redmine_output))
        return redmine_output

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

    def get_issue_rd(self, logger, app, issue_id):
        issue_to_plan, plan_to_issue = self.__get_dict_issueid(logger)
        Redmine.get_redmine_key(self, logger, app)
        logger.info("self.redmine_key: {0}".format(self.redmine_key))
        redmine_output_issue = Redmine.redmine_get_issue(self, logger, app, issue_to_plan[str(issue_id)]).json()
        output = self.__dealwith_issue_redmine_output(logger, redmine_output_issue['issue'], plan_to_issue)
        return output
    
    def get_issue_by_user(self, logger, app, user_id):
        user_to_plan, plan_to_user = self.__get_dict_userid(logger)
        issue_to_plan, plan_to_issue = self.__get_dict_issueid(logger)
        Redmine.get_redmine_key(self, logger, app)
        logger.info("self.redmine_key: {0}".format(self.redmine_key))
        output_array=[]
        redmine_output_issue_array= Redmine.redmine_get_issues_by_user(self, logger, app, user_to_plan[str(user_id)])
        for redmine_issue in redmine_output_issue_array['issues']:
            output = self.__dealwith_issue_redmine_output(logger, redmine_issue, plan_to_issue)
            output_array.append(output)
        return output_array
        

    def update_issue_rd(self, logger, app, issue_id, args):
        args = {k: v for k, v in args.items() if v is not None}
        if 'parent_id' in args:
            args['parent_issue_id'] = args['parent_id']
            args.pop('parent_id', None)
        logger.info("args: {0}".format(args))
        issue_to_plan, plan_to_issue = self.__get_dict_issueid(logger)
        Redmine.get_redmine_key(self, logger, app)
        try:
            output = Redmine.redmine_update_issue(self, logger, app, issue_to_plan[str(issue_id)], args)
        except Exception as error:
            return str(error), 400

        
    def get_issue_status(self, logger, app):
        Redmine.get_redmine_key(self, logger, app)
        try:
            issus_status_output = Redmine.redmine_get_issue_status(self, logger, app)
            return issus_status_output['issue_statuses']
        except Exception as error:
            return str(error), 400

    def get_issue_priority(self, logger, app):
        Redmine.get_redmine_key(self, logger, app)
        try:
            output=[]
            issus_status_output = Redmine.redmine_get_priority(self, logger, app)
            for issus_status in issus_status_output['issue_priorities']:
                issus_status.pop('is_default', None)
                if issus_status['active'] is True:
                    issus_status["is_closed"] = False
                else:
                    issus_status["is_closed"] = True
                issus_status.pop('active', None)
                output.append(issus_status)
            return output
        except Exception as error:
            return str(error), 400


    def get_issue_trackers(self, logger, app):
        Redmine.get_redmine_key(self, logger, app)
        output = []
        try:
            redmine_trackers_output = Redmine.redmine_get_trackers(self, logger, app)
            for redmine_tracker in redmine_trackers_output['trackers']:
                redmine_tracker.pop('default_status', None)
                redmine_tracker.pop('description', None)
                output.append(redmine_tracker)
            return output
        except Exception as error:
            return str(error), 400
        
    def count_prioriry_number_by_issues(self, logger, app, user_id):
        try:
            priority_count = {}
            issues = self.get_issue_by_user(logger, app, user_id)
            logger.info("issues: {0}".format(issues))
            for issue in issues:
                if issue['priority']['name'] not in priority_count:
                    priority_count[issue['priority']['name']] = 1
                else:
                    priority_count[issue['priority']['name']] += 1
            logger.info("priority_count: {0}".format(priority_count))
            output = []
            for key,value in priority_count.items():
                output.append({'name': key, 'number': value})
            return output
        except Exception as error:
            return str(error), 400

    def count_project_number_by_issues(self, logger, app, user_id):
        try:
            project_count = {}
            issues = self.get_issue_by_user(logger, app, user_id)
            logger.info("issues: {0}".format(issues))
            for issue in issues:
                if issue['project']['name'] not in project_count:
                    project_count[issue['project']['name']] = 1
                else:
                    project_count[issue['project']['name']] += 1
            logger.info("project_count: {0}".format(project_count))
            output = []
            for key,value in project_count.items():
                output.append({'name': key, 'number': value})
            return output
        except Exception as error:
            return str(error), 400

    def count_type_number_by_issues(self, logger, app, user_id):
        try:
            tracker_count = {}
            issues = self.get_issue_by_user(logger, app, user_id)
            logger.info("issues: {0}".format(issues))
            for issue in issues:
                if issue['tracker']['name'] not in tracker_count:
                    tracker_count[issue['tracker']['name']] = 1
                else:
                    tracker_count[issue['tracker']['name']] += 1
            logger.info("tracker_count: {0}".format(tracker_count))
            output = []
            for key,value in tracker_count.items():
                output.append({'name': key, 'number': value})
            return output
        except Exception as error:
            return str(error), 400
