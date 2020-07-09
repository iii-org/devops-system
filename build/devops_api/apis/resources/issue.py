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
        output = Redmine.redmine_get_issue(self, logger, app, issue_to_plan[str(issue_id)]).json()
        logger.info("redmine get  output: {0}".format(output['issue']))
        output['issue']['project']['id'] = issue_id
        output['issue']['author'] = output['issue']['assigned_to']
        output['issue'].pop('assigned_to', None)
        output['issue'].pop('is_private', None)
        output['issue'].pop('estimated_hours', None)
        output['issue'].pop('total_estimated_hours', None)
        output['issue'].pop('spent_hours', None)
        output['issue'].pop('total_spent_hours', None)
        output['issue']['created_date'] = output['issue'].pop('created_on')
        output['issue']['updated_date'] = output['issue'].pop('updated_on')
        output['issue']['updated_date']
        output['issue'].pop('closed_on', None)
        if 'parent' in output['issue']:
            output['issue']['parent_id'] = plan_to_issue[str(output['issue']['parent']['id'])]
            output['issue'].pop('parent', None)
        logger.info("redmine issue output: {0}".format(output['issue']))
        return output['issue']

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
