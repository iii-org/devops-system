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
            issue_to_plan[issue['issue_id']] = issue['plan_issue_id']
            plan_to_issue[issue['plan_issue_id']] = issue['issue_id']
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
        output = Redmine.redmine_get_issue(self, logger, app, issue_to_plan[issue_id]).json()
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
            output['issue']['parent_id'] = plan_to_issue[output['issue']['parent']['id']]
            output['issue'].pop('parent', None)
        logger.info("redmine issue output: {0}".format(output['issue']))
        return output['issue']
    '''
    def update_issue_rd(self, logger, issue_id, args):
        args = {k: v for k, v in args.items() if v is not None}
        logger.info("args: {0}".format(args))
        issue_to_plan, plan_to_issue = self.__get_dict_issueid(logger)
    '''
        
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

    def get_issue_priority(self, logger):
        try:
            result = db.engine.execute("SELECT id, name, is_closed FROM public.priorities")
            issue_priority_list_sql_output = result.fetchall()
            result.close()
            logger.info("issue_priority_list_sql_output: {0}".format(issue_priority_list_sql_output))
            issue_priority_list = []
            for issue_priority_sql_output in issue_priority_list_sql_output:
                issue_priority_list.append({
                    'id': issue_priority_sql_output['id'],
                    'name': issue_priority_sql_output['name'],
                    'is_closed': issue_priority_sql_output['is_closed']
                })
            return issue_priority_list, 200
        except Exception as error:
            return str(error), 400

    def get_issue_category(self, logger):
        try:
            result = db.engine.execute("SELECT id, name, is_closed FROM public.trackers")
            issue_tracker_list_sql_output = result.fetchall()
            result.close()
            logger.info("issue_tracker_list_sql_output: {0}".format(issue_tracker_list_sql_output))
            issue_tracker_list = []
            for issue_tracker_sql_output in issue_tracker_list_sql_output:
                issue_tracker_list.append({
                    'id': issue_tracker_sql_output['id'],
                    'name': issue_tracker_sql_output['name'],
                    'is_closed': issue_tracker_sql_output['is_closed']
                })
            return issue_tracker_list, 200
        except Exception as error:
            return str(error), 400

    def get_issue_category_by_project(self, logger, project_id):
        try:
            result = db.engine.execute("SELECT id, name, is_closed FROM public.trackers \
                WHERE project_id = {0}".format(project_id))
            issue_tracker_list_sql_output = result.fetchall()
            result.close()
            logger.info("issue_tracker_list_sql_output: {0}".format(issue_tracker_list_sql_output))
            issue_tracker_list = []
            for issue_tracker_sql_output in issue_tracker_list_sql_output:
                issue_tracker_list.append({
                    'id': issue_tracker_sql_output['id'],
                    'name': issue_tracker_sql_output['name'],
                    'is_closed': issue_tracker_sql_output['is_closed']
                })
            return issue_tracker_list, 200
        except Exception as error:
            return str(error), 400
