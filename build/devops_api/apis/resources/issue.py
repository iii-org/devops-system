from model import db, Project_relationship
from .util import util
from .redmine import Redmine

class Issue(object):
    headers = {'Content-Type': 'application/json'}

    def __init__(self):
        pass

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

    def get_issue_rd(self, logger, app, issue_id):
        result = db.engine.execute("SELECT plan_issue_id FROM public.issue_plugin_relation \
            WHERE issue_id = {0}".format(issue_id))
        plan_issue_id_output = result.fetchone()[0]
        result.close()
        project_dict = {plan_issue_id_output: issue_id}
        logger.info("plan_issue_id_output: {0}".format(plan_issue_id_output))
        Redmine.get_redmine_key(self, logger, app)
        logger.info("self.redmine_key: {0}".format(self.redmine_key))
        output = Redmine.redmine_get_issue(self, logger, app, issue_id).json()
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
            result = db.engine.execute("SELECT issue_id FROM public.issue_plugin_relation \
                WHERE plan_issue_id = {0}".format(output['issue']['parent']['id']))
            parent_issue_id = result.fetchone()[0]
            result.close()
            output['issue']['parent_id'] = parent_issue_id
            output['issue'].pop('parent', None)
        logger.info("redmine issue output: {0}".format(output['issue']))
        return output['issue']
    
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
