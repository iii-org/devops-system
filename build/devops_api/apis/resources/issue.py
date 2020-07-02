from model import db, Project_relationship
from .util import util


class Issue(object):
    
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
