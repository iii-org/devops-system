from model import db, ProjectPluginRelation, ProjectUserRole
from .util import util
from .redmine import Redmine
from .project import Project
from .auth import auth

from flask import jsonify


class Issue(object):
    headers = {'Content-Type': 'application/json'}

    def __init__(self):
        pass

    def __get_dict_userid(self, logger):
        result = db.engine.execute(
            "SELECT user_id, plan_user_id FROM public.user_plugin_relation")
        user_id_output = result.fetchall()
        result.close()
        user_to_plan = {}
        plan_to_user = {}
        for user in user_id_output:
            user_to_plan[str(user['user_id'])] = user['plan_user_id']
            plan_to_user[str(user['plan_user_id'])] = user['user_id']
        logger.debug("user_to_plan: {0}".format(user_to_plan))
        logger.debug("plan_to_user: {0}".format(plan_to_user))
        return user_to_plan, plan_to_user

    def __dealwith_issue_redmine_output(self, logger, redmine_output):
        logger.info("redmine get redmine_output: {0}".format(redmine_output))
        prject_list = Project.get_project_by_plan_project_id\
            (self, logger, redmine_output['project']['id'])
        logger.info("redmine_output['project']['id']: {0}".format(
            prject_list['id']))
        redmine_output['project']['id'] = prject_list['id']
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
            redmine_output['parent_id'] = redmine_output['parent']['id']
            redmine_output.pop('parent', None)
        if 'journals' in redmine_output:
            for journal in redmine_output['journals']:
                journal.pop('id', None)
                journal.pop('private_notes', None)
        logger.info("redmine issue redmine_output: {0}".format(redmine_output))
        return redmine_output

    def __dealwith_issue_by_user_redmine_output(self, logger, redmine_output):
        output_list = {}
        output_list['id'] = redmine_output['id']
        output_list['name'] = redmine_output['project']['name']
        output_list['issue_category'] = redmine_output['tracker']['name']
        output_list['issue_priority'] = redmine_output['priority']['name']
        output_list['issue_status'] = redmine_output['status']['name']
        output_list['issue_name'] = redmine_output['subject']
        output_list['description'] = redmine_output['description']
        output_list['assigned_to'] = None
        if 'assigned_to' in redmine_output:
            output_list['assigned_to'] = redmine_output['assigned_to']['name']
        logger.info(
            "get issue by user redmine_output: {0}".format(output_list))
        return output_list

    def verify_issue_user(self, logger, app, issue_id, user_id):
        # base on issus get project
        issue_info = Issue.get_issue_rd(self, logger, app, issue_id)
        project_id = issue_info['project']['id']
        logger.info("issue_info: {0}".format(issue_info))
        select_project_user_role_command = db.select([ProjectUserRole.stru_project_user_role])\
            .where(db.and_(ProjectUserRole.stru_project_user_role.c.project_id==project_id, \
            ProjectUserRole.stru_project_user_role.c.user_id==user_id))
        logger.debug("select_project_user_role_command: {0}".format(
            select_project_user_role_command))
        reMessage = util.callsqlalchemy(self, select_project_user_role_command,
                                        logger)
        match_list = reMessage.fetchall()
        logger.info("reMessage: {0}".format(match_list))
        logger.info("reMessage len: {0}".format(len(match_list)))
        if len(match_list) > 0:
            return True
        else:
            return False

    def get_issue_rd(self, logger, app, issue_id):
        Redmine.get_redmine_key(self, logger, app)
        logger.info("self.redmine_key: {0}".format(self.redmine_key))
        redmine_output_issue = Redmine.redmine_get_issue(
            self, logger, app, issue_id)
        if redmine_output_issue.status_code == 200:
            output = self.__dealwith_issue_redmine_output(
                logger, redmine_output_issue.json()['issue'])
        else:
            output = {"message": "could not get this redmine issue."}, 400
        return output

    def get_issue_by_project(self, logger, app, project_id):
        # get plan_project_id, git_repository_id, ci_project_id, ci_pipeline_id
        get_project_command = db.select([ProjectPluginRelation.stru_project_plug_relation])\
        .where(db.and_(ProjectPluginRelation.stru_project_plug_relation.c.project_id==project_id))
        logger.debug("get_project_command: {0}".format(get_project_command))
        reMessage = util.callsqlalchemy(self, get_project_command, logger)
        project_dict = reMessage.fetchone()
        logger.debug("project_list: {0}".format(project_dict))
        if project_dict is not None:
            redmine_key = Redmine.get_redmine_key(self, logger, app)
            output_array = []
            redmine_output_issue_array = Redmine.redmine_get_issues_by_project(
                self, logger, app, project_dict['plan_project_id'], redmine_key)
            for redmine_issue in redmine_output_issue_array['issues']:
                output_dict = self.__dealwith_issue_by_user_redmine_output(
                    logger, redmine_issue)
                output_dict = Project.get_ci_last_test_result(
                    self, app, logger, output_dict, project_dict)
                output_array.append(output_dict)
            return {"message": "success", "data": output_array}, 200
        else:
            return {"message": "could not find this project"}, 400

    def get_issueProgress_by_project(self, logger, app, project_id):
        issue_list, status_code = self.get_issue_by_project(logger, app, project_id)
        logger.debug("issue_list: {0}, status_code: {1}".format(issue_list, status_code))
        if status_code == 200:
            unfinish_number = 0
            for issue in issue_list['data']:
                if issue["issue_status"] != "closed":
                    unfinish_number += 1
            return {
                "message": "success",
                "data": {
                    "unfinish_number": unfinish_number,
                    "total_issue": len(issue_list)
                }
            }
        else:
            return {"message": "could not get issue list"}, 400


    def get_issueStatistics_by_project(self, logger, app, project_id):
        issue_list, status_code = self.get_issue_by_project(logger, app, project_id)
        logger.debug("issue_list: {0}, status_code: {1}".format(issue_list, status_code))
        if status_code == 200:
            priority_list = {}
            category_list = {}
            owner_list = {}
            for issue in issue_list['data']:
                #count priority
                if issue["issue_priority"] not in priority_list:
                    if issue["issue_status"] != "closed":
                        priority_list[issue["issue_priority"]] = {
                            "unfinish": 1,
                            "finished": 0
                        }
                    else:
                        priority_list[issue["issue_priority"]] = {
                            "unfinish": 0,
                            "finished": 1
                        }
                else:
                    unfinish_value = priority_list[
                        issue["issue_priority"]]["unfinish"]
                    finish_value = priority_list[
                        issue["issue_priority"]]["finished"]
                    if issue["issue_status"] != "closed":
                        priority_list[issue["issue_priority"]] = {
                            "unfinish": unfinish_value + 1,
                            "finished": finish_value
                        }
                    else:
                        priority_list[issue["issue_priority"]] = {
                            "unfinish": unfinish_value,
                            "finished": finish_value + 1
                        }
                #count category
                if issue["issue_category"] not in category_list:
                    if issue["issue_status"] != "closed":
                        category_list[issue["issue_category"]] = {
                            "unfinish": 1,
                            "finished": 0
                        }
                    else:
                        category_list[issue["issue_category"]] = {
                            "unfinish": 0,
                            "finished": 1
                        }
                else:
                    unfinish_value = category_list[
                        issue["issue_category"]]["unfinish"]
                    finish_value = category_list[
                        issue["issue_category"]]["finished"]
                    if issue["issue_status"] != "closed":
                        category_list[issue["issue_category"]] = {
                            "unfinish": unfinish_value + 1,
                            "finished": finish_value
                        }
                    else:
                        category_list[issue["issue_category"]] = {
                            "unfinish": unfinish_value,
                            "finished": finish_value + 1
                        }
                #count owner
                if issue["assigned_to"] not in owner_list:
                    if issue["issue_status"] != "closed":
                        owner_list[issue["assigned_to"]] = {
                            "unfinish": 1,
                            "finished": 0
                        }
                    else:
                        owner_list[issue["assigned_to"]] = {
                            "unfinish": 0,
                            "finished": 1
                        }
                else:
                    unfinish_value = owner_list[issue["assigned_to"]]["unfinish"]
                    finish_value = owner_list[issue["assigned_to"]]["finished"]
                    if issue["issue_status"] != "closed":
                        owner_list[issue["assigned_to"]] = {
                            "unfinish": unfinish_value + 1,
                            "finished": finish_value
                        }
                    else:
                        owner_list[issue["assigned_to"]] = {
                            "unfinish": unfinish_value,
                            "finished": finish_value + 1
                        }
            logger.info("issue_list: {0}".format(priority_list))
            logger.info("category_list: {0}".format(category_list))
            logger.info("owner_list: {0}".format(owner_list))
            return {
                "message": "success",
                "data": {
                    "priority": priority_list,
                    "category": category_list,
                    "owner": owner_list
                }
            }, 200
        else:
            return {"message": "could not get issue list"}, 400

    def get_issue_by_user(self, logger, app, user_id):
        user_to_plan, plan_to_user = self.__get_dict_userid(logger)
        Redmine.get_redmine_key(self, logger, app)
        logger.info("self.redmine_key: {0}".format(self.redmine_key))
        output_array = []
        redmine_output_issue_array = Redmine.redmine_get_issues_by_user(
            self, logger, app, user_to_plan[str(user_id)])
        for redmine_issue in redmine_output_issue_array['issues']:
            output_dict = self.__dealwith_issue_by_user_redmine_output(
                logger, redmine_issue)
            project = Project.get_project_by_plan_project_id(
                self, logger, redmine_issue['project']['id'])
            logger.info("project: {0}".format(project))
            output_dict = Project.get_ci_last_test_result(
                self, app, logger, output_dict, project)
            output_array.append(output_dict)
        return output_array

    def create_issue(self, logger, app, args):
        args = {k: v for k, v in args.items() if v is not None}
        if 'parent_id' in args:
            args['parent_issue_id'] = args['parent_id']
            args.pop('parent_id', None)
        project_plugin_relation_array = Project.get_project_plugin_relation(
            self, logger)
        for project_plugin_relation in project_plugin_relation_array:
            if project_plugin_relation['project_id'] == args['project_id']:
                args['project_id'] = project_plugin_relation['plan_project_id']
        if "assigned_to_id" in args:
            user_plugin_relation_array = auth.get_user_plugin_relation(
                self, logger)
            for user_plugin_relation in user_plugin_relation_array:
                if user_plugin_relation['user_id'] == args['assigned_to_id']:
                    args['assigned_to_id'] = user_plugin_relation[
                        'plan_user_id']
        logger.info("args: {0}".format(args))
        Redmine.get_redmine_key(self, logger, app)
        try:
            output = Redmine.redmine_create_issue(self, logger, app, args)
            return {
                "message": "success",
                "data": {
                    "issue_id": output.json()["issue"]["id"]
                }
            }, output.status_code
        except Exception as error:
            return str(error), 400

    def update_issue_rd(self, logger, app, issue_id, args):
        args = {k: v for k, v in args.items() if v is not None}
        '''
        if "assigned_to_id" in args:
            user_plugin_relation_array = auth.get_user_plugin_relation(
                self, logger)
            for user_plugin_relation in user_plugin_relation_array:
                if user_plugin_relation['user_id'] == args['assigned_to_id']:
                    args['Assignee'] = user_plugin_relation[
                        'plan_user_id']
                    args.pop('assigned_to_id', None)
        '''
        if 'parent_id' in args:
            args['parent_issue_id'] = args['parent_id']
            args.pop('parent_id', None)
        logger.info("args: {0}".format(args))
        Redmine.get_redmine_key(self, logger, app)
        output, status_code = Redmine.redmine_update_issue(self, logger, app, issue_id,
                                                  args)
        if status_code == 204:
            return {"message": "success"}, 200
        else:
            return {"message": "update issue failed"}, 400

    def delete_issue(self, logger, app, issue_id):
        Redmine.get_redmine_key(self, logger, app)
        try:
            # go to redmine, delete issue
            output = Redmine.redmine_delete_issue(self, logger, app, issue_id)
            return {"message": "success"}, 201
        except Exception as error:
            return str(error), 400

    def get_issue_status(self, logger, app):
        Redmine.get_redmine_key(self, logger, app)
        try:
            issus_status_output = Redmine.redmine_get_issue_status(
                self, logger, app)
            return issus_status_output['issue_statuses']
        except Exception as error:
            return str(error), 400

    def get_issue_priority(self, logger, app):
        Redmine.get_redmine_key(self, logger, app)
        try:
            output = []
            issus_status_output = Redmine.redmine_get_priority(
                self, logger, app)
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
            redmine_trackers_output = Redmine.redmine_get_trackers(
                self, logger, app)
            for redmine_tracker in redmine_trackers_output['trackers']:
                redmine_tracker.pop('default_status', None)
                redmine_tracker.pop('description', None)
                output.append(redmine_tracker)
            return output
        except Exception as error:
            return str(error), 400

    def get_issue_statistics(self, logger, app, args, user_id):
        Redmine.get_redmine_key(self, logger, app)
        if args["to_time"] is not None:
            args["update_on"] = "%3E%3C{0}|{1}".format(args["from_time"],
                                                       args["to_time"])
        else:
            args["update_on"] = "%3E%3D{0}".format(args["from_time"])
        user_plugin_relation_array = auth.get_user_plugin_relation(
            self, logger)
        for user_plugin_relation in user_plugin_relation_array:
            if user_plugin_relation['user_id'] == user_id:
                args["assigned_to_id"] = user_plugin_relation['plan_user_id']
        try:
            redmine_output, status_code = Redmine.redmine_get_statistics(
                self, logger, app, args)
            return {
                "message": "success",
                "data": {
                    "issue_number": redmine_output["total_count"]
                }
            }, status_code
        except Exception as error:
            return {"message": str(error)}, 400

    def count_prioriry_number_by_issues(self, logger, app, user_id):
        try:
            priority_count = {}
            issues = self.get_issue_by_user(logger, app, user_id)
            logger.info("issues: {0}".format(issues))
            for issue in issues:
                if issue['issue_priority'] not in priority_count:
                    priority_count[issue['issue_priority']] = 1
                else:
                    priority_count[issue['issue_priority']] += 1
            logger.info("priority_count: {0}".format(priority_count))
            output = []
            for key, value in priority_count.items():
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
                if issue['name'] not in project_count:
                    project_count[issue['name']] = 1
                else:
                    project_count[issue['name']] += 1
            logger.info("project_count: {0}".format(project_count))
            output = []
            for key, value in project_count.items():
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
                if issue['issue_category'] not in tracker_count:
                    tracker_count[issue['issue_category']] = 1
                else:
                    tracker_count[issue['issue_category']] += 1
            logger.info("tracker_count: {0}".format(tracker_count))
            output = []
            for key, value in tracker_count.items():
                output.append({'name': key, 'number': value})
            return output
        except Exception as error:
            return str(error), 400
