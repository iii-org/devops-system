import calendar
import config
import logging
from datetime import datetime, date, timedelta

from model import db, ProjectPluginRelation, ProjectUserRole
from .user import User
import resources.apiError as apiError
import resources.util as util

logger = logging.getLogger(config.get('LOGGER_NAME'))


class Issue(object):
    headers = {'Content-Type': 'application/json'}

    def __init__(self, pjt, redmine, au):
        self.pjt = pjt
        self.redmine = redmine
        self.au = au

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
        prject_list = self.pjt.get_project_by_plan_project_id \
            (logger, redmine_output['project']['id'])
        logger.debug("prject_list: {0}".format(prject_list))
        if prject_list is not None:
            project_name = self.pjt.get_project_info(logger, prject_list['project_id'])['name']
            redmine_output['project']['id'] = prject_list['project_id']
            redmine_output['project']['name'] = project_name
        else:
            redmine_output['project']['id'] = None
            redmine_output['project']['name'] = None
        if 'assigned_to' in redmine_output:
            userInfo = self.au.get_user_id_name_by_plan_user_id(redmine_output['assigned_to']['id'])
            if userInfo is not None:
                redmine_output['assigned_to'] = {'id': userInfo['id'], 'name': userInfo['name']}
        if 'author' in redmine_output:
            userInfo = self.au.get_user_id_name_by_plan_user_id(redmine_output['author']['id'])
            if userInfo is not None:
                redmine_output['author'] = {'id': userInfo['id'], 'name': userInfo['name']}
        redmine_output.pop('is_private', None)
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
            i = 0
            while i < len(redmine_output['journals']):
                if redmine_output['journals'][i]['notes'] == "":
                    del redmine_output['journals'][i]
                else:
                    if 'user' in redmine_output['journals'][i]:
                        userInfo = self.au.get_user_id_name_by_plan_user_id(redmine_output['journals'][i]['user']['id'])
                        if userInfo is not None:
                            redmine_output['journals'][i]['user'] = {'id': userInfo['id'], 'name': userInfo['name']}
                    redmine_output['journals'][i].pop('id', None)
                    redmine_output['journals'][i].pop('private_notes', None)
                    i += 1
        logger.info("redmine issue redmine_output: {0}".format(redmine_output))
        return redmine_output

    def __dealwith_issue_by_user_redmine_output(self, logger, redmine_output):
        output_list = {}
        output_list['id'] = redmine_output['id']
        project_list = self.pjt.get_project_by_plan_project_id(logger, redmine_output['project']['id'])
        project = self.pjt.get_project_info(logger, project_list['project_id'])
        project_name = project['name']
        project_display = project['display']
        output_list['project_id'] = project_list['project_id']
        output_list['project_name'] = project_name
        output_list['project_display'] = project_display
        output_list['issue_category'] = redmine_output['tracker']['name']
        output_list['issue_priority'] = redmine_output['priority']['name']
        output_list['issue_status'] = redmine_output['status']['name']
        output_list['issue_name'] = redmine_output['subject']
        output_list['description'] = redmine_output['description']
        output_list['updated_on'] = redmine_output['updated_on']
        output_list['start_date'] = None
        if 'start_date' in redmine_output:
            output_list['start_date'] = redmine_output['start_date']
        output_list['due_date'] = None
        if 'due_date' in redmine_output:
            output_list['due_date'] = redmine_output['due_date']
        output_list['assigned_to'] = None
        if 'assigned_to' in redmine_output:
            userInfo = self.au.get_user_id_name_by_plan_user_id(redmine_output['assigned_to']['id'])
            if userInfo is not None:
                output_list['assigned_to'] = userInfo['name']
        output_list['parent_id'] = None
        if 'parent' in redmine_output:
            output_list['parent_id'] = redmine_output['parent']['id']
        output_list['fixed_version_id'] = None
        output_list['fixed_version_name'] = None
        if 'fixed_version' in redmine_output:
            output_list['fixed_version_id'] = redmine_output['fixed_version'][
                'id']
            output_list['fixed_version_name'] = redmine_output[
                'fixed_version']['name']
        logger.info(
            "get issue by user redmine_output: {0}".format(output_list))
        return output_list

    def verify_issue_user(self, logger, app, issue_id, user_id):
        # base on issus get project
        issue_info, status_code = Issue.get_issue_rd(self, issue_id)
        logger.debug("issue_id: {0}, issue_info: {1}".format(issue_id, issue_info))
        project_id = issue_info['data']['project']['id']
        logger.info("issue_info: {0}".format(issue_info))
        select_project_user_role_command = db.select([ProjectUserRole.stru_project_user_role]) \
            .where(db.and_(ProjectUserRole.stru_project_user_role.c.project_id == project_id, \
                           ProjectUserRole.stru_project_user_role.c.user_id == user_id))
        logger.debug("select_project_user_role_command: {0}".format(
            select_project_user_role_command))
        reMessage = util.call_sqlalchemy(select_project_user_role_command)
        match_list = reMessage.fetchall()
        logger.info("reMessage: {0}".format(match_list))
        logger.info("reMessage len: {0}".format(len(match_list)))
        if len(match_list) > 0:
            return True
        else:
            return False

    def get_issue_rd(self, issue_id):
        redmine_output_issue = self.redmine.rm_get_issue(issue_id)
        if redmine_output_issue.status_code == 200:
            output = self.__dealwith_issue_redmine_output(
                logger,
                redmine_output_issue.json()['issue'])
            return {"message": "success", "data": output}, 200
        else:
            return {"message": "could not get this redmine issue."}, 400

    def get_issue_by_project(self, logger, app, project_id, args):
        if util.is_dummy_project(project_id):
            return util.success([])
        get_project_command = db.select([ProjectPluginRelation.stru_project_plug_relation]) \
            .where(db.and_(ProjectPluginRelation.stru_project_plug_relation.c.project_id == project_id))
        logger.debug("get_project_command: {0}".format(get_project_command))
        reMessage = util.call_sqlalchemy(get_project_command)
        project_dict = reMessage.fetchone()
        logger.debug("project_list: {0}".format(project_dict))
        if project_dict is not None:
            output_array = []
            redmine_output_issue_array = self.redmine.rm_get_issues_by_project(
                project_dict['plan_project_id'], args)

            for redmine_issue in redmine_output_issue_array['issues']:
                output_dict = self.__dealwith_issue_by_user_redmine_output(
                    logger, redmine_issue)
                output_array.append(output_dict)
            return {"message": "success", "data": output_array}, 200
        else:
            return {"message": "could not find this project"}, 400

    def get_issue_by_tree_by_project(self, logger, app, project_id):
        args = {}

        issue_list_output, status_code = self.get_issue_by_project(
            logger, app, project_id, args)
        if status_code == 200:
            nodes = {}
            for issue_list in issue_list_output['data']:
                issue_list['children'] = []
                nodes[issue_list['id']] = issue_list
            forest = []
            for issue_list in issue_list_output['data']:
                node = nodes[issue_list['id']]
                if issue_list['parent_id'] is None:
                    forest.append(node)
                else:
                    parent = nodes[issue_list['parent_id']]
                    parent['children'].append(node)
            # logger.debug("forest: {0}".format(forest))

            return {"message": "success", "data": forest}, 200
        else:
            return {"message": "could not get issue list"}, 400

    def get_issue_by_status_by_project(self, logger, app, project_id):
        if util.is_dummy_project(project_id):
            return util.success({})
        args = {}
        issue_list_output, status_code = self.get_issue_by_project(
            logger, app, project_id, args)
        if status_code == 200:
            get_issue_by_status_output = {}
            for issue_list in issue_list_output['data']:
                if issue_list[
                    'issue_status'] not in get_issue_by_status_output:
                    get_issue_by_status_output[issue_list['issue_status']] = []
                get_issue_by_status_output[issue_list['issue_status']].append(
                    issue_list)
            # logger.debug("get_issue_by_status_output: {0}".format(get_issue_by_status_output))
            return {
                       "message": "success",
                       "data": get_issue_by_status_output
                   }, 200
        else:
            return {"message": "could not get issue list"}, 400

    def get_issue_by_date_by_project(self, logger, app, project_id):
        if util.is_dummy_project(project_id):
            return util.success({})
        args = {}
        issue_list_output, status_code = self.get_issue_by_project(
            logger, app, project_id, args)
        if status_code == 200:
            get_issue_by_date_output = {}
            for issue_list in issue_list_output['data']:
                issue_updated_date = datetime.strptime(
                    issue_list['updated_on'],
                    "%Y-%m-%dT%H:%M:%SZ").date().strftime("%Y/%m/%d")
                # logger.debug("issue_updated_date: {0}".format(issue_updated_date))
                if issue_updated_date not in get_issue_by_date_output:
                    get_issue_by_date_output[issue_updated_date] = []
                get_issue_by_date_output[issue_updated_date].append(issue_list)
            # logger.debug("get_issue_by_date_output: {0}".format(get_issue_by_date_output))
            return {
                       "message": "success",
                       "data": get_issue_by_date_output
                   }, 200
        else:
            return {"message": "could not get issue list"}, 400

    def get_issueProgress_by_project(self, logger, app, project_id, args):
        issue_list, status_code = self.get_issue_by_project(
            logger, app, project_id, args)
        logger.debug("issue_list: {0}, status_code: {1}".format(
            issue_list, status_code))
        if status_code == 200:
            open_issue = 0
            for issue in issue_list['data']:
                if issue["issue_status"] != "Closed":
                    open_issue += 1
            return {
                "message": "success",
                "data": {
                    "open": open_issue,
                    "total_issue": len(issue_list['data'])
                }
            }
        else:
            return {"message": "could not get issue list"}, 400

    def get_issueProgress_allVersion_by_project(self, logger, app, project_id):
        args = {}
        issue_list, status_code = self.get_issue_by_project(
            logger, app, project_id, args)
        if status_code == 200:
            get_issue_sortby_version_output = {}
            for issue in issue_list['data']:
                count_dict = {'open': 0, 'closed': 0}
                if issue[
                    'fixed_version_name'] not in get_issue_sortby_version_output:
                    get_issue_sortby_version_output[
                        issue['fixed_version_name']] = count_dict
                if issue["issue_status"] != "Closed":
                    get_issue_sortby_version_output[
                        issue['fixed_version_name']]['open'] += 1
                else:
                    get_issue_sortby_version_output[
                        issue['fixed_version_name']]['closed'] += 1
            return {
                "message": "success",
                "data": get_issue_sortby_version_output
            }
        else:
            return {"message": "could not get issue list"}, 400

    def get_issueStatistics_by_project(self, logger, app, project_id, args):
        issue_list, status_code = self.get_issue_by_project(
            logger, app, project_id, args)
        logger.debug("issue_list: {0}, status_code: {1}".format(
            issue_list, status_code))
        if status_code == 200:
            priority_list = {}
            category_list = {}
            owner_list = {}
            for issue in issue_list['data']:
                # count priority
                if issue["issue_priority"] not in priority_list:
                    if issue["issue_status"] != "Closed":
                        priority_list[issue["issue_priority"]] = {
                            "open": 1,
                            "closed": 0
                        }
                    else:
                        priority_list[issue["issue_priority"]] = {
                            "open": 0,
                            "closed": 1
                        }
                else:
                    open_count = priority_list[
                        issue["issue_priority"]]["open"]
                    closed_count = priority_list[
                        issue["issue_priority"]]["closed"]
                    if issue["issue_status"] != "Closed":
                        priority_list[issue["issue_priority"]] = {
                            "open": open_count + 1,
                            "closed": closed_count
                        }
                    else:
                        priority_list[issue["issue_priority"]] = {
                            "open": open_count,
                            "closed": closed_count + 1
                        }
                # count category
                if issue["issue_category"] not in category_list:
                    if issue["issue_status"] != "Closed":
                        category_list[issue["issue_category"]] = {
                            "open": 1,
                            "closed": 0
                        }
                    else:
                        category_list[issue["issue_category"]] = {
                            "open": 0,
                            "closed": 1
                        }
                else:
                    open_count = category_list[
                        issue["issue_category"]]["open"]
                    closed_count = category_list[
                        issue["issue_category"]]["closed"]
                    if issue["issue_status"] != "Closed":
                        category_list[issue["issue_category"]] = {
                            "open": open_count + 1,
                            "closed": closed_count
                        }
                    else:
                        category_list[issue["issue_category"]] = {
                            "open": open_count,
                            "closed": closed_count + 1
                        }
                # count owner
                if issue["assigned_to"] not in owner_list:
                    if issue["issue_status"] != "Closed":
                        owner_list[issue["assigned_to"]] = {
                            "open": 1,
                            "closed": 0
                        }
                    else:
                        owner_list[issue["assigned_to"]] = {
                            "open": 0,
                            "closed": 1
                        }
                else:
                    open_count = owner_list[
                        issue["assigned_to"]]["open"]
                    closed_count = owner_list[issue["assigned_to"]]["closed"]
                    if issue["issue_status"] != "Closed":
                        owner_list[issue["assigned_to"]] = {
                            "open": open_count + 1,
                            "closed": closed_count
                        }
                    else:
                        owner_list[issue["assigned_to"]] = {
                            "open": open_count,
                            "closed": closed_count + 1
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

    def get_issue_by_user(self, user_id):
        user_to_plan, plan_to_user = self.__get_dict_userid(logger)
        output_array = []
        if str(user_id) not in user_to_plan:
            return util.respond(400, 'Cannot find user in redmine')
        redmine_output_issue_array = self.redmine.rm_get_issues_by_user(user_to_plan[str(user_id)])
        for redmine_issue in redmine_output_issue_array['issues']:
            output_dict = self.__dealwith_issue_by_user_redmine_output(
                logger, redmine_issue)
            project = self.pjt.get_project_by_plan_project_id(
                logger, redmine_issue['project']['id'])
            logger.info("project: {0}".format(project))
            # output_dict = self.pjt.get_ci_last_test_result(app, logger, output_dict, project)
            output_array.append(output_dict)
        return {'message': 'success', 'data': output_array}, 200

    def create_issue(self, args, operator_id):
        args = {k: v for k, v in args.items() if v is not None}
        if 'parent_id' in args:
            args['parent_issue_id'] = args['parent_id']
            args.pop('parent_id', None)
        project_plugin_relation = self.pjt.get_project_plugin_relation(args['project_id'])
        args['project_id'] = project_plugin_relation['plan_project_id']
        if "assigned_to_id" in args:
            user_plugin_relation = User.get_user_plugin_relation(user_id=args['assigned_to_id'])
            args['assigned_to_id'] = user_plugin_relation['plan_user_id']
        logger.info("args: {0}".format(args))

        attachment = self.redmine.rm_upload(args)
        if attachment is not None:
            args['uploads'] = [attachment]

        try:
            plan_operator_id = None
            if operator_id is not None:
                operator_plugin_relation = User.get_user_plugin_relation(user_id=operator_id)
                plan_operator_id = operator_plugin_relation['plan_user_id']
            output, status_code = self.redmine.rm_create_issue(args, plan_operator_id)
            if status_code == 201:
                return util.success({"issue_id": output.json()["issue"]["id"]})
            else:
                return util.respond(status_code, "Error while creating issue",
                                    error=apiError.redmine_error(output))
        except Exception as error:
            return util.respond(500, "Error while creating issue",
                                error=apiError.uncaught_exception(error))

    def update_issue_rd(self, logger, app, issue_id, args, operator_id):
        args = {k: v for k, v in args.items() if v is not None}
        if 'parent_id' in args:
            args['parent_issue_id'] = args['parent_id']
            args.pop('parent_id', None)
        if "assigned_to_id" in args:
            user_plugin_relation = User.get_user_plugin_relation(user_id=args['assigned_to_id'])
            args['assigned_to_id'] = user_plugin_relation['plan_user_id']
        logger.info("update_issue_rd args: {0}".format(args))

        attachment = self.redmine.rm_upload(args)
        if attachment is not None:
            args['uploads'] = [attachment]
        plan_operator_id = None
        if operator_id is not None:
            operator_plugin_relation = User.get_user_plugin_relation(user_id=operator_id)
            plan_operator_id = operator_plugin_relation['plan_user_id']
        output, status_code = self.redmine.rm_update_issue(issue_id, args, plan_operator_id)
        if status_code == 204:
            return {"message": "success"}, 200
        else:
            return util.respond(
                400, "update issue failed",
                error=apiError.redmine_error(output.text)
            )

    def delete_issue(self, issue_id):
        try:
            output, status_code = self.redmine.rm_delete_issue(issue_id)
            if status_code != 204 and status_code != 404:
                return util.respond(status_code, 'Error when deleting issue',
                                    apiError.redmine_error(output.text))
            return {"message": "success"}, 200
        except Exception as error:
            return util.respond(500, 'Error when deleting issue',
                                apiError.redmine_error(str(type(error)) + ':' + error.__str__()))

    def get_issue_status(self):
        try:
            issue_status_output = self.redmine.rm_get_issue_status()
            return issue_status_output['issue_statuses']
        except Exception as error:
            return util.respond(500, 'Error when deleting issue',
                                apiError.redmine_error(str(type(error)) + ':' + error.__str__()))

    def get_issue_priority(self):
        try:
            output = []
            issue_status_output = self.redmine.rm_get_priority()
            for issus_status in issue_status_output['issue_priorities']:
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

    def get_issue_trackers(self):
        output = []
        try:
            redmine_trackers_output = self.redmine.rm_get_trackers()
            for redmine_tracker in redmine_trackers_output['trackers']:
                redmine_tracker.pop('default_status', None)
                redmine_tracker.pop('description', None)
                output.append(redmine_tracker)
            return output
        except Exception as error:
            return str(error), 400

    def get_issue_statistics(self, args, user_id):
        args['status_id'] = '*'
        if args["to_time"] is not None:
            args["due_date"] = "><{0}|{1}".format(args["from_time"],
                                                  args["to_time"])
        else:
            args["due_date"] = ">=".format(args["from_time"])
        user_plugin_relation = User.get_user_plugin_relation(user_id=user_id)
        if user_plugin_relation is not None:
            args["assigned_to_id"] = user_plugin_relation['plan_user_id']
        try:
            redmine_output, status_code = self.redmine.rm_get_statistics(args)
            return {
                       "message": "success",
                       "data": {
                           "issue_number": redmine_output["total_count"]
                       }
                   }, status_code
        except Exception as error:
            return {"message": str(error)}, 400

    def get_open_issue_statistics(self, user_id):
        args = {'limit': 100}
        user_plugin_relation = User.get_user_plugin_relation(user_id=user_id)
        if user_plugin_relation is not None:
            args["assigned_to_id"] = user_plugin_relation['plan_user_id']
        args['status_id'] = '*'
        total_issue_output, status_code = self.redmine.rm_get_statistics(args)
        if status_code != 200:
            return {"message": "could not get redmine total issue"}, 400
        logger.debug("user_id {0} total issue number: {1}".format(user_id, total_issue_output["total_count"]))
        args['status_id'] = 'closed'
        closed_issue_output, closed_status_code = self.redmine.rm_get_statistics(args)
        if closed_status_code != 200:
            return {"message": "could not get redmine closed issue"}, 400
        logger.debug("user_id {0} closed issue number: {1}".format(user_id, closed_issue_output["total_count"]))
        active_issue_number = total_issue_output["total_count"] - closed_issue_output["total_count"]
        return {"message": "success", "data": {"active_issue_number": active_issue_number}}

    def get_issue_statistics_in_period(self, logger, app, period, user_id):
        current_date = date.today()
        if period == 'week':
            monday = datetime.today() - timedelta(
                days=datetime.today().weekday() % 7)
            sunday = monday + timedelta(days=6)
            from_time = monday.strftime('%Y-%m-%d')
            to_time = sunday.strftime('%Y-%m-%d')
        elif period == 'month':
            first_day = datetime.today().replace(day=1)
            last_day = datetime.today().replace(day=calendar.monthrange(
                current_date.year, current_date.month)[1])
            from_time = first_day.strftime('%Y-%m-%d')
            to_time = last_day.strftime('%Y-%m-%d')
        else:
            return {'message': 'Type error, should be week or month'}, 400

        args = {"due_date": "><{0}|{1}".format(from_time, to_time)}
        user_plugin_relation = User.get_user_plugin_relation(user_id=user_id)
        if user_plugin_relation is not None:
            args["assigned_to_id"] = user_plugin_relation['plan_user_id']

        try:
            args['status_id'] = '*'
            redmine_output, status_code = self.redmine.rm_get_statistics(args)
            if status_code != 200:
                return {
                           'message': 'error when retrieving data from redmine',
                           'data': redmine_output
                       }, status_code
            total = redmine_output["total_count"]

            args['status_id'] = 'closed'
            redmine_output_6, status_code = self.redmine.rm_get_statistics(args)
            if status_code != 200:
                return {
                           'message': 'error when retrieving data from redmine',
                           'data': redmine_output
                       }, status_code
            closed = redmine_output_6["total_count"]
            return {
                       "message": "success",
                       "data": {
                           "open": total - closed,
                           "closed": closed
                       }
                   }, 200
        except Exception as error:
            return {"message": str(error)}, 400

    def count_priority_number_by_issues(self, user_id):
        try:
            priority_count = {}
            data, status_code = self.get_issue_by_user(user_id)
            if status_code / 100 != 2:
                return util.respond(status_code, 'Error while getting issues by user', data)
            issues = data['data']
            logger.info("issues: {0}".format(issues))
            for issue in issues:
                priority = issue['issue_priority']
                if priority not in priority_count:
                    priority_count[priority] = 1
                else:
                    priority_count[priority] += 1
            logger.info("priority_count: {0}".format(priority_count))
            output = []
            for key, value in priority_count.items():
                output.append({'name': key, 'number': value})
            return {"message": "success", "data": output}, 200
        except Exception as error:
            return {"message": str(error)}, 400

    def count_project_number_by_issues(self, logger, app, user_id):
        try:
            project_count = {}
            data, status_code = self.get_issue_by_user(user_id)
            if status_code / 100 != 2:
                return util.respond(status_code, 'Error while getting issues by user', data)
            issues = data['data']
            logger.info("issues: {0}".format(issues))
            for issue in issues:
                if issue['project_name'] not in project_count:
                    project_count[issue['project_name']] = 1
                else:
                    project_count[issue['project_name']] += 1
            logger.info("project_count: {0}".format(project_count))
            output = []
            for key, value in project_count.items():
                output.append({'name': key, 'number': value})
            return {"message": "success", "data": output}, 200
        except Exception as error:
            return {"message": str(error)}, 400

    def count_type_number_by_issues(self, logger, app, user_id):
        try:
            tracker_count = {}
            data, status_code = self.get_issue_by_user(user_id)
            if status_code / 100 != 2:
                return util.respond(status_code, 'Error while getting issues by user', data)
            issues = data['data']
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
            return {"message": "success", "data": output}, 200
        except Exception as error:
            return {"message": str(error)}, 400

    def dump(self, logger, issue_id):
        output = {}
        tables = [
            'requirements', 'parameters', 'flows', 'test_cases', 'test_items',
            'test_values'
        ]
        for table in tables:
            output[table] = []
            result = db.engine.execute(
                "SELECT * FROM public.{0} WHERE issue_id={1}".format(
                    table, issue_id))
            keys = result.keys()
            rows = result.fetchall()
            result.close()
            for row in rows:
                ele = {}
                for key in keys:
                    if type(row[key]) is datetime:
                        ele[key] = str(row[key])
                    else:
                        ele[key] = row[key]
                output[table].append(ele)
        return {'message': 'success', 'data': output}, 200
