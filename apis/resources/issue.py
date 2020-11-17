import calendar
from datetime import datetime, date, timedelta

import werkzeug
from flask_jwt_extended import jwt_required, get_jwt_identity
from flask_restful import Resource, reqparse

import resources.apiError as apiError
import resources.user as user
import resources.util as util
from model import db, ProjectPluginRelation, ProjectUserRole
from resources.logger import logger
from resources.redmine import redmine
from . import project as project_module, role


def get_dict_userid():
    result = db.engine.execute(
        "SELECT user_id, plan_user_id FROM public.user_plugin_relation")
    user_id_output = result.fetchall()
    result.close()
    user_to_plan = {}
    plan_to_user = {}
    for u in user_id_output:
        user_to_plan[str(u['user_id'])] = u['plan_user_id']
        plan_to_user[str(u['plan_user_id'])] = u['user_id']
    return user_to_plan, plan_to_user


def dump_by_issue(issue_id):
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


def deal_with_issue_by_user_redmine_output(redmine_output):
    output_list = {'id': redmine_output['id']}
    project_list = project_module.get_project_by_plan_project_id(redmine_output['project']['id'])
    project = project_module.get_project_info(project_list['project_id'])
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
        user_info = user.get_user_id_name_by_plan_user_id(redmine_output['assigned_to']['id'])
        if user_info is not None:
            output_list['assigned_to'] = user_info['name']
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


def __deal_with_issue_redmine_output(redmine_output):
    project_list = project_module.get_project_by_plan_project_id(redmine_output['project']['id'])
    if project_list is not None:
        project_name = project_module.get_project_info(project_list['project_id'])['name']
        redmine_output['project']['id'] = project_list['project_id']
        redmine_output['project']['name'] = project_name
    else:
        redmine_output['project']['id'] = None
        redmine_output['project']['name'] = None
    if 'assigned_to' in redmine_output:
        user_info = user.get_user_id_name_by_plan_user_id(redmine_output['assigned_to']['id'])
        if user_info is not None:
            redmine_output['assigned_to'] = {'id': user_info['id'], 'name': user_info['name']}
    if 'author' in redmine_output:
        user_info = user.get_user_id_name_by_plan_user_id(redmine_output['author']['id'])
        if user_info is not None:
            redmine_output['author'] = {'id': user_info['id'], 'name': user_info['name']}
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
                    user_info = user.get_user_id_name_by_plan_user_id(redmine_output['journals'][i]['user']['id'])
                    if user_info is not None:
                        redmine_output['journals'][i]['user'] = {'id': user_info['id'], 'name': user_info['name']}
                redmine_output['journals'][i].pop('id', None)
                redmine_output['journals'][i].pop('private_notes', None)
                i += 1
    return redmine_output


def require_issue_visible(issue_id,
                          err_message="You don't have the permission to access this issue.",
                          even_admin=False):
    identity = get_jwt_identity()
    user_id = identity['user_id']
    if not even_admin and identity['role_id'] == role.ADMIN.id:
        return
    check_result = verify_issue_user(issue_id, user_id)
    if check_result:
        return
    else:
        raise apiError.NotInProjectError(err_message)


def verify_issue_user(issue_id, user_id):
    issue_info, status_code = get_issue(issue_id)
    project_id = issue_info['data']['project']['id']
    select_project_user_role_command = db.select([ProjectUserRole.stru_project_user_role]) \
        .where(db.and_(ProjectUserRole.stru_project_user_role.c.project_id == project_id,
                       ProjectUserRole.stru_project_user_role.c.user_id == user_id))
    ret_msg = util.call_sqlalchemy(select_project_user_role_command)
    match_list = ret_msg.fetchall()
    if len(match_list) > 0:
        return True
    else:
        return False


def get_issue(issue_id):
    redmine_output_issue = redmine.rm_get_issue(issue_id)
    if redmine_output_issue.status_code != 200:
        return util.respond_redmine_error(redmine_output_issue,
                                          "Error while getting issue details.")
    output = __deal_with_issue_redmine_output(redmine_output_issue.json()['issue'])
    return util.success(output)


def create_issue(args, operator_id):
    args = {k: v for k, v in args.items() if v is not None}
    if 'parent_id' in args:
        args['parent_issue_id'] = args['parent_id']
        args.pop('parent_id', None)
    project_plugin_relation = project_module.get_project_plugin_relation(args['project_id'])
    args['project_id'] = project_plugin_relation['plan_project_id']
    if "assigned_to_id" in args:
        user_plugin_relation = user.get_user_plugin_relation(user_id=args['assigned_to_id'])
        args['assigned_to_id'] = user_plugin_relation['plan_user_id']

    attachment = redmine.rm_upload(args)
    if attachment is not None:
        args['uploads'] = [attachment]

    plan_operator_id = None
    if operator_id is not None:
        operator_plugin_relation = user.get_user_plugin_relation(user_id=operator_id)
        plan_operator_id = operator_plugin_relation['plan_user_id']
    output, status_code = redmine.rm_create_issue(args, plan_operator_id)
    if status_code == 201:
        return util.success({"issue_id": output.json()["issue"]["id"]})
    else:
        return util.respond_redmine_error(output, "Error while creating issue")


def update_issue(issue_id, args, operator_id):
    args = {k: v for k, v in args.items() if v is not None}
    if 'parent_id' in args:
        args['parent_issue_id'] = args['parent_id']
        args.pop('parent_id', None)
    if "assigned_to_id" in args:
        user_plugin_relation = user.get_user_plugin_relation(user_id=args['assigned_to_id'])
        args['assigned_to_id'] = user_plugin_relation['plan_user_id']

    attachment = redmine.rm_upload(args)
    if attachment is not None:
        args['uploads'] = [attachment]
    plan_operator_id = None
    if operator_id is not None:
        operator_plugin_relation = user.get_user_plugin_relation(user_id=operator_id)
        plan_operator_id = operator_plugin_relation['plan_user_id']
    output, status_code = redmine.rm_update_issue(issue_id, args, plan_operator_id)
    if status_code == 204:
        return util.success()
    else:
        return util.respond_redmine_error(output, "update issue failed.")


def delete_issue(issue_id):
    output, status_code = redmine.rm_delete_issue(issue_id)
    if status_code != 204 and status_code != 404:
        return util.respond_redmine_error(output, 'Error when deleting issue.')
    return util.success()


def get_issue_by_project(project_id, args):
    if util.is_dummy_project(project_id):
        return util.success([])
    get_project_command = db.select([ProjectPluginRelation.stru_project_plug_relation]).where(
        db.and_(ProjectPluginRelation.stru_project_plug_relation.c.project_id == project_id))
    ret_msg = util.call_sqlalchemy(get_project_command)
    project_dict = ret_msg.fetchone()
    if project_dict is None:
        return util.respond(404, "Error while getting issues",
                            error=apiError.project_not_found(project_id))
    output_array = []
    redmine_output_issue_array = redmine.rm_get_issues_by_project(
        project_dict['plan_project_id'], args).json()

    for redmine_issue in redmine_output_issue_array['issues']:
        output_dict = deal_with_issue_by_user_redmine_output(redmine_issue)
        output_array.append(output_dict)
    return util.success(output_array)


def get_issue_by_tree_by_project(project_id):
    args = {}

    issue_list_output, status_code = get_issue_by_project(project_id, args)
    if status_code != 200:
        return issue_list_output, status_code
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
    return util.success(forest)


def get_issue_by_status_by_project(project_id):
    if util.is_dummy_project(project_id):
        return util.success({})
    args = {}
    issue_list_output, status_code = get_issue_by_project(project_id, args)
    if status_code != 200:
        return issue_list_output, status_code
    get_issue_by_status_output = {}
    for issue_list in issue_list_output['data']:
        if issue_list['issue_status'] not in get_issue_by_status_output:
            get_issue_by_status_output[issue_list['issue_status']] = []
        get_issue_by_status_output[issue_list['issue_status']].append(
            issue_list)
    return util.success(get_issue_by_status_output)


def get_issue_by_date_by_project(project_id):
    if util.is_dummy_project(project_id):
        return util.success({})
    args = {}
    issue_list_output, status_code = get_issue_by_project(project_id, args)
    if status_code != 200:
        return issue_list_output, status_code
    get_issue_by_date_output = {}
    for issue_list in issue_list_output['data']:
        issue_updated_date = datetime.strptime(
            issue_list['updated_on'],
            "%Y-%m-%dT%H:%M:%SZ").date().strftime("%Y/%m/%d")
        if issue_updated_date not in get_issue_by_date_output:
            get_issue_by_date_output[issue_updated_date] = []
        get_issue_by_date_output[issue_updated_date].append(issue_list)
    return util.success(get_issue_by_date_output)


def get_issueProgress_by_project(project_id, args):
    issue_list, status_code = get_issue_by_project(project_id, args)
    if status_code != 200:
        return issue_list, status_code
    open_issue = 0
    for issue in issue_list['data']:
        if issue["issue_status"] != "Closed":
            open_issue += 1
    return util.success({
        "open": open_issue,
        "total_issue": len(issue_list['data'])
    })


def get_issueProgress_allVersion_by_project(project_id):
    args = {}
    issue_list, status_code = get_issue_by_project(project_id, args)
    if status_code != 200:
        return issue_list, status_code
    ret = {}
    for issue in issue_list['data']:
        count_dict = {'open': 0, 'closed': 0}
        if issue['fixed_version_name'] not in ret:
            ret[issue['fixed_version_name']] = count_dict
        if issue["issue_status"] != "Closed":
            ret[issue['fixed_version_name']]['open'] += 1
        else:
            ret[issue['fixed_version_name']]['closed'] += 1
    return util.success(ret)


def get_issueStatistics_by_project(project_id, args):
    issue_list, status_code = get_issue_by_project(project_id, args)
    if status_code != 200:
        return issue_list, status_code
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
    return util.success({
        "priority": priority_list,
        "category": category_list,
        "owner": owner_list
    })


def get_issue_by_user(user_id):
    user_to_plan, plan_to_user = get_dict_userid()
    output_array = []
    if str(user_id) not in user_to_plan:
        return util.respond(400, 'Cannot find user in redmine')
    redmine_output_issue_array = redmine.rm_get_issues_by_user(user_to_plan[str(user_id)])
    for redmine_issue in redmine_output_issue_array['issues']:
        output_dict = deal_with_issue_by_user_redmine_output(redmine_issue)
        output_array.append(output_dict)
    return util.success(output_array)


def get_issue_status():
    issue_status_output = redmine.rm_get_issue_status()
    return util.success(issue_status_output['issue_statuses'])


def get_issue_priority():
    output = []
    issue_status_output = redmine.rm_get_priority()
    for issue_status in issue_status_output['issue_priorities']:
        issue_status.pop('is_default', None)
        if issue_status['active'] is True:
            issue_status["is_closed"] = False
        else:
            issue_status["is_closed"] = True
        issue_status.pop('active', None)
        output.append(issue_status)
    return util.success(output)


def get_issue_trackers():
    output = []
    redmine_trackers_output = redmine.rm_get_trackers()
    for redmine_tracker in redmine_trackers_output['trackers']:
        redmine_tracker.pop('default_status', None)
        redmine_tracker.pop('description', None)
        output.append(redmine_tracker)
    return util.success(output)


def get_issue_statistics(args, user_id):
    args['status_id'] = '*'
    if args["to_time"] is not None:
        args["due_date"] = "><{0}|{1}".format(args["from_time"],
                                              args["to_time"])
    else:
        args["due_date"] = ">=".format(args["from_time"])
    user_plugin_relation = user.get_user_plugin_relation(user_id=user_id)
    if user_plugin_relation is not None:
        args["assigned_to_id"] = user_plugin_relation['plan_user_id']
    redmine_output, status_code = redmine.rm_get_statistics(args)
    if status_code != 200:
        return util.respond(status_code, "Error when getting issue statistics",
                            error=apiError.redmine_error(redmine_output))
    return util.success({"issue_number": redmine_output["total_count"]})


def get_open_issue_statistics(user_id):
    args = {'limit': 100}
    user_plugin_relation = user.get_user_plugin_relation(user_id=user_id)
    if user_plugin_relation is not None:
        args["assigned_to_id"] = user_plugin_relation['plan_user_id']
    args['status_id'] = '*'
    total_issue_output, status_code = redmine.rm_get_statistics(args)
    if status_code != 200:
        return util.respond(status_code, "Error when getting issue statistics",
                            error=apiError.redmine_error(total_issue_output))
    args['status_id'] = 'closed'
    closed_issue_output, closed_status_code = redmine.rm_get_statistics(args)
    if closed_status_code != 200:
        return util.respond(status_code, "Error when getting issue statistics",
                            error=apiError.redmine_error(closed_status_code))
    active_issue_number = total_issue_output["total_count"] - closed_issue_output["total_count"]
    return util.success({"active_issue_number": active_issue_number})


def get_issue_statistics_in_period(period, user_id):
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
        return util.respond(400, 'Type error, should be week or month')

    args = {"due_date": "><{0}|{1}".format(from_time, to_time)}
    user_plugin_relation = user.get_user_plugin_relation(user_id=user_id)
    if user_plugin_relation is not None:
        args["assigned_to_id"] = user_plugin_relation['plan_user_id']

    args['status_id'] = '*'
    redmine_output, status_code = redmine.rm_get_statistics(args)
    if status_code != 200:
        return util.respond(status_code, "Error when getting issue statistics",
                            error=apiError.redmine_error(redmine_output))
    total = redmine_output["total_count"]

    args['status_id'] = 'closed'
    redmine_output_6, status_code = redmine.rm_get_statistics(args)
    if status_code != 200:
        return util.respond(status_code, "Error when getting issue statistics",
                            error=apiError.redmine_error(redmine_output_6))
    closed = redmine_output_6["total_count"]
    return util.success({
        "open": total - closed,
        "closed": closed
    })


def count_project_number_by_issues(user_id):
    project_count = {}
    data, status_code = get_issue_by_user(user_id)
    if status_code / 100 != 2:
        return util.respond(status_code, 'Error while getting issues by user', data)
    issues = data['data']
    for issue in issues:
        if issue['project_name'] not in project_count:
            project_count[issue['project_name']] = 1
        else:
            project_count[issue['project_name']] += 1
    output = []
    for key, value in project_count.items():
        output.append({'name': key, 'number': value})
    return util.success(output)


def count_priority_number_by_issues(user_id):
    priority_count = {}
    data, status_code = get_issue_by_user(user_id)
    if status_code / 100 != 2:
        return util.respond(status_code, 'Error while getting issues by user', data)
    issues = data['data']
    for issue in issues:
        priority = issue['issue_priority']
        if priority not in priority_count:
            priority_count[priority] = 1
        else:
            priority_count[priority] += 1
    output = []
    for key, value in priority_count.items():
        output.append({'name': key, 'number': value})
    return util.success(output)


def count_type_number_by_issues(user_id):
    tracker_count = {}
    data, status_code = get_issue_by_user(user_id)
    if status_code / 100 != 2:
        return util.respond(status_code, 'Error while getting issues by user', data)
    issues = data['data']
    for issue in issues:
        if issue['issue_category'] not in tracker_count:
            tracker_count[issue['issue_category']] = 1
        else:
            tracker_count[issue['issue_category']] += 1
    output = []
    for key, value in tracker_count.items():
        output.append({'name': key, 'number': value})
    return util.success(output)


# --------------------- Resources ---------------------
class SingleIssue(Resource):
    @jwt_required
    def get(self, issue_id):
        require_issue_visible(issue_id)
        return get_issue(issue_id)

    @jwt_required
    def post(self):
        parser = reqparse.RequestParser()
        parser.add_argument('project_id', type=int, required=True)
        parser.add_argument('tracker_id', type=int, required=True)
        parser.add_argument('status_id', type=int, required=True)
        parser.add_argument('priority_id', type=int, required=True)
        parser.add_argument('subject', type=str, required=True)
        parser.add_argument('description', type=str)
        parser.add_argument('assigned_to_id', type=int, required=True)
        parser.add_argument('parent_id', type=int)
        parser.add_argument('fixed_version_id', type=int)
        parser.add_argument('start_date', type=str, required=True)
        parser.add_argument('due_date', type=str, required=True)
        parser.add_argument('done_ratio', type=int, required=True)
        parser.add_argument('estimated_hours', type=int, required=True)

        # Attachment upload
        parser.add_argument('upload_file', type=werkzeug.datastructures.FileStorage, location='files')
        parser.add_argument('upload_filename', type=str)
        parser.add_argument('upload_description', type=str)

        args = parser.parse_args()
        return create_issue(args, get_jwt_identity()['user_id'])

    @jwt_required
    def put(self, issue_id):
        require_issue_visible(issue_id)
        parser = reqparse.RequestParser()
        parser.add_argument('assigned_to_id', type=int)
        parser.add_argument('tracker_id', type=int)
        parser.add_argument('status_id', type=int)
        parser.add_argument('priority_id', type=int)
        parser.add_argument('estimated_hours', type=int)
        parser.add_argument('description', type=str)
        parser.add_argument('parent_id', type=int)
        parser.add_argument('fixed_version_id', type=int)
        parser.add_argument('subject', type=str)
        parser.add_argument('start_date', type=str)
        parser.add_argument('due_date', type=str)
        parser.add_argument('done_ratio', type=int)
        parser.add_argument('notes', type=str)

        # Attachment upload
        parser.add_argument('upload_file', type=werkzeug.datastructures.FileStorage, location='files')
        parser.add_argument('upload_filename', type=str)
        parser.add_argument('upload_description', type=str)

        args = parser.parse_args()
        return update_issue(issue_id, args, get_jwt_identity()['user_id'])

    @jwt_required
    def delete(self, issue_id):
        require_issue_visible(issue_id)
        return delete_issue(issue_id)


class DumpByIssue(Resource):
    @jwt_required
    def get(self, issue_id):
        require_issue_visible(issue_id)
        return dump_by_issue(issue_id)


class IssueByProject(Resource):
    @jwt_required
    def get(self, project_id):
        role.require_in_project(project_id, 'Error to get issue.')
        parser = reqparse.RequestParser()
        parser.add_argument('fixed_version_id', type=int)
        args = parser.parse_args()
        return get_issue_by_project(project_id, args)


class IssueByTreeByProject(Resource):
    @jwt_required
    def get(self, project_id):
        role.require_in_project(project_id, 'Error to get issue.')
        return get_issue_by_tree_by_project(project_id)


class IssueByStatusByProject(Resource):
    @jwt_required
    def get(self, project_id):
        role.require_in_project(project_id)
        return get_issue_by_status_by_project(project_id)


class IssueByDateByProject(Resource):
    @jwt_required
    def get(self, project_id):
        role.require_in_project(project_id)
        return get_issue_by_date_by_project(project_id)


class IssuesProgressByProject(Resource):
    @jwt_required
    def get(self, project_id):
        role.require_in_project(project_id)
        parser = reqparse.RequestParser()
        parser.add_argument('fixed_version_id', type=int)
        args = parser.parse_args()
        return get_issueProgress_by_project(project_id, args)


class IssuesProgressAllVersionByProject(Resource):
    @jwt_required
    def get(self, project_id):
        role.require_in_project(project_id)
        return get_issueProgress_allVersion_by_project(project_id)


class IssuesStatisticsByProject(Resource):
    @jwt_required
    def get(self, project_id):
        role.require_in_project(project_id)
        parser = reqparse.RequestParser()
        parser.add_argument('fixed_version_id', type=int)
        args = parser.parse_args()
        return get_issueStatistics_by_project(project_id, args)


class IssueStatus(Resource):
    @jwt_required
    def get(self):
        return get_issue_status()


class IssuePriority(Resource):
    @jwt_required
    def get(self):
        return get_issue_priority()


class IssueTracker(Resource):
    @jwt_required
    def get(self):
        return get_issue_trackers()


class IssueRDbyUser(Resource):
    @jwt_required
    def get(self, user_id):
        role.require_user_himself(user_id, even_pm=False)
        return get_issue_by_user(user_id)


class MyIssueStatistics(Resource):
    @jwt_required
    def get(self):
        parser = reqparse.RequestParser()
        parser.add_argument('from_time', type=str, required=True)
        parser.add_argument('to_time', type=str)
        parser.add_argument('status_id', type=int)
        args = parser.parse_args()
        output = get_issue_statistics(args, get_jwt_identity()['user_id'])
        return output


class MyOpenIssueStatistics(Resource):
    @jwt_required
    def get(self):
        return get_open_issue_statistics(get_jwt_identity()['user_id'])


class MyIssueWeekStatistics(Resource):
    @jwt_required
    def get(self):
        return get_issue_statistics_in_period('week', get_jwt_identity()['user_id'])


class MyIssueMonthStatistics(Resource):
    @jwt_required
    def get(self):
        return get_issue_statistics_in_period('month', get_jwt_identity()['user_id'])


class DashboardIssuePriority(Resource):
    @jwt_required
    def get(self, user_id):
        if int(user_id) == get_jwt_identity()['user_id'] or get_jwt_identity(
        )['role_id'] in (3, 5):
            return count_priority_number_by_issues(user_id)
        else:
            return {'message': 'Access token is missing or invalid'}, 401


class DashboardIssueProject(Resource):
    @jwt_required
    def get(self, user_id):
        if int(user_id) == get_jwt_identity()['user_id'] or get_jwt_identity(
        )['role_id'] in (3, 5):
            return count_project_number_by_issues(user_id)
        else:
            return {'message': 'Access token is missing or invalid'}, 401


class DashboardIssueType(Resource):
    @jwt_required
    def get(self, user_id):
        if int(user_id) == get_jwt_identity()['user_id'] or get_jwt_identity(
        )['role_id'] in (3, 5):
            return count_type_number_by_issues(user_id)
        else:
            return {'message': 'Access token is missing or invalid'}, 401
