import calendar
import json
from datetime import datetime, date, timedelta

import werkzeug
from flask_jwt_extended import jwt_required, get_jwt_identity
from flask_restful import Resource, reqparse
from sqlalchemy import or_
from sqlalchemy.orm.exc import NoResultFound
from collections import defaultdict
from distutils.util import strtobool
from redminelib import exceptions as redminelibError

import config
import model
import nexus
import resources.apiError as apiError
import resources.user as user
import util as util
from data.nexus_project import NexusProject
from resources.apiError import DevOpsError
from model import db
from resources.logger import logger
from resources.redmine import redmine
from . import project as project_module, project, role
from services import redmine_lib

FLOW_TYPES = {"0": "Given", "1": "When", "2": "Then", "3": "But", "4": "And"}
PARAMETER_TYPES = {'1': '文字', '2': '英數字', '3': '英文字', '4': '數字'}


class NexusIssue:
    closed_statuses = None

    # Use from_redmine or other factory methods
    def __init__(self):
        self.data = None

    def set_redmine_issue(self, redmine_issue, nx_project):
        self.data = {
            'id': redmine_issue['id'],
            'name': redmine_issue['subject'],
            'description': redmine_issue['description'],
            'updated_on': redmine_issue['updated_on'],
            'start_date': {},
            'assigned_to': {},
            'fixed_version': {},
            'due_date': None,
            'parent': None,
            'is_closed': False,
            'issue_link': redmine.rm_build_external_link(
                '/issues/{0}'.format(redmine_issue['id'])),
            'project': {
                'id': nx_project.id,
                'name': nx_project.name,
                'display': nx_project.display,
            },
            'tracker': {
                'id': redmine_issue['tracker']['id'],
                'name': redmine_issue['tracker']['name']
            },
            'priority': {
                'id': redmine_issue['priority']['id'],
                'name': redmine_issue['priority']['name']
            },
            'status': {
                'id': redmine_issue['status']['id'],
                'name': redmine_issue['status']['name']
            },
            'relations': []
        }
        if 'start_date' in redmine_issue:
            self.data['start_date'] = redmine_issue['start_date']
        if 'parent' in redmine_issue:
            get_issue_assign_to_detail(redmine_issue['parent'])
            self.data['parent'] = redmine_issue['parent']
        if 'assigned_to' in redmine_issue:
            user_info = user.get_user_id_name_by_plan_user_id(
                redmine_issue['assigned_to']['id'])
            if user_info is not None:
                self.data['assigned_to'] = {
                    'id': user_info.id,
                    'name': user_info.name,
                    'login': user_info.login
                }
        if 'fixed_version' in redmine_issue:
            self.data['fixed_version'] = {
                'id': redmine_issue['fixed_version']['id'],
                'name': redmine_issue['fixed_version']['name']
            }
        if redmine_issue['status']['id'] in NexusIssue.get_closed_statuses():
            self.data['is_closed'] = True
        if 'relations' in redmine_issue:
            self.data['relations'] = redmine_issue['relations']
        return self

    def set_redmine_issue_v2(self, redmine_issue, with_relationship=False,
                             relationship_bool=False):
        self.data = {
            'id': redmine_issue.id,
            'name': redmine_issue.subject,
            'project': None,
            'description': None,
            'updated_on': redmine_issue.updated_on.isoformat(),
            'start_date': {},
            'assigned_to': {},
            'fixed_version': {},
            'due_date': None,
            'done_ratio': redmine_issue.done_ratio,
            'is_closed': False,
            'issue_link': redmine.rm_build_external_link(
                '/issues/{0}'.format(redmine_issue.id)),
            'tracker': {
                'id': redmine_issue.tracker.id,
                'name': redmine_issue.tracker.name
            },
            'priority': {
                'id': redmine_issue.priority.id,
                'name': redmine_issue.priority.name
            },
            'status': {
                'id': redmine_issue.status.id,
                'name': redmine_issue.status.name
            },
            'relations': []
        }
        if hasattr(redmine_issue, 'project'):
            nx_project = model.Project.query.get(nexus.nx_get_project_plugin_relation(
                rm_project_id=redmine_issue.project.id).project_id)
            self.data['project'] = {
                'id': nx_project.id,
                'name': nx_project.name,
                'display': nx_project.display
            }
        if relationship_bool:
            self.data['family'] = False
            if hasattr(redmine_issue, 'parent'):
                self.data['family'] = True
        if with_relationship:
            self.data['parent'] = None
            self.data['children'] = []
            if hasattr(redmine_issue, 'parent'):
                self.data['parent'] = redmine_issue.parent.id
        if hasattr(redmine_issue, 'author'):
            user_info = user.get_user_id_name_by_plan_user_id(
                redmine_issue.author.id)
            if user_info is not None:
                self.data['author'] = {
                    'id': user_info.id,
                    'name': user_info.name
                }
        if hasattr(redmine_issue, 'description'):
            self.data['description'] = redmine_issue.description
        if hasattr(redmine_issue, 'start_date'):
            self.data['start_date'] = redmine_issue.start_date.isoformat()
        if hasattr(redmine_issue, 'due_date'):
            self.data['due_date'] = redmine_issue.due_date.isoformat()
        if hasattr(redmine_issue, 'assigned_to'):
            user_info = user.get_user_id_name_by_plan_user_id(
                redmine_issue.assigned_to.id)
            if user_info is not None:
                self.data['assigned_to'] = {
                    'id': user_info.id,
                    'name': user_info.name,
                    'login': user_info.login
                }
        if hasattr(redmine_issue, 'fixed_version'):
            self.data['fixed_version'] = {
                'id': redmine_issue.fixed_version.id,
                'name': redmine_issue.fixed_version.name
            }
        if redmine_issue.status.id in NexusIssue.get_closed_statuses():
            self.data['is_closed'] = True
        if hasattr(redmine_issue, 'relations'):
            self.data['relations'] = list(redmine_issue.relations.values())
        return self

    @staticmethod
    def get_closed_statuses():
        if NexusIssue.closed_statuses is None:
            redmine_issue_status = redmine.rm_get_issue_status()
            NexusIssue.closed_statuses = redmine.get_closed_status(
                redmine_issue_status['issue_statuses'])
        return NexusIssue.closed_statuses

    def to_json(self):
        return self.data

    def get_project_name(self):
        return self.data['project']['name']

    def get_priority_name(self):
        return self.data['priority']['name']

    def get_tracker_name(self):
        return self.data['tracker']['name']


def get_issue_attr_name(detail, value):
    resource_not_found = {'id': None, 'name': 'NotExist'}
    # 例外處理: dev3 環境的 issue fixed_version_id 有 -1
    if not value or value == '-1':
        return value
    else:
        if detail['name'] == 'status_id':
            try:
                status = redmine_lib.redmine.issue_status.get(int(value))
            except redminelibError.ResourceNotFoundError:
                return resource_not_found
            return {
                'id': int(value),
                'name': status.name
            }
        elif detail['name'] == 'tracker_id':
            try:
                tracker = redmine_lib.redmine.tracker.get(int(value))
            except redminelibError.ResourceNotFoundError:
                return resource_not_found
            return {
                'id': int(value),
                'name': tracker.name
            }
        elif detail['name'] == 'priority_id':
            try:
                priority = redmine_lib.redmine.enumeration.get(
                    int(value), resource='issue_priorities')
            except redminelibError.ResourceNotFoundError:
                return resource_not_found
            return {
                'id': int(value),
                'name': priority.name
            }
        elif detail['name'] == 'fixed_version_id':
            try:
                fixed_version = redmine_lib.redmine.version.get(int(value))
            except redminelibError.ResourceNotFoundError:
                return resource_not_found
            return {
                'id': int(value),
                'name': fixed_version.name
            }
        elif detail['name'] == 'parent_id':
            try:
                issue = redmine_lib.redmine.issue.get(int(value))
            except redminelibError.ResourceNotFoundError:
                return resource_not_found
            return {
                'id': int(value),
                'name': issue.subject
            }
        else:
            return value


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


def __deal_with_issue_redmine_output(redmine_output, closed_status=None):
    project_list = project_module.get_project_by_plan_project_id(
        redmine_output['project']['id'])
    if project_list is not None:
        project_name = nexus.nx_get_project(id=project_list['project_id']).name
        redmine_output['project']['id'] = project_list['project_id']
        redmine_output['project']['name'] = project_name
    else:
        redmine_output['project']['id'] = None
        redmine_output['project']['name'] = None
    if 'assigned_to' in redmine_output:
        user_info = user.get_user_id_name_by_plan_user_id(
            redmine_output['assigned_to']['id'])
        if user_info is not None:
            redmine_output['assigned_to'] = {
                'id': user_info.id, 'name': user_info.name, 'login': user_info.login}
    if 'author' in redmine_output:
        user_info = user.get_user_id_name_by_plan_user_id(
            redmine_output['author']['id'])
        if user_info is not None:
            redmine_output['author'] = {
                'id': user_info.id, 'name': user_info.name}
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
    # rm_users = redmine.paging('users',25)
    # list_user = {}
    # for rm_user_info in rm_users:
    #     list_user[rm_user_info['id']] = rm_user_info['firstname'] + ' ' + rm_user_info['lastname']
    if 'journals' in redmine_output:
        i = 0
        while i < len(redmine_output['journals']):
            if 'user' in redmine_output['journals'][i]:
                user_info = user.get_user_id_name_by_plan_user_id(
                    redmine_output['journals'][i]['user']['id'])
                if user_info is not None:
                    redmine_output['journals'][i]['user'] = {
                        'id': user_info.id, 'name': user_info.name}
            list_details = []
            if 'details' in redmine_output['journals'][i] and len(redmine_output['journals'][i]['details']) > 0:
                for detail in redmine_output['journals'][i]['details']:
                    detail_info = {}
                    detail_info['name'] = detail['name']
                    detail_info['property'] = detail['property']
                    if detail['name'] == "assigned_to_id":
                        if detail['old_value'] is not None:
                            user_info = user.get_user_id_name_by_plan_user_id(
                                detail['old_value'])
                            detail_info['old_value'] = {
                                'user': {'id': user_info.id, 'name': user_info.name}}
                        else:
                            detail_info['old_value'] = detail['old_value']
                        if detail['new_value'] is not None:
                            user_info = user.get_user_id_name_by_plan_user_id(
                                detail['new_value'])
                            detail_info['new_value'] = {
                                'user': {'id': user_info.id, 'name': user_info.name}}
                        else:
                            detail_info['new_value'] = detail['new_value']
                    else:
                        detail_info['old_value'] = get_issue_attr_name(detail, detail['old_value'])
                        detail_info['new_value'] = get_issue_attr_name(detail, detail['new_value'])
                    list_details.append(detail_info)
            redmine_output['journals'][i]['details'] = list_details
            i += 1
    redmine_output['issue_link'] = f'{config.get("REDMINE_EXTERNAL_BASE_URL")}/issues/{redmine_output["id"]}'
    if 'attachments' in redmine_output:
        for attachment in redmine_output['attachments']:
            attachment['content_url'] = f'{config.get("REDMINE_EXTERNAL_BASE_URL")}/attachments/download/{attachment["id"]}/{attachment["filename"]}'
    redmine_output['is_closed'] = False
    if redmine_output['status']['id'] in closed_status:
        redmine_output['is_closed'] = True
    return redmine_output


def require_issue_visible(issue_id,
                          issue_info=None,
                          err_message="You don't have the permission to access this issue.",
                          even_admin=False):
    identity = get_jwt_identity()
    user_id = identity['user_id']
    if not even_admin and identity['role_id'] == role.ADMIN.id:
        return
    check_result = verify_issue_user(issue_id, user_id, issue_info)
    if check_result:
        return
    else:
        raise apiError.NotInProjectError(err_message)


def verify_issue_user(issue_id, user_id, issue_info=None):
    if issue_info is None:
        issue_info = get_issue(issue_id)
    project_id = issue_info['project']['id']
    count = model.ProjectUserRole.query.filter_by(
        project_id=project_id, user_id=user_id).count()
    return count > 0


def get_issue(issue_id, with_children=True, journals=True):
    issue = redmine.rm_get_issue(issue_id, journals)
    redmine_issue_status = redmine.rm_get_issue_status()
    closed_statuses = redmine.get_closed_status(
        redmine_issue_status['issue_statuses'])
    if not with_children:
        issue.pop('children', None)
    elif issue.get('children', None):
        for children_issue in issue['children']:
            get_issue_assign_to_detail(children_issue)
    return __deal_with_issue_redmine_output(issue, closed_statuses)


def get_issue_assign_to_detail(issue):
    issue_obj = redmine_lib.redmine.issue.get(issue['id'])
    issue['status'] = {
        'id': issue_obj.status.id,
        'name': issue_obj.status.name
    }
    if hasattr(issue_obj, 'assigned_to'):
        user_relation = nexus.nx_get_user_plugin_relation(
            plan_user_id=issue_obj.assigned_to.id)
        user = model.User.query.get(user_relation.user_id)
        issue['assigned_to'] = {
            'id': user.id,
            'name': user.name,
            'login': user.login
        }
    if not issue.get('tracker', None):
        issue['tracker'] = {
            'id': issue_obj.tracker.id,
            'name': issue_obj.tracker.name
        }
    if not issue.get('subject', None):
        issue['name'] = issue_obj.subject


def create_issue(args, operator_id):
    args = {k: v for k, v in args.items() if v is not None}
    if 'fixed_version_id' in args:
        version = redmine_lib.redmine.version.get(args['fixed_version_id'])
        if version.status in ['locked', 'closed']:
            raise DevOpsError(400, "Error while creating issue",
                              error=apiError.invalid_fixed_version_id(version.name, version.status))
    if 'parent_id' in args:
        args['parent_issue_id'] = args['parent_id']
        args.pop('parent_id', None)
    project_plugin_relation = nexus.nx_get_project_plugin_relation(
        nexus_project_id=args['project_id'])
    args['project_id'] = project_plugin_relation.plan_project_id
    if "assigned_to_id" in args:
        user_plugin_relation = nexus.nx_get_user_plugin_relation(
            user_id=args['assigned_to_id'])
        args['assigned_to_id'] = user_plugin_relation.plan_user_id

    attachment = redmine.rm_upload(args)
    if attachment is not None:
        args['uploads'] = [attachment]

    plan_operator_id = None
    if operator_id is not None:
        operator_plugin_relation = nexus.nx_get_user_plugin_relation(
            user_id=operator_id)
        plan_operator_id = operator_plugin_relation.plan_user_id
    return redmine.rm_create_issue(args, plan_operator_id)


def update_issue(issue_id, args, operator_id):
    args = args.copy()
    args = {k: v for k, v in args.items() if v is not None}
    if 'fixed_version_id' in args:
        if len(args['fixed_version_id']) > 0:
            issue = redmine_lib.redmine.issue.get(issue_id)
            version = redmine_lib.redmine.version.get(args['fixed_version_id'])
            if hasattr(issue, 'fixed_version') and issue.fixed_version.id == version.id:
                pass
            elif version.status in ['locked', 'closed']:
                raise DevOpsError(400, "Error while updating issue",
                                  error=apiError.invalid_fixed_version_id(version.name, version.status))
        else:
            args['fixed_version_id'] = None
    if 'parent_id' in args:
        if len(args['parent_id']) > 0:
            args['parent_issue_id'] = int(args['parent_id'])
        else:
            args['parent_issue_id'] = None
        args.pop('parent_id', None)
    if "assigned_to_id" in args and len(args['assigned_to_id']) > 0:
        user_plugin_relation = nexus.nx_get_user_plugin_relation(
            user_id=int(args['assigned_to_id']))
        args['assigned_to_id'] = user_plugin_relation.plan_user_id

    attachment = redmine.rm_upload(args)
    if attachment is not None:
        args['uploads'] = [attachment]
    plan_operator_id = None
    if operator_id is not None:
        operator_plugin_relation = nexus.nx_get_user_plugin_relation(
            user_id=operator_id)
        plan_operator_id = operator_plugin_relation.plan_user_id
    redmine.rm_update_issue(issue_id, args, plan_operator_id)
    issue = redmine_lib.redmine.issue.get(issue_id)
    output = NexusIssue().set_redmine_issue_v2(issue).to_json()
    family = get_issue_family(issue_id)
    if family.get('parent', None):
        output['parent'] = family['parent']
    elif family.get('children', None):
        output['children'] = family['children']
    return output


def delete_issue(issue_id):
    try:
        redmine.rm_delete_issue(issue_id)
    except DevOpsError as e:
        if e.status_code == 404:
            # Already deleted, let it go
            pass
        else:
            raise e
    return util.success()


def get_issue_by_project(project_id, args):
    if util.is_dummy_project(project_id):
        return []
    try:
        nx_project = NexusProject().set_project_id(project_id)
        plan_id = nx_project.get_plugin_row().plan_project_id
    except NoResultFound:
        raise DevOpsError(404, "Error while getting issues",
                          error=apiError.project_not_found(project_id))
    output_array = []
    redmine_output_issue_array = redmine.rm_get_issues_by_project(
        plan_id, args)
    for redmine_issue in redmine_output_issue_array:
        output_array.append(
            NexusIssue().set_redmine_issue(redmine_issue, nx_project=nx_project).to_json())
    return output_array


def get_issue_by_project_v2(project_id, args):
    output = []
    if util.is_dummy_project(project_id):
        return []
    try:
        nx_project = NexusProject().set_project_id(project_id)
        plan_id = nx_project.get_plugin_row().plan_project_id
    except NoResultFound:
        raise DevOpsError(404, "Error while getting issues",
                          error=apiError.project_not_found(project_id))
    default_filters = get_custom_filters_by_args(args, project_id=plan_id)
    all_issues = redmine_lib.redmine.issue.filter(**default_filters)
    for redmine_issue in all_issues:
        output.append(NexusIssue().set_redmine_issue_v2(redmine_issue).to_json())
    return output


def get_issue_list_by_project(project_id, args):
    nx_issue_params = defaultdict()
    output = []
    if util.is_dummy_project(project_id):
        return []
    try:
        nx_project = NexusProject().set_project_id(project_id)
        plan_id = nx_project.get_plugin_row().plan_project_id
    except NoResultFound:
        raise DevOpsError(404, "Error while getting issues",
                          error=apiError.project_not_found(project_id))

    default_filters = get_custom_filters_by_args(args, project_id=plan_id)
    # multiple_assigned_to = True，代表 filter 跟 assigned_to_id 為不同的 user id
    if default_filters.get('multiple_assigned_to', None) and default_filters['multiple_assigned_to']:
        return []
        # 指定 assigned_to_id 又不存在 multiple_assigned_to 的情況下，
        # default_filters 帶 search ，但沒有取得 issued_id，搜尋結果為空
    elif args.get(
        'search', None) and not default_filters.get(
            'issue_id', None) and default_filters.get(
                'assigned_to_id', None) and 'multiple_assigned_to' not in default_filters:
        return []
    all_issues = redmine_lib.redmine.issue.filter(**default_filters)
    # 透過 selection params 決定是否顯示 family bool 欄位
    if not args['selection'] or not strtobool(args['selection']):
        nx_issue_params['relationship_bool'] = True

    for redmine_issue in all_issues:
        nx_issue_params['redmine_issue'] = redmine_issue
        issue = NexusIssue().set_redmine_issue_v2(**nx_issue_params).to_json()
        # 如果 family 是 False，代表 issue 不是 parent，但必須另外檢查是不是有 children
        if 'family' in issue and not issue['family']:
            check_children = redmine_lib.redmine.issue.filter(parent_id=redmine_issue.id,
                                                              status_id='*')
            if len(check_children):
                issue['has_children'] = True
            else:
                issue['has_children'] = False
        output.append(issue)

    if args['limit'] and args['offset'] is not None:
        page_dict = util.get_pagination(all_issues.total_count,
                                        args['limit'], args['offset'])
        output = {'issue_list': output, 'page': page_dict}
    return output


def get_issue_list_by_user(user_id, args):
    nx_issue_params = defaultdict()
    output = []
    try:
        nx_user = nexus.nx_get_user_plugin_relation(user_id=user_id)
    except NoResultFound:
        raise DevOpsError(404, "Error while getting issues",
                          error=apiError.user_not_found(user_id))
    # args 新增 nx_user_id，在 get_issue_assigned_to_search 需要判斷是否跟 search 結果為同一人
    args['nx_user_id'] = user_id
    default_filters = get_custom_filters_by_args(args, user_id=nx_user.plan_user_id)
    if not args.get('from', None) or args['from'] not in ['author_id', 'assigned_to_id']:
        return []
    # multiple_assigned_to = True，代表 filter 跟 assigned_to_id 為不同的 user id
    elif default_filters.get('multiple_assigned_to', None) and default_filters['multiple_assigned_to']:
        return []
        # from author_id 又不存在 multiple_assigned_to 的情況下，
        # default_filters 帶 search ，但沒有取得 issued_id，搜尋結果為空
    elif args.get(
        'search', None) and not default_filters.get(
            'issue_id', None) and args.get(
                'from', None) == 'author_id' and 'multiple_assigned_to' not in default_filters:
        return []
    all_issues = redmine_lib.redmine.issue.filter(**default_filters)
    # 透過 selection params 決定是否顯示 family bool 欄位
    if not args['selection'] or not strtobool(args['selection']):
        nx_issue_params['relationship_bool'] = True

    for redmine_issue in all_issues:
        nx_issue_params['redmine_issue'] = redmine_issue
        issue = NexusIssue().set_redmine_issue_v2(**nx_issue_params).to_json()
        # 如果 family 是 False，代表 issue 不是 parent，但必須另外檢查是不是有 children
        if 'family' in issue and not issue['family']:
            check_children = redmine_lib.redmine.issue.filter(parent_id=redmine_issue.id,
                                                              status_id='*')
            if len(check_children):
                issue['has_children'] = True
            else:
                issue['has_children'] = False
        output.append(issue)

    if args['limit'] and args['offset'] is not None:
        page_dict = util.get_pagination(all_issues.total_count,
                                        args['limit'], args['offset'])
        output = {'issue_list': output, 'page': page_dict}
    return output


def get_issue_by_tree_by_project(project_id):
    children_issues = []
    tree = defaultdict(dict)
    if util.is_dummy_project(project_id):
        return []
    try:
        nx_project = NexusProject().set_project_id(project_id)
        plan_id = nx_project.get_plugin_row().plan_project_id
    except NoResultFound:
        raise DevOpsError(404, "Error while getting issues",
                          error=apiError.project_not_found(project_id))
    default_filters = get_custom_filters_by_args(project_id=plan_id)
    all_issues = redmine_lib.redmine.issue.filter(**default_filters)
    for redmine_issue in all_issues:
        tree[redmine_issue.id] = NexusIssue().set_redmine_issue_v2(redmine_issue,
                                                                   with_relationship=True).to_json()
    for id in tree:
        # 代表此 issue 有 parent 存在
        if tree[id]['parent']:
            # 補上 parent 相關的資訊
            tree[id]['parent'] = {
                'id': tree[tree[id]['parent']]['id'],
                'name': tree[tree[id]['parent']]['name'],
                'status': tree[tree[id]['parent']]['status'].copy(),
                'tracker': tree[tree[id]['parent']]['tracker'].copy(),
                'assigned_to': tree[tree[id]['parent']]['assigned_to'].copy()
            }
            # 將此 issue 移至其他 issue 的 children 中
            tree[tree[id]['parent']['id']]['children'].append(tree[id].copy())
            # 增加 ouput 需要排除的 children issues 名單
            children_issues.append(id)
    output = [tree[id] for id in tree if id not in children_issues]
    return output


# 依據 params 組成 redmine filters
def get_custom_filters_by_args(args=None, project_id=None, user_id=None):
    default_filters = {'status_id': '*', 'include': 'relations'}
    if project_id:
        default_filters['project_id'] = project_id
    if args:
        if user_id:
            if args.get('from', None) in ['author_id', 'assigned_to_id']:
                default_filters[args['from']] = user_id
            # 如果 from 已經指定 assigned_to_id，但是 params 又有 assigned_to_id 的時候，要從 args 刪除
            if args.get('assigned_to_id', None) and args.get('from', None) == 'assigned_to_id':
                args.pop('assigned_to_id', None)
        handle_allowed_keywords(default_filters, args)
        if args.get('search', None):
            handle_search(default_filters, args)
        # offset 可能為 0
        if args.get('limit', None) and args.get('offset') is not None:
            default_filters['limit'] = args['limit']
            default_filters['offset'] = args['offset']
        if args.get('sort', None):
            default_filters['sort'] = args['sort']
    return default_filters


def handle_allowed_keywords(default_filters, args):
    allowed_keywords = ['fixed_version_id', 'status_id', 'tracker_id', 'assigned_to_id', 'priority_id']
    for key in allowed_keywords:
        if args.get(key, None):
            # 如果 keywords 值為 'null'，python-redmine filter 值為 '!*'
            if args[key] == 'null':
                default_filters[key] = '!*'
            elif key == 'status_id' and args[key] == 'all':
                default_filters[key] = '*'
            # 如果 args[key] 值是 string，且可以被認知為正整數
            elif isinstance(args[key], str) and args[key].isdigit():
                # assigned_to_id 需要另外查詢 plan_user_id
                if key == 'assigned_to_id':
                    try:
                        nx_user = db.session.query(model.UserPluginRelation).join(
                            model.User).filter_by(id=int(args[key])).one()
                    except NoResultFound:
                        raise apiError.DevOpsError(
                            404, 'User id {0} does not exist.'.format(int(args[key])),
                            apiError.user_not_found(int(args[key])))
                    default_filters[key] = nx_user.plan_user_id
                elif key == 'fixed_version_id' or key == 'status_id':
                    default_filters[key] = int(args[key])
            else:
                default_filters[key] = args[key]


def handle_search(default_filters, args):
    result = []
    # 搜尋被分配者
    result.extend(get_issue_assigned_to_search(default_filters, args))
    # 搜尋 issue 標題
    search_title = redmine_lib.redmine.search(args['search'], titles_only=True, resources=['issues'])
    if search_title:
        if search_title.get('issues', None):
            result.extend(list(search_title['issues'].values_list('id', flat=True)))
        if search_title.get('unknown', None):
            result.extend([issue['id'] for issue in search_title['unknown']['issue-closed']])
    # 檢查 keyword 是否為數字
    if args['search'].isdigit():
        # 搜尋 issue id
        search_issue_id = redmine_lib.redmine.issue.filter(**default_filters, issue_id=args['search'])
        if len(search_issue_id):
            result.extend([issue.id for issue in search_issue_id])
    # 去除重複 id
    set(result)
    if result:
        # issue filter 多個 issue_id 只接受逗號分隔的字串
        issue_id = ','.join(str(id) for id in result)
        default_filters['issue_id'] = issue_id


# 搜尋被分配者符合 keyword 的 issues
def get_issue_assigned_to_search(default_filters, args):
    assigned_to_issue = []
    # 使用 ilike 同時搜尋 login 或 name 相符的 user
    nx_user_list = db.session.query(model.UserPluginRelation).join(
        model.User, model.ProjectUserRole).filter(or_(
            model.User.login.ilike(f'%{args["search"]}%'),
            model.User.name.ilike(f'%{args["search"]}%')
        ), model.ProjectUserRole.role_id != 6).all()
    if nx_user_list:
        for nx_user in nx_user_list:
            # 判斷是否多重 assigned_to 的預設值
            default_filters['multiple_assigned_to'] = False
            # 如果有指定 assigned_to_id，判斷是否跟 search 找到的 user 為相同 user_id
            if args.get('assigned_to_id', None):
                if nx_user.user_id != int(args['assigned_to_id']):
                    default_filters['multiple_assigned_to'] = True
                return assigned_to_issue
            # 如果 from 使用的是 assigned_to_id，判斷 url 帶的 user_id 是否跟 search 找到的 user 為相同 user_id
            elif args.get('from') == 'assigned_to_id':
                if nx_user.user_id != args['nx_user_id']:
                    default_filters['multiple_assigned_to'] = True
                return assigned_to_issue
            all_issues = redmine_lib.redmine.issue.filter(**default_filters, assigned_to_id=nx_user.plan_user_id)
            assigned_to_issue.extend([issue.id for issue in all_issues])
    return assigned_to_issue


# 取得 issue 相關的 parent & children & relations 資訊
def get_issue_family(issue_id, args=None):
    output = defaultdict(list)
    if args and args.get('relation', False) and strtobool(args['relation']):
        redmine_issue = redmine_lib.redmine.issue.get(issue_id, include=['children', 'relations'])
        if hasattr(redmine_issue, 'relations') and len(redmine_issue.relations):
            for relation in redmine_issue.relations:
                rel_issue_id = 0
                if relation.issue_id != int(issue_id):
                    rel_issue_id = relation.issue_id
                else:
                    rel_issue_id = relation.issue_to_id
                rel_issue = redmine_lib.redmine.issue.get(rel_issue_id)
                output['relations'].append(NexusIssue().set_redmine_issue_v2(rel_issue).to_json())
    else:
        redmine_issue = redmine_lib.redmine.issue.get(issue_id, include=['children'])
    if hasattr(redmine_issue, 'parent'):
        parent_issue = redmine_lib.redmine.issue.get(redmine_issue.parent.id)
        output['parent'] = NexusIssue().set_redmine_issue_v2(parent_issue).to_json()
    if len(redmine_issue.children):
        children_issues = redmine_lib.redmine.issue.filter(parent_id=issue_id, status_id='*')
        output['children'] = [NexusIssue().set_redmine_issue_v2(redmine_issue).to_json()
                              for redmine_issue in children_issues]
    return output


def get_issue_by_status_by_project(project_id):
    if util.is_dummy_project(project_id):
        return util.success({})
    args = {}
    list_issues = get_issue_by_project(project_id, args)
    get_issue_by_status_output = {}
    for issue in list_issues:
        status = issue['status']['name']
        if status not in get_issue_by_status_output:
            get_issue_by_status_output[status] = []
        get_issue_by_status_output[status].append(
            issue)
    return util.success(get_issue_by_status_output)


def get_issue_by_date_by_project(project_id):
    if util.is_dummy_project(project_id):
        return util.success({})
    args = {}
    issue_list_output = get_issue_by_project(project_id, args)
    get_issue_by_date_output = {}
    for issue_list in issue_list_output:
        issue_updated_date = datetime.strptime(
            issue_list['updated_on'],
            "%Y-%m-%dT%H:%M:%SZ").date().strftime("%Y/%m/%d")
        if issue_updated_date not in get_issue_by_date_output:
            get_issue_by_date_output[issue_updated_date] = []
        get_issue_by_date_output[issue_updated_date].append(issue_list)
    return util.success(get_issue_by_date_output)


def get_issue_progress_or_statistics_by_project(project_id, args, progress=False, statistics=False):
    output = {}
    if util.is_dummy_project(project_id):
        return []
    try:
        nx_project = NexusProject().set_project_id(project_id)
        plan_id = nx_project.get_plugin_row().plan_project_id
    except NoResultFound:
        raise DevOpsError(404, "Error while getting issues",
                          error=apiError.project_not_found(project_id))
    # redmine issue filter 參數，fixed_version_id 為 optional
    filters = {'project_id': plan_id, 'status_id': '*'}
    if args.get('fixed_version_id'):
        filters['fixed_version_id'] = args['fixed_version_id']
    issue_status = {
        status.id: status.name for status in redmine_lib.redmine.issue_status.all()
    }
    if progress:
        output = defaultdict(int)
        calculate_issue_progress(filters, issue_status, output)
    elif statistics:
        output_keys = ['assigned_to', 'priority', 'tracker']
        # output_values 格式: {'xxxx': { "Active": 0, "Assigned": 0, "InProgress": 0 ..... }}
        output_values = defaultdict(
            lambda: defaultdict(
                dict, {status: 0 for status in issue_status.values()}
                )
            )
        output = {key: output_values.copy() for key in output_keys}
        calculate_issue_statistics(filters, issue_status, output_keys, output)
    return output


def calculate_issue_progress(filters, issue_status, output):
    redmine_issues = redmine_lib.redmine.issue.filter(**filters)
    for issue in redmine_issues:
        if issue.status.id in issue_status:
            output[issue.status.name] += 1
        else:
            output['Unknown'] += 1


def calculate_issue_statistics(filters, issue_status, output_keys, output):
    redmine_issues = redmine_lib.redmine.issue.filter(**filters)
    for issue in redmine_issues:
        mappings = {
            'assigned_to': 'Unassigned',
            'priority': issue.priority.name,
            'tracker': issue.tracker.name
        }
        if hasattr(issue, 'assigned_to'):
            user_id = nexus.nx_get_user_plugin_relation(plan_user_id=issue.assigned_to.id).user_id
            user_name = user.NexusUser().set_user_id(user_id).name
            mappings['assigned_to'] = user_name

        for key in output_keys:
            if issue.status.id in issue_status:
                output[key][mappings[key]][issue.status.name] += 1
            else:
                output[key][mappings[key]]['Unknown'] += 1


def get_issue_by_user(user_id):
    user_to_plan, plan_to_user = get_dict_userid()
    output_array = []
    if str(user_id) not in user_to_plan:
        raise DevOpsError(400, 'Cannot find user in redmine.',
                          error=apiError.user_not_found(user_id))
    redmine_output_issue_array = redmine.rm_get_issues_by_user(
        user_to_plan[str(user_id)])
    for redmine_issue in redmine_output_issue_array:
        nx_project = NexusProject().set_plan_project_id(redmine_issue['project']['id'])
        nx_issue = NexusIssue().set_redmine_issue(redmine_issue, nx_project)
        output_array.append(nx_issue)
    return output_array


def list_issue_statuses(data_type):
    issue_statuses = redmine.rm_get_issue_status()
    if data_type == 'api':
        return util.success(issue_statuses['issue_statuses'])
    elif data_type == 'statuses_name':
        statuses = issue_statuses['issue_statuses']
        list_statuses_name = []
        for status in statuses:
            list_statuses_name.append(status['name'])
        return list_statuses_name
    elif data_type == 'issues_count_by_status':
        statuses = issue_statuses['issue_statuses']
        issues_by_statuses = {}
        list_statuses = {}
        for status in statuses:
            status_id = str(status['id'])
            issues_by_statuses[status_id] = 0
            list_statuses[status_id] = status['name']
        issues_by_statuses['-1'] = 0
        list_statuses['-1'] = 'Unknown'
        return issues_by_statuses, list_statuses


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
    user_plugin_relation = nexus.nx_get_user_plugin_relation(user_id=user_id)
    if user_plugin_relation is not None:
        args["assigned_to_id"] = user_plugin_relation.plan_user_id
    redmine_output = redmine.rm_get_statistics(args)
    return util.success({"issue_number": redmine_output["total_count"]})


def get_open_issue_statistics(user_id):
    args = {'limit': 100}
    user_plugin_relation = nexus.nx_get_user_plugin_relation(user_id=user_id)
    if user_plugin_relation is not None:
        args["assigned_to_id"] = user_plugin_relation.plan_user_id
    args['status_id'] = '*'
    total_issue_output = redmine.rm_get_statistics(args)
    args['status_id'] = 'closed'
    closed_issue_output = redmine.rm_get_statistics(args)
    active_issue_number = total_issue_output["total_count"] - \
                          closed_issue_output["total_count"]
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
        raise DevOpsError(400, 'Type error, should be week or month',
                          error=apiError.no_detail())

    args = {"due_date": "><{0}|{1}".format(from_time, to_time)}
    user_plugin_relation = nexus.nx_get_user_plugin_relation(user_id=user_id)
    if user_plugin_relation is not None:
        args["assigned_to_id"] = user_plugin_relation.plan_user_id

    args['status_id'] = '*'
    redmine_output = redmine.rm_get_statistics(args)
    total = redmine_output["total_count"]

    args['status_id'] = 'closed'
    redmine_output_6 = redmine.rm_get_statistics(args)
    closed = redmine_output_6["total_count"]
    return util.success({
        "open": total - closed,
        "closed": closed
    })


def count_project_number_by_issues(user_id):
    project_count = {}
    issues = get_issue_by_user(user_id)
    for issue in issues:
        project_name = issue.get_project_name()
        if project_name not in project_count:
            project_count[project_name] = 1
        else:
            project_count[project_name] += 1
    output = []
    for key, value in project_count.items():
        output.append({'name': key, 'number': value})
    return util.success(output)


def count_priority_number_by_issues(user_id):
    priority_count = {}
    issues = get_issue_by_user(user_id)
    for issue in issues:
        priority = issue.get_priority_name()
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
    issues = get_issue_by_user(user_id)
    for issue in issues:
        tracker = issue.get_tracker_name()
        if tracker not in tracker_count:
            tracker_count[tracker] = 1
        else:
            tracker_count[tracker] += 1
    output = []
    for key, value in tracker_count.items():
        output.append({'name': key, 'number': value})
    return util.success(output)


def row_to_dict(row):
    ret = {}
    for key in type(row).__table__.columns.keys():
        value = getattr(row, key)
        if type(value) is datetime or type(value) is date:
            ret[key] = str(value)
        else:
            ret[key] = value
    return ret


def deal_with_json_string(json_string):
    return json.dumps(json.loads(json_string), ensure_ascii=False, separators=(',', ':'))


def deal_with_parameters(sql_row):
    output = {'id': sql_row.id,
              'name': sql_row.name,
              'parameter_type_id': sql_row.parameter_type_id
              }
    parameter_type_id = str(sql_row.parameter_type_id)
    output['parameter_type'] = 'None'
    if parameter_type_id in PARAMETER_TYPES:
        output['parameter_type'] = PARAMETER_TYPES[parameter_type_id]
    output['description'] = sql_row.description
    output['limitation'] = sql_row.limitation
    output['length'] = sql_row.length
    output['update_at'] = sql_row.update_at.isoformat()
    output['create_at'] = sql_row.create_at.isoformat()
    return output


def get_parameters_by_param_id(parameters_id):
    row = model.Parameters.query.filter_by(id=parameters_id).first()
    output = deal_with_parameters(row)
    return output


def del_parameters_by_param_id(parameters_id):
    row = model.Parameters.query.filter_by(id=parameters_id).one()
    row.disabled = True
    row.update_at = datetime.now()
    db.session.commit()
    return row_to_dict(row)


def modify_parameters_by_param_id(parameters_id, args):
    row = model.Parameters.query.filter_by(id=parameters_id).one()
    row.update_at = datetime.now()
    row.parameter_type_id = args['parameter_type_id']
    row.name = args['name']
    row.description = args['description']
    row.limitation = args['limitation']
    row.length = args['length']
    return row_to_dict(row)


def get_parameters_by_issue_id(issue_id):
    rows = model.Parameters.query.filter_by(issue_id=issue_id).filter(
        model.Parameters.disabled.isnot(True))
    output = []
    for row in rows:
        output.append(deal_with_parameters(row))
    return output


def post_parameters_by_issue_id(issue_id, args):
    new = model.Parameters(
        project_id=args['project_id'],
        issue_id=issue_id,
        parameter_type_id=args['parameter_type_id'],
        name=args['name'],
        description=args['description'],
        limitation=args['limitation'],
        length=args['length'],
        create_at=datetime.now(),
        update_at=datetime.now()
    )
    db.session.add(new)
    db.session.commit()
    return {'parameters_id': new.id}


def get_parameter_types():
    output = []
    for key in PARAMETER_TYPES:
        temp = {"parameter_type_id": key, "name": PARAMETER_TYPES[key]}
        output.append(temp)
    return output


def get_flow_support_type():
    output = []
    for key in FLOW_TYPES:
        output.append({"flow_type_id": int(key), "name": FLOW_TYPES[key]})
    return output


def deal_with_flow_object(sql_row):
    return {'id': sql_row.id,
            'project_id': sql_row.project_id,
            'issue_id': sql_row.issue_id,
            'requirement_id': sql_row.requirement_id,
            'type_id': sql_row.type_id,
            'name': sql_row.name,
            'description': sql_row.description,
            'serial_id': sql_row.serial_id,
            'update_at': util.date_to_str(sql_row.update_at),
            'create_at': util.date_to_str(sql_row.create_at)
            }


def get_flow_by_flow_id(flow_id):
    f = model.Flows.query.filter_by(id=flow_id).one()
    return deal_with_flow_object(f)


def disabled_flow_by_flow_id(flow_id):
    f = model.Flows.query.filter_by(id=flow_id).one()
    f.disabled = True
    f.update_at = datetime.now()
    db.session.commit()
    return {'last_modified': f.update_at}


def modify_flow_by_flow_id(flow_id, args):
    f = model.Flows.query.filter_by(id=flow_id)
    f.type_id = args['type_id'],
    f.name = args['name'],
    f.description = args['description'],
    f.serial_id = args['serial_id'],
    f.update_at = datetime.now()
    db.session.commit()
    return {'last_modified': f.update_at}


def get_flow_by_requirement_id(requirement_id):
    rows = model.Flows.query.filter_by(requirement_id=requirement_id).filter(
        model.Flows.disabled.isnot(True)).all()
    output = []
    for row in rows:
        output.append(deal_with_flow_object(row))
    return output


def post_flow_by_requirement_id(issue_id, requirement_id, args):
    rows = model.Flows.query.filter_by(requirement_id=requirement_id). \
        order_by(model.Flows.serial_id).all()
    flow_serial_ids = []
    for row in rows:
        flow_serial_ids.append(row.serial_id)

    if not flow_serial_ids:
        serial_number = 1
    else:
        serial_number = max(flow_serial_ids) + 1
    new = model.Flows(
        project_id=args['project_id'],
        issue_id=issue_id,
        requirement_id=requirement_id,
        type_id=args['type_id'],
        name=args['name'],
        description=args['description'],
        serial_id=serial_number,
        create_at=datetime.now(),
        update_at=datetime.now())
    db.session.add(new)
    db.session.commit()
    return {'flow_id': new.id}


def _deal_with_json(json_string):
    return json.dumps(json.loads(json_string),
                      ensure_ascii=False,
                      separators=(',', ':'))


def check_requirement_by_issue_id(issue_id):
    rows = model.Requirements.query.filter_by(
        issue_id=issue_id).order_by(model.Requirements.id).all()
    requirement_ids = []
    for row in rows:
        requirement_ids.append(row.id)

    return requirement_ids


def get_requirement_by_rqmt_id(requirement_id):
    r = model.Requirements.query.filter_by(id=requirement_id).first()
    return {'flow_info': json.loads(str(r.flow_info))}


# 將 requirement 隱藏
def del_requirement_by_rqmt_id(requirement_id):
    r = model.Requirements.query.filter_by(id=requirement_id).first()
    r.disabled = True
    r.update_at = datetime.now()
    db.session.commit()
    return row_to_dict(r)


def modify_requirement_by_rqmt_id(requirement_id, args):
    r = model.Requirements.query.filter_by(id=requirement_id).first()
    r.update_at = datetime.now()
    r.flow_info = _deal_with_json(args['flow_info'])
    db.session.commit()
    return row_to_dict(r)


def get_requirements_by_issue_id(issue_id):
    rows = model.Requirements.query.filter_by(issue_id=issue_id).filter(
        model.Requirements.disabled.isnot(True)).all()
    output = []
    for row in rows:
        output.append(json.loads(row.flow_info))
    return {'flow_info': output}


def post_requirement_by_issue_id(issue_id, args):
    new = model.Requirements(
        project_id=args['project_id'],
        issue_id=issue_id,
        create_at=datetime.now(),
        update_at=datetime.now())
    db.session.add(new)
    db.session.commit()
    return {'requirement_id': new.id}


def get_requirements_by_project_id(project_id):
    rows = model.Requirements.query.filter_by(
        project_id=project_id).filter(model.Requirements.disabled.isnot(True)).all()
    output = []
    for row in rows:
        output.append(json.loads(row.flow_info))
    return {'flow_info': output}


def post_issue_relation(issue_id, issue_to_id):
    return redmine_lib.rm_post_relation(issue_id, issue_to_id)


def put_issue_relation(issue_id, issue_to_ids):
    input_set= set()
    origin_set = set()
    for issue_to_id in issue_to_ids:
        input_set.add(frozenset({issue_id, issue_to_id}))
    redmine_issue = redmine.rm_get_issue(issue_id)
    if "relations" in redmine_issue:
        relations = redmine_issue["relations"]
        for relation in relations:
            origin_set.add(frozenset({relation['issue_id'], relation['issue_to_id']}))
        need_del_set = origin_set - input_set
        for need_del in list(need_del_set):
            need_del = list(need_del)
            for relation in relations:
                if (relation['issue_id'] == need_del[0] and relation['issue_to_id'] == need_del[1]) or \
                    (relation['issue_id'] == need_del[1] and relation['issue_to_id'] == need_del[0]):
                    redmine_lib.rm_delete_relation(relation['id'])
    need_add_set = input_set - origin_set
    for need_add in list(need_add_set):
        need_add = list(need_add)
        redmine_lib.rm_post_relation(need_add[0], need_add[1])


def delete_issue_relation(relation_id):
    return redmine_lib.rm_delete_relation(relation_id)


def check_issue_closable(issue_id):
    # loop 離開標誌
    exit_flag = False
    # 已完成 issues
    finished_issues = []
    # 未完成 issues，預設為 request 的 issue_id
    unfinished_issues = [issue_id]
    while unfinished_issues and not exit_flag:
        for id in unfinished_issues:
            # 已完成 issue_id 不需重複檢查
            if id not in finished_issues:
                try:
                    issue = redmine_lib.redmine.issue.get(id)
                except redminelibError.ResourceNotFoundError:
                    raise apiError.DevOpsError(
                        404, 'Got non-2xx response from Redmine.',
                        apiError.redmine_error('Error while geting issue.'))
                # 如果 issue status 不是 Closed
                # 如果 id 非預設 request 的 issue_id
                if issue.status.id != 6 and id != issue_id:
                    # 設置離開標誌，break
                    exit_flag = True
                    break
                # 若 issue 的 children 存在，將 children issue id 放入未完成 issues 中
                elif issue.children.total_count != 0:
                    unfinished_issues.extend([children_issue.id for children_issue in issue.children])
                    # 消除重複的 issue_id
                    set(unfinished_issues)
                # 將上述動作完成的 issue 從未完成-->已完成
                unfinished_issues.remove(id)
                finished_issues.append(id)
    # 若未完成的 issues 存在，回傳布林值
    if unfinished_issues:
        return False
    else:
        return True


# --------------------- Resources ---------------------
class SingleIssue(Resource):
    @jwt_required
    def get(self, issue_id):
        issue_info = get_issue(issue_id)
        require_issue_visible(issue_id, issue_info)
        if 'parent_id' in issue_info:
            parent_info = get_issue(issue_info['parent_id'], with_children=False)
            parent_info['name'] = parent_info.pop('subject', None)
            issue_info.pop('parent_id', None)
            issue_info['parent'] = parent_info
        return util.success(issue_info)

    @jwt_required
    def post(self):
        parser = reqparse.RequestParser()
        parser.add_argument('project_id', type=int, required=True)
        parser.add_argument('tracker_id', type=int, required=True)
        parser.add_argument('status_id', type=int, required=True)
        parser.add_argument('priority_id', type=int, required=True)
        parser.add_argument('subject', type=str, required=True)
        parser.add_argument('description', type=str)
        parser.add_argument('assigned_to_id', type=int)
        parser.add_argument('parent_id', type=int)
        parser.add_argument('fixed_version_id', type=int)
        parser.add_argument('start_date', type=str)
        parser.add_argument('due_date', type=str)
        parser.add_argument('done_ratio', type=int)
        parser.add_argument('estimated_hours', type=int)

        # Attachment upload
        parser.add_argument(
            'upload_file', type=werkzeug.datastructures.FileStorage, location='files')
        parser.add_argument('upload_filename', type=str)
        parser.add_argument('upload_description', type=str)
        parser.add_argument('upload_content_type', type=str)

        args = parser.parse_args()
        rm_output = create_issue(args, get_jwt_identity()['user_id'])
        return util.success({"issue_id": rm_output["issue"]["id"]})

    @jwt_required
    def put(self, issue_id):
        require_issue_visible(issue_id)
        parser = reqparse.RequestParser()
        parser.add_argument('assigned_to_id', type=str)
        parser.add_argument('tracker_id', type=int)
        parser.add_argument('status_id', type=int)
        parser.add_argument('priority_id', type=int)
        parser.add_argument('estimated_hours', type=int)
        parser.add_argument('description', type=str)
        parser.add_argument('parent_id', type=str)
        parser.add_argument('fixed_version_id', type=str)
        parser.add_argument('subject', type=str)
        parser.add_argument('start_date', type=str)
        parser.add_argument('due_date', type=str)
        parser.add_argument('done_ratio', type=int)
        parser.add_argument('notes', type=str)

        # Attachment upload
        parser.add_argument(
            'upload_file', type=werkzeug.datastructures.FileStorage, location='files')
        parser.add_argument('upload_filename', type=str)
        parser.add_argument('upload_description', type=str)
        parser.add_argument('upload_content_type', type=str)

        args = parser.parse_args()
        # Handle removable int parameters
        keys_int_or_null = ['assigned_to_id', 'fixed_version_id', 'parent_id']
        for k in keys_int_or_null:
            if args[k] == 'null':
                args[k] = ''
        output = update_issue(issue_id, args, get_jwt_identity()['user_id'])
        return util.success(output)

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
        output = get_issue_by_project_v2(project_id, args)
        return util.success(output)


class IssueListByProject(Resource):
    @jwt_required
    def get(self, project_id):
        role.require_in_project(project_id, 'Error to get issue.')
        parser = reqparse.RequestParser()
        parser.add_argument('fixed_version_id', type=str)
        parser.add_argument('status_id', type=str)
        parser.add_argument('tracker_id', type=int)
        parser.add_argument('assigned_to_id', type=str)
        parser.add_argument('priority_id', type=int)
        parser.add_argument('limit', type=int)
        parser.add_argument('offset', type=int)
        parser.add_argument('search', type=str)
        parser.add_argument('selection', type=str)
        parser.add_argument('sort', type=str)
        args = parser.parse_args()
        output = get_issue_list_by_project(project_id, args)
        return util.success(output)


class IssueListByUser(Resource):
    @jwt_required
    def get(self, user_id):
        parser = reqparse.RequestParser()
        parser.add_argument('fixed_version_id', type=str)
        parser.add_argument('status_id', type=str)
        parser.add_argument('tracker_id', type=int)
        parser.add_argument('assigned_to_id', type=str)
        parser.add_argument('priority_id', type=int)
        parser.add_argument('limit', type=int)
        parser.add_argument('offset', type=int)
        parser.add_argument('search', type=str)
        parser.add_argument('selection', type=str)
        parser.add_argument('from', type=str)
        parser.add_argument('sort', type=str)
        args = parser.parse_args()
        output = get_issue_list_by_user(user_id, args)
        return util.success(output)


class IssueByVersion(Resource):
    @jwt_required
    def get(self, project_id):
        role.require_in_project(project_id, 'Error to get issue.')
        parser = reqparse.RequestParser()
        parser.add_argument('fixed_version_id')
        args = parser.parse_args()

        return util.success(get_issue_by_project(project_id, args))


class IssueByTreeByProject(Resource):
    @jwt_required
    def get(self, project_id):
        role.require_in_project(project_id, 'Error to get issue.')
        output = get_issue_by_tree_by_project(project_id)
        return util.success(output)


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
        output = get_issue_progress_or_statistics_by_project(project_id,
                                                             args, progress=True)
        return util.success(output)


class IssuesStatisticsByProject(Resource):
    @jwt_required
    def get(self, project_id):
        role.require_in_project(project_id)
        parser = reqparse.RequestParser()
        parser.add_argument('fixed_version_id', type=int)
        args = parser.parse_args()
        output = get_issue_progress_or_statistics_by_project(project_id,
                                                             args, statistics=True)
        return util.success(output)


class IssueStatus(Resource):
    @jwt_required
    def get(self):
        return list_issue_statuses('api')


class IssuePriority(Resource):
    @jwt_required
    def get(self):
        return get_issue_priority()


class IssueTracker(Resource):
    @jwt_required
    def get(self):
        return get_issue_trackers()


class IssueFamily(Resource):
    @jwt_required
    def get(self, issue_id):
        require_issue_visible(issue_id)
        parser = reqparse.RequestParser()
        parser.add_argument('relation', type=str)
        args = parser.parse_args()
        family = get_issue_family(issue_id, args)
        return util.success(family)


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


class RequirementByIssue(Resource):

    # 用issues ID 取得目前所有的需求清單
    @jwt_required
    def get(self, issue_id):
        output = get_requirements_by_issue_id(issue_id)
        return util.success(output)

    # 用issues ID 新建立需求清單
    @jwt_required
    def post(self, issue_id):
        parser = reqparse.RequestParser()
        parser.add_argument('project_id', type=int)
        # parser.add_argument('flow_info', type=str)
        args = parser.parse_args()
        output = post_requirement_by_issue_id(issue_id, args)
        return util.success(output)


class Requirement(Resource):

    # 用requirement_id 取得目前需求流程
    @jwt_required
    def get(self, requirement_id):
        output = get_requirement_by_rqmt_id(requirement_id)
        return util.success(output)

    # 用requirement_id 刪除目前需求流程
    @jwt_required
    def delete(self, requirement_id):
        del_requirement_by_rqmt_id(requirement_id)
        return util.success()

    # 用requirement_id 更新目前需求流程
    @jwt_required
    def put(self, requirement_id):
        parser = reqparse.RequestParser()
        parser.add_argument('flow_info', type=str)
        args = parser.parse_args()
        modify_requirement_by_rqmt_id(requirement_id, args)
        return util.success()


class GetFlowType(Resource):
    @jwt_required
    def get(self):
        output = get_flow_support_type()
        return util.success(output)


class FlowByIssue(Resource):

    # 用issues ID 取得目前所有的需求清單
    @jwt_required
    def get(self, issue_id):
        requirement_ids = check_requirement_by_issue_id(issue_id)
        if not requirement_ids:
            return util.success()
        output = []
        for requirement_id in requirement_ids:
            result = get_flow_by_requirement_id(requirement_id)
            if len(result) > 0:
                output.append({
                    'requirement_id': requirement_id,
                    'flow_data': result
                })
        return util.success(output)

    # 用issues ID 新建立需求清單
    @jwt_required
    def post(self, issue_id):
        parser = reqparse.RequestParser()
        parser.add_argument('project_id', type=int)
        parser.add_argument('type_id', type=int)
        parser.add_argument('name', type=str)
        parser.add_argument('description', type=str)
        args = parser.parse_args()
        requirements = check_requirement_by_issue_id(issue_id)
        if len(requirements) == 0:
            new = post_requirement_by_issue_id(issue_id, args)
            requirement_id = new['requirement_id']
        else:
            requirement_id = requirements[0]

        output = post_flow_by_requirement_id(
            int(issue_id), requirement_id, args)
        return util.success(output, has_date_etc=True)


class Flow(Resource):

    # 用requirement_id 取得目前需求流程
    @jwt_required
    def get(self, flow_id):
        output = get_flow_by_flow_id(flow_id)
        return util.success(output)

    # 用requirement_id 刪除目前需求流程
    @jwt_required
    def delete(self, flow_id):
        output = disabled_flow_by_flow_id(flow_id)
        return util.success(output, has_date_etc=True)

    # 用requirement_id 更新目前需求流程
    @jwt_required
    def put(self, flow_id):
        parser = reqparse.RequestParser()
        parser.add_argument('serial_id', type=int)
        parser.add_argument('type_id', type=int)
        parser.add_argument('name', type=str)
        parser.add_argument('description', type=str)
        args = parser.parse_args()
        output = modify_flow_by_flow_id(flow_id, args)
        return util.success(output, has_date_etc=True)


class ParameterType(Resource):
    @jwt_required
    def get(self):
        output = get_parameter_types()
        return util.success(output)


class ParameterByIssue(Resource):

    # 用issues ID 取得目前所有的需求清單
    @jwt_required
    def get(self, issue_id):
        output = get_parameters_by_issue_id(issue_id)
        return util.success(output)

    # 用issues ID 新建立需求清單
    @jwt_required
    def post(self, issue_id):
        parser = reqparse.RequestParser()
        parser.add_argument('project_id', type=int)
        parser.add_argument('parameter_type_id', type=int)
        parser.add_argument('name', type=str)
        parser.add_argument('description', type=str)
        parser.add_argument('limitation', type=str)
        parser.add_argument('length', type=int)
        args = parser.parse_args()
        output = post_parameters_by_issue_id(issue_id, args)
        return util.success(output)


class Parameter(Resource):

    # 用requirement_id 取得目前需求流程
    @jwt_required
    def get(self, parameter_id):
        output = get_parameters_by_param_id(parameter_id)
        return util.success(output)

    # 用requirement_id 刪除目前需求流程
    @jwt_required
    def delete(self, parameter_id):
        output = del_parameters_by_param_id(parameter_id)
        return util.success(output)

    # 用requirement_id 更新目前需求流程
    @jwt_required
    def put(self, parameter_id):
        parser = reqparse.RequestParser()
        parser.add_argument('parameter_type_id', type=int)
        parser.add_argument('name', type=str)
        parser.add_argument('description', type=str)
        parser.add_argument('limitation', type=str)
        parser.add_argument('length', type=int)
        args = parser.parse_args()
        output = modify_parameters_by_param_id(parameter_id, args)
        return util.success(output)


class Relation(Resource):
    def post(self):
        parser = reqparse.RequestParser()
        parser.add_argument('issue_id', type=int, required=True)
        parser.add_argument('issue_to_id', type=int, required=True)
        args = parser.parse_args()
        output = post_issue_relation(args['issue_id'], args['issue_to_id'])
        return util.success(output)

    def put(self):
        parser = reqparse.RequestParser()
        parser.add_argument('issue_id', type=int, required=True)
        parser.add_argument('issue_to_ids', type=list, location='json', required=True)
        args = parser.parse_args()
        put_issue_relation(args['issue_id'], args['issue_to_ids'])
        return util.success()

    def delete(self, relation_id):
        output = delete_issue_relation(relation_id)
        return util.success(output)


class CheckIssueClosable(Resource):
    @jwt_required
    def get(self, issue_id):
        output = check_issue_closable(issue_id)
        return util.success(output)
