import calendar
import json
from collections import defaultdict
from datetime import datetime, date, timedelta
from distutils.util import strtobool

import werkzeug
from flask_socketio import Namespace, emit, join_room, leave_room
from flask_jwt_extended import jwt_required, get_jwt_identity
from flask_restful import Resource, reqparse
from redminelib import exceptions as redminelibError
from sqlalchemy import or_
from sqlalchemy.dialects.postgresql import Any
from sqlalchemy.orm.exc import NoResultFound
from sqlalchemy.sql import operators

import re
import threading
import os
from flask import send_file
from pathlib import Path
import config
import model
import nexus
import resources.apiError as apiError
import resources.user as user
import util as util
from resources.tag import get_tag
from accessories import redmine_lib
from data.nexus_project import NexusProject
from enums.action_type import ActionType
from model import db, IssueExtensions, CustomIssueFilter
from resources.apiError import DevOpsError
from resources.redmine import redmine
from resources import project as project_module, project, role
from resources.activity import record_activity
from resources import tag as tag_py
from resources.user import user_list_by_project
from redminelib.exceptions import ResourceAttrError
from resources import logger
from resources.lock import get_lock_status
from resources.project_relation import project_has_child, project_has_parent
from flask_apispec import marshal_with, doc, use_kwargs
from flask_apispec.views import MethodResource
from . import route_model

FLOW_TYPES = {"0": "Given", "1": "When", "2": "Then", "3": "But", "4": "And"}
PARAMETER_TYPES = {'1': '文字', '2': '英數字', '3': '英文字', '4': '數字'}
STATUS_TRANSLATE = {
    "Active": '已開立',
    "Assigned": '已分派',
    "InProgress": '進行中',
    "Solved": '已解決',
    "Verified": '已確認',
    "Closed": '已關閉',
    "Responded": '已回應',
    "Finished": '已完成',
}
PRIORITY_TRANSLATE = {"Low": '低', "Normal": '一般', "High": '高', "Immediate": '緊急'}
TRACKER_TRANSLATE = {
    "Document": '文件',
    "Research": '研究',
    "Epic": '需求規格',
    "Audit": '情境故事',
    "Feature": '功能設計',
    "Bug": '程式錯誤',
    "Issue": '議題',
    "Change Request": '變更請求',
    "Risk": '風險管理',
    "Test Plan": '測試計畫',
    "Fail Management": '異常管理',
}


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
            parent_issue = get_issue_assign_to_detail(redmine_issue['parent'])
            self.data['parent'] = parent_issue
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
                             relationship_bool=False, nx_project=None, users_info=None, with_point=False):

        self.data = {
            'id': redmine_issue.id,
            'name': redmine_issue.subject,
            'project': None,
            'description': None,
            'updated_on': redmine_issue.updated_on.isoformat(),
            'start_date': None,
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
            "tags": get_issue_tags(redmine_issue.id),

        }
        if hasattr(redmine_issue, 'project'):
            project_id = nexus.nx_get_project_plugin_relation(
                    rm_project_id=redmine_issue.project.id).project_id
            if nx_project is None or project_has_child(project_id) or project_has_parent(project_id):
                nx_project = model.Project.query.get(project_id)
            self.data['project'] = {
                'id': nx_project.id,
                'name': nx_project.name,
                'display': nx_project.display
            }
        self.data['has_children'] = False
        if redmine_issue.children.total_count > 0:
            self.data['has_children'] = True
        if relationship_bool:
            self.data['family'] = False
            if hasattr(redmine_issue, 'parent') or redmine_issue.relations.total_count > 0 \
                    or self.data['has_children']:
                self.data['family'] = True
        if with_relationship:
            self.data['parent'] = None
            self.data['children'] = []
            if hasattr(redmine_issue, 'parent'):
                self.data['parent'] = redmine_issue.parent.id
        if hasattr(redmine_issue, 'author'):
            if users_info is not None:
                for user_info in users_info:
                    if user_info[3] == redmine_issue.author.id:
                        self.data['author'] = {
                            'id': user_info[0],
                            'name': user_info[1]
                        }
                        break
            else:
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
            if users_info is not None:
                for user_info in users_info:
                    if user_info[3] == redmine_issue.assigned_to.id:
                        self.data['assigned_to'] = {
                            'id': user_info[0],
                            'name': user_info[1],
                            'login': user_info[2]
                        }
                        break
            else:
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

        if with_point:
            self.data["point"] = get_issue_point(self.data["id"])
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


def convert_list_tag_id_to_name(tag_list):
    if tag_list == [""]:
        return []
    return[model.Tag.query.get(int(id)).name for id in sorted(tag_list)]


def check_tags_id_is_int(tags):
    if tags == [""]:
        return []
    tag_ids = list(set([int(tag) for tag in tags]))
    tag_ids.sort()
    return tag_ids

def tags_note_json(id, name, add=True):
    if add:
        note = {
            'details': [
                {
                    'name': 'tag',
                    'property': 'attr',
                    'old_value': {
                        'id': None,
                        'name': None,
                    },
                    'new_value': {
                        'id': id,
                        'name': name,
                    }
                }
            ]
        }
    else:
        note = {
            'details': [
                {
                    'name': 'tag',
                    'property': 'attr',
                    'old_value': {
                        'id': id,
                        'name': name,
                    },
                    'new_value': {
                        'id': None,
                        'name': None,
                    }
                }
            ]
        }
    return json.dumps(note, ensure_ascii=False)
    # return note


def create_issue_tags(issue_id, tags, plan_operator_id):
    new_tag_list = sorted(check_tags_id_is_int(tags))
    new = model.IssueTag(
        issue_id=issue_id,
        tag_id=new_tag_list
    )
    db.session.add(new)
    db.session.commit()

    # Record issue_tags changes in notes
    add_tags = check_tags_diff(new_tag_list, [])
    if add_tags != {}:
        for tag_id, tag_name in add_tags.items():
            redmine.rm_update_issue(
                issue_id, {"notes": tags_note_json(tag_id, tag_name)}, plan_operator_id)
    return new.issue_id


def update_issue_tags(issue_id, tags, plan_operator_id):
    issue_tags = model.IssueTag.query.filter_by(issue_id=issue_id).first()
    if issue_tags is None:
        return create_issue_tags(issue_id, tags, plan_operator_id)

    # Record issue_tags changes in notes
    new_tag_list = sorted(check_tags_id_is_int(tags))
    origin_tag_list = sorted(issue_tags.tag_id)

    if new_tag_list != origin_tag_list:
        issue_tags.tag_id = new_tag_list
        db.session.commit()
        args = {"notes": ""}
        add_tags = check_tags_diff(new_tag_list, origin_tag_list)
        if add_tags != {}:
            for tag_id, tag_name in add_tags.items():
                redmine.rm_update_issue(
                    issue_id, {"notes": tags_note_json(tag_id, tag_name)}, plan_operator_id)

        delete_tags = check_tags_diff(origin_tag_list, new_tag_list)
        if delete_tags != {}:
            for tag_id, tag_name in delete_tags.items():
                redmine.rm_update_issue(
                    issue_id, {"notes": tags_note_json(tag_id, tag_name, add=False)}, plan_operator_id)
    return issue_tags.issue_id

def check_tags_diff(fir_tags, sec_tags):
    return {int(item): model.Tag.query.get(int(item)).name for item in fir_tags if item not in sec_tags} 


def delete_issue_tags(issue_id):
    issue_tags = model.IssueTag.query.filter_by(issue_id=issue_id).first()
    if issue_tags is not None:
        db.session.delete(issue_tags)
        db.session.commit()


def get_issue_tags(issue_id):
    issue_tags = model.IssueTag.query.filter_by(issue_id=issue_id).first()
    if issue_tags is None:
        return []
    tags = tag_py.get_tags_for_dict()
    output = []
    if len(issue_tags.tag_id) == 0:
        return output
    for tag_id in issue_tags.tag_id:
        if tag_id in tags:
            output.append(tags[tag_id])
    return output


def search_issue_tags_by_tags(tags):
    tags = check_tags_id_is_int(tags.split(","))
    issues = db.session.query(model.IssueTag).filter(
        or_(model.IssueTag.tag_id.any(v) for v in tags)
    ).all()

    return [issue.issue_id for issue in issues]


def get_issue_point(issue_id):
    point = 0
    issue = IssueExtensions.query.filter_by(issue_id=issue_id).first()
    if issue is not None:
        point = issue.point
    else:
        create_issue_extensions(issue_id, point)
    return point


def create_issue_extensions(issue_id, point=0):
    issue = IssueExtensions(issue_id=issue_id, point=point)
    db.session.add(issue)
    db.session.commit()


def update_issue_point(issue_id, point):
    issue = IssueExtensions.query.filter_by(issue_id=issue_id).first()
    if issue is not None:
        issue.point = point
        db.session.commit()
    else:
        create_issue_extensions(issue_id, point)


def delete_issue_extensions(issue_id):
    issue = IssueExtensions.query.filter_by(issue_id=issue_id).first()
    if issue is not None:
        db.session.delete(issue)
        db.session.commit()


def __get_plan_user_id(operator_id):
    if operator_id is not None:
        operator_plugin_relation = nexus.nx_get_user_plugin_relation(
            user_id=operator_id)
        return operator_plugin_relation.plan_user_id


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
                            if user_info is not None:
                                detail_info['old_value'] = {
                                    'user': {'id': user_info.id, 'name': user_info.name}}
                        else:
                            detail_info['old_value'] = detail['old_value']
                        if detail['new_value'] is not None:
                            user_info = user.get_user_id_name_by_plan_user_id(
                                detail['new_value'])
                            if user_info is not None:
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
            attachment[
                'content_url'] = f'{config.get("REDMINE_EXTERNAL_BASE_URL")}/attachments/download/{attachment["id"]}/{attachment["filename"]}'
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
        issue_info = get_issue(issue_id, False, False)
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
        children_detail = []
        for children_issue in issue['children']:
            children_detail.append(get_issue_assign_to_detail(children_issue))
        issue["children"] = children_detail
    return __deal_with_issue_redmine_output(issue, closed_statuses)


def get_issue_assign_to_detail(issue):
    issue_detail = {"id": issue['id']}
    issue_obj = redmine_lib.redmine.issue.get(issue['id'])
    issue_detail['status'] = {
        'id': issue_obj.status.id,
        'name': issue_obj.status.name
    }
    if hasattr(issue_obj, 'assigned_to'):
        user_relation = nexus.nx_get_user_plugin_relation(
            plan_user_id=issue_obj.assigned_to.id)
        user = model.User.query.get(user_relation.user_id)
        issue_detail['assigned_to'] = {
            'id': user.id,
            'name': user.name,
            'login': user.login
        }
    if hasattr(issue_obj, 'tracker'):
        issue_detail['tracker'] = {
            'id': issue_obj.tracker.id,
            'name': issue_obj.tracker.name
        }
    if hasattr(issue_obj, 'subject'):
        issue_detail['name'] = issue_obj.subject
    return issue_detail


def create_issue(args, operator_id):
    args = {k: v for k, v in args.items() if v is not None}
    if 'fixed_version_id' in args:
        if len(args['fixed_version_id']) > 0 and args['fixed_version_id'].isdigit():
            args['fixed_version_id'] = int(args['fixed_version_id'])
            version = redmine_lib.redmine.version.get(args['fixed_version_id'])
            if version.status in ['locked', 'closed']:
                raise DevOpsError(400, "Error while creating issue",
                                  error=apiError.invalid_fixed_version_id(version.name, version.status))
        else:
            args['fixed_version_id'] = None
    if 'parent_id' in args:
        if len(args['parent_id']) > 0 and args['parent_id'].isdigit():
            args['parent_issue_id'] = int(args['parent_id'])
            args.pop('parent_id', None)
        else:
            args['parend_issue_id'] = None

    project_plugin_relation = nexus.nx_get_project_plugin_relation(
        nexus_project_id=args['project_id'])
    args['project_id'] = project_plugin_relation.plan_project_id

    if "assigned_to_id" in args:
        if len(args['assigned_to_id']) > 0 and args['assigned_to_id'].isdigit():
            user_plugin_relation = nexus.nx_get_user_plugin_relation(
                user_id=int(args['assigned_to_id']))
            args['assigned_to_id'] = user_plugin_relation.plan_user_id
        else:
            args['assigned_to_id'] = None

    point = args.pop("point", 0)
    # Get Tags ID
    tags = args.pop("tags", None)

    attachment = redmine.rm_upload(args)
    if attachment is not None:
        args['uploads'] = [attachment]

    plan_operator_id = None
    if operator_id is not None:
        operator_plugin_relation = nexus.nx_get_user_plugin_relation(
            user_id=operator_id)
        plan_operator_id = operator_plugin_relation.plan_user_id
    created_issue = redmine.rm_create_issue(args, plan_operator_id)
    created_issue_id = created_issue["issue"]["id"]
    issue = redmine_lib.redmine.issue.get(created_issue_id)
    output = NexusIssue().set_redmine_issue_v2(issue).to_json()

    create_issue_extensions(output["id"], point=point)
    output["point"] = point
    if tags is not None:
        tag_ids = tags.strip().split(',')
        if tags.strip() != "" and len(tag_ids) > 0:
            issue_tags = create_issue_tags(output["id"], tag_ids, plan_operator_id)
    output['tags'] = get_issue_tags(output["id"])

    family = get_issue_family(issue)
    if family.get('parent') is not None:
        output['parent'] = family['parent']
    elif family.get('children') is not None:
        output['children'] = family['children']
    elif family.get('relations') is not None:
        output['relations'] = family['relations']
    emit("add_issue", output, namespace="/issues/websocket", to=output['project']['id'], broadcast=True)
    return output


def update_issue(issue_id, args, operator_id=None):
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

    point = args.pop("point", None)
    tags = args.pop("tags", None)
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
    if point is not None:
        update_issue_point(output["id"], point)
        output["point"] = point
    else:
        output["point"] = get_issue_point(output["id"])

    if tags is not None:
        tag_ids = tags.strip().split(',')
        update_issue_tags(output["id"], tag_ids, plan_operator_id)
    output["tags"] = get_issue_tags(output["id"])

    family = get_issue_family(issue)
    if family.get('parent', None):
        output['parent'] = family['parent']
    elif family.get('children', None):
        output['children'] = family['children']
    elif family.get('relations', None):
        output['relations'] = family['relations']
    emit("update_issue", output, namespace="/issues/websocket", to=output['project']['id'], broadcast=True)
    return output


@record_activity(ActionType.DELETE_ISSUE)
def delete_issue(issue_id):
    try:
        require_issue_visible(issue_id)
        project_id = nexus.nx_get_project_plugin_relation(
                    rm_project_id=redmine_lib.redmine.issue.get(issue_id).project.id).project_id
        redmine.rm_delete_issue(issue_id)
        delete_issue_extensions(issue_id)
        delete_issue_tags(issue_id)
        emit("delete_issue", {"id": issue_id}, namespace="/issues/websocket", to=project_id, broadcast=True)
    except DevOpsError as e:
        print(e.status_code)
        if e.status_code == 404:
            # Already deleted, let it go
            pass
        else:
            raise e
    return "success"


def get_issue_by_project(project_id, args):
    if util.is_dummy_project(project_id):
        return []
    try:
        nx_project = NexusProject().set_project_id(project_id)
        plan_id = nx_project.get_project_row().plugin_relation.plan_project_id
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

def handle_exceed_limit_length_default_filter(default_filters, issue_ids, default_filters_list):
    if issue_ids == []:
        return default_filters_list
    default_filters_copy = default_filters.copy()
    default_filters_copy["issue_id"] = ",".join(issue_ids[:200])   
    default_filters_list.append(default_filters_copy)
    return handle_exceed_limit_length_default_filter(default_filters, issue_ids[200:], default_filters_list)


def get_issue_list_by_project(project_id, args, download=False):
    nx_issue_params = defaultdict()
    output = []
    if util.is_dummy_project(project_id):
        return []
    try:
        nx_project = NexusProject().set_project_id(project_id)
        nx_issue_params['nx_project'] = nx_project
        plan_id = nx_project.get_project_row().plugin_relation.plan_project_id
    except NoResultFound:
        raise DevOpsError(404, "Error while getting issues",
                          error=apiError.project_not_found(project_id))

    default_filters = get_custom_filters_by_args(args, project_id=plan_id, children=True)
    # default_filters 帶 search ，但沒有取得 issued_id，搜尋結果為空
    if args.get('search') is not None and default_filters.get('issue_id') is None:
        if args.get("assigned_to_id") is None:
            return []
    elif args.get("has_tag_issue", False):
        return []
    
    if len(default_filters.get('issue_id',"").split(",")) > 200:
        issue_ids = default_filters.pop('issue_id').split(",")
        default_filters_list = handle_exceed_limit_length_default_filter(default_filters, issue_ids, [])
    else:
        default_filters_list = [default_filters]

    total_count = 0
    for default_filters in default_filters_list:
        if download:
            all_issues = redmine_lib.redmine.issue.filter(**default_filters)
        else:
            if get_jwt_identity()["role_id"] != 7:
                user_name = get_jwt_identity()["user_account"]
                all_issues = redmine_lib.rm_impersonate(user_name).issue.filter(**default_filters)
            else:
                all_issues = redmine_lib.redmine.issue.filter(**default_filters)

        # 透過 selection params 決定是否顯示 family bool 欄位
        if not args['selection'] or not strtobool(args['selection']):
            nx_issue_params['relationship_bool'] = True

        nx_issue_params['users_info'] = user.get_all_user_info()
        for redmine_issue in all_issues:
            nx_issue_params['redmine_issue'] = redmine_issue
            nx_issue_params['with_point'] = args["with_point"]
            issue = NexusIssue().set_redmine_issue_v2(**nx_issue_params).to_json()
            output.append(issue)
        
        total_count += all_issues.total_count

    if download:
        return output

    if args['limit'] and args['offset'] is not None:
        page_dict = util.get_pagination(total_count,
                                        args['limit'], args['offset'])
        output = {'issue_list': output, 'page': page_dict}
    return output

def get_issue_list_by_project_helper(project_id, args, download=False, operator_id=None):
    nx_issue_params = defaultdict()
    output = []
    if util.is_dummy_project(project_id):
        return []
    try:
        nx_project = NexusProject().set_project_id(project_id)
        nx_issue_params['nx_project'] = nx_project
        plan_id = nx_project.get_project_row().plugin_relation.plan_project_id
    except NoResultFound:
        raise DevOpsError(404, "Error while getting issues",
                          error=apiError.project_not_found(project_id))

    default_filters = get_custom_filters_by_args(args, project_id=plan_id, children=True)
    # default_filters 帶 search ，但沒有取得 issued_id，搜尋結果為空
    if args.get('search') is not None and default_filters.get('issue_id') is None:
        if args.get("assigned_to_id") is None:
            return []
    elif args.get("has_tag_issue", False):
        return []
    if len(default_filters.get('issue_id',"").split(",")) > 200:
        issue_ids = default_filters.pop('issue_id').split(",")
        default_filters_list = handle_exceed_limit_length_default_filter(default_filters, issue_ids, [])
    else:
        default_filters_list = [default_filters]

    total_count = 0
    users_info = user.get_all_user_info()
    for default_filters in default_filters_list:
        default_filters["include"] = "relations"
        if download:
            all_issues, _ = redmine.rm_list_issues(params=default_filters, operator_id=operator_id)
        else:
            if get_jwt_identity()["role_id"] != 7:
                operator_id = model.UserPluginRelation.query. \
                    filter_by(user_id=get_jwt_identity()["user_id"]).one().plan_user_id
                all_issues, total_count = redmine.rm_list_issues(params=default_filters, operator_id=operator_id)
            else:
                all_issues, total_count = redmine.rm_list_issues(params=default_filters)

        # 透過 selection params 決定是否顯示 family bool 欄位
        if not args.get('selection') or not strtobool(args.get('selection')):
            nx_issue_params['relationship_bool'] = True

        output += all_issues

    # Get all project issues to check each issue has relation or children issue
    has_family_issues = []
    has_children = []
    all_issues, _ = redmine.rm_list_issues(params={"project_id": plan_id, "include": "relations"})
    for issue in all_issues:
        if issue.get("parent") is not None:
            has_children.append(issue["parent"]["id"])
            has_family_issues += [issue["parent"]["id"], issue["id"]]
            continue
        if issue["relations"] != []:
            has_family_issues.append(issue["id"])
    
    # Parse filter_issues
    for issue in output:
        issue["name"] = issue.pop("subject")

        if issue.get("fixed_version") is None:
            issue["fixed_version"] = {}
        
        if issue.get("updated_on") is not None:
            issue["updated_on"] = issue["updated_on"][:-1]

        project_id = nexus.nx_get_project_plugin_relation(
            rm_project_id=issue['project']['id']).project_id
        if project_has_child(project_id) or project_has_parent(project_id):
            nx_project = model.Project.query.get(project_id)
        issue["project"]= {
            'id': nx_project.id,
            'name': nx_project.name,
            'display': nx_project.display
        }

        if issue.get("assigned_to") is not None:
            for user_info in users_info:
                if user_info[3] == issue["assigned_to"]["id"]:
                    issue["assigned_to"] = {
                        'id': user_info[0],
                        'name': user_info[1],
                        'login': user_info[2]
                    }
                    break
        else:
            issue["assigned_to"] = {}

        if issue.get("author") is not None:
            for user_info in users_info:
                if user_info[3] == issue["author"]["id"]:
                    issue["author"] = {
                        'id': user_info[0],
                        'name': user_info[1]
                    }
                    break
        else:
            issue["author"] = {}

        issue["is_closed"] = issue['status']['id'] in NexusIssue.get_closed_statuses()
        issue['issue_link'] = f"{config.get('REDMINE_EXTERNAL_BASE_URL')}/issues/{issue['id']}"
        issue["family"] = issue["id"] in has_family_issues
        issue["has_children"] = issue["id"] in has_children
        
        if args.get("with_point", False):
            issue["point"] = get_issue_point(issue["id"])
        issue["tags"] = get_issue_tags(issue["id"])
        
        issue.pop("parent", "")
        issue.pop("relations", "")
        issue.pop("created_on", "")

    if download:
        return output

    if args.get('limit') is not None and args.get('offset') is not None:
        page_dict = util.get_pagination(total_count,
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
    if args.get('project_id'):
        nx_project = NexusProject().set_project_id(args['project_id'])
        nx_issue_params['nx_project'] = nx_project
        plan_id = nx_project.get_project_row().plugin_relation.plan_project_id
        default_filters = get_custom_filters_by_args(args, project_id=plan_id, user_id=nx_user.plan_user_id)
    else:
        default_filters = get_custom_filters_by_args(args, user_id=nx_user.plan_user_id)
    if args.get('from') not in ['author_id', 'assigned_to_id']:
        return []
    # default_filters 帶 search ，但沒有取得 issued_id，搜尋結果為空
    elif args.get('search') and default_filters.get('issue_id') is None:
        return []
    elif args.get("has_tag_issue", False):
        return []

    if len(default_filters.get('issue_id', "").split(",")) > 200:
        issue_ids = default_filters.pop('issue_id').split(",")
        default_filters_list = handle_exceed_limit_length_default_filter(default_filters, issue_ids, [])
    else:
        default_filters_list = [default_filters]

    total_count = 0
    for default_filters in default_filters_list:
        if get_jwt_identity()["role_id"] != 7:
            user_name = get_jwt_identity()["user_account"]
            all_issues = redmine_lib.rm_impersonate(user_name).issue.filter(**default_filters)
        else:
            all_issues = redmine_lib.redmine.issue.filter(**default_filters)
        
        # 透過 selection params 決定是否顯示 family bool 欄位
        if not args['selection'] or not strtobool(args['selection']):
            nx_issue_params['relationship_bool'] = True

        nx_issue_params['users_info'] = user.get_all_user_info()
        for redmine_issue in all_issues:
            nx_issue_params['redmine_issue'] = redmine_issue
            issue = NexusIssue().set_redmine_issue_v2(**nx_issue_params).to_json()
            output.append(issue)
        
        total_count += all_issues.total_count

    if args['limit'] and args['offset'] is not None:
        page_dict = util.get_pagination(total_count,
                                        args['limit'], args['offset'])
        output = {'issue_list': output, 'page': page_dict}
    return output


def get_issue_by_tree_by_project(project_id):
    children_issues = []
    tree = defaultdict(dict)
    if util.is_dummy_project(project_id):
        return []
    nx_project = None
    try:
        nx_project = NexusProject().set_project_id(project_id)
        plan_id = nx_project.get_project_row().plugin_relation.plan_project_id
    except NoResultFound:
        raise DevOpsError(404, "Error while getting issues",
                          error=apiError.project_not_found(project_id))
    default_filters = get_custom_filters_by_args(project_id=plan_id)
    all_issues = redmine_lib.redmine.issue.filter(**default_filters)
    users_info = user.get_all_user_info()
    for redmine_issue in all_issues:
        tree[redmine_issue.id] = NexusIssue().set_redmine_issue_v2(redmine_issue,
                                                                   with_relationship=True,
                                                                   nx_project=nx_project,
                                                                   users_info=users_info).to_json()
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
def get_custom_filters_by_args(args=None, project_id=None, user_id=None, children=None):
    if children is None:
        default_filters = {'status_id': '*', 'include': 'relations'}
    else:
        default_filters = {'status_id': '*', 'include': ['relations', 'children']}
    if project_id:
        default_filters['project_id'] = project_id
    if args:
        if user_id:
            if args.get('from') in ['author_id', 'assigned_to_id']:
                default_filters[args['from']] = user_id
            # 如果 from 已經指定 assigned_to_id，但是 params 又有 assigned_to_id 的時候，要從 args 刪除
            if args.get('assigned_to_id') and args.get('from') == 'assigned_to_id':
                args.pop('assigned_to_id')
        handle_allowed_keywords(default_filters, args)
        if args.get('search'):
            handle_search(default_filters, args)
        # offset 可能為 0
        if args.get('limit') and args.get('offset') is not None:
            default_filters['limit'] = args['limit']
            default_filters['offset'] = args['offset']
        if args.get('sort'):
            default_filters['sort'] = args['sort']
        if args.get('due_date_start') or args.get('due_date_end'):
            if args.get('due_date_start') and args.get('due_date_end'):
                default_filters['due_date'] = f"><{args.get('due_date_start')}|{args.get('due_date_end')}"
            elif args.get('due_date_start'):
                default_filters['due_date'] = f">={args.get('due_date_start')}"
            elif args.get('due_date_end'):
                default_filters['due_date'] = f"<={args.get('due_date_end')}"

        if args.get("tags") is not None:
            tags_issue_id_list = search_issue_tags_by_tags(args["tags"])
            if default_filters.get("issue_id") is not None:
                filter_issue_id_list = default_filters["issue_id"].split(",")
                issue_list = [id for id in filter_issue_id_list if int(id) in tags_issue_id_list]
            else:
                issue_list = tags_issue_id_list

            if issue_list != []:
                default_filters["issue_id"] = ','.join(str(id) for id in issue_list)
            else:
                args["has_tag_issue"] = True   

        if args.get("only_subproject_issues", False):
            default_filters["subproject_id"] = "!*"
         
    return default_filters


def handle_allowed_keywords(default_filters, args):
    allowed_keywords = ['fixed_version_id', 'status_id', 'tracker_id', 'assigned_to_id', 'priority_id', 'parent_id']
    for key in allowed_keywords:
        if args.get(key, None):
            # 如果 keywords 值為 'null'，python-redmine filter 值為 '!*'
            if args[key] == 'null':
                default_filters[key] = '!*'
            elif key == 'status_id' and args[key] == 'all':
                default_filters[key] = '*'
            elif key == "assigned_to_id" and isinstance(args[key], str):
                if "null" in args[key]:
                    filter_users = args[key].split("|")
                    filter_users.remove("null")
                    filter_users = [int(filter_user) for filter_user in filter_users]
                    all_users = [user["id"] for user in user_list_by_project(args["project_id"], {'exclude': None})]
                    except_users = [str(validate_plan_user_id(int(all_user))) for all_user in all_users if all_user not in filter_users]
                    if generate_default_filter_value(except_users) is not None:
                        default_filters[key] = generate_default_filter_value(except_users)
                else:
                    assigned_to_ids = []
                    for id in args[key].split("|"):
                        assigned_to_ids.append(str(validate_plan_user_id(int(id))))
                    default_filters[key] = "|".join(assigned_to_ids)
            elif key == "fixed_version_id" and isinstance(args[key], str):
                if "null" in args[key]:
                    filter_versions = args[key].split("|")
                    filter_versions.remove("null")
                    all_versions = get_all_id(redmine_lib.redmine.project.get(default_filters["project_id"]).versions)
                    except_versions = [all_version for all_version in all_versions if all_version not in filter_versions]
                    if generate_default_filter_value(except_versions) is not None:
                        default_filters[key] = generate_default_filter_value(except_versions)
                else:
                    fixed_version_ids = []
                    for id in args[key].split("|"):
                        fixed_version_ids.append(str(id))
                    default_filters[key] = "|".join(fixed_version_ids)
            # 如果 args[key] 值是 string，且可以被認知為正整數
            elif isinstance(args[key], str) and args[key].isdigit():
                if key in ['status_id', 'priority_id', 'tracker_id']:
                    default_filters[key] = int(args[key])
            else:
                default_filters[key] = args[key]


def generate_default_filter_value(except_values):
    if len(except_values) == 0:
        res = None
    else:
        res = "!" + "|".join(except_values)
    return res


def get_all_id(objects):
    return [str(object.id) for object in objects]


def validate_plan_user_id(id):
    try:
        nx_user = db.session.query(model.UserPluginRelation).join(
            model.User).filter_by(id=id).one()
    except NoResultFound:
        raise apiError.DevOpsError(
            404, f'User id {id} does not exist.',
            apiError.user_not_found(id)
        )
    return nx_user.plan_user_id


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
    result = list(set(result))
    if result:
        # issue filter 多個 issue_id 只接受逗號分隔的字串
        issue_id = ','.join(str(id) for id in result)
        default_filters['issue_id'] = issue_id


# 搜尋被分配者符合 keyword 的 issues
def get_issue_assigned_to_search(default_filters, args):
    assigned_to_issue = []
    # 使用 ilike 同時搜尋 login 或 name 相符的 user
    nx_user_list = db.session.query(model.UserPluginRelation).join(
        model.User, model.ProjectUserRole
    ).filter(or_(
        model.User.login.ilike(f'%{args["search"]}%'),
        model.User.name.ilike(f'%{args["search"]}%')
    ), model.ProjectUserRole.role_id != 6).all()
    if nx_user_list:
        for nx_user in nx_user_list:
            # 如果有指定 assigned_to_id，或from是assign_to_id, 回傳空array
            if args.get('assigned_to_id'):
                return assigned_to_issue
            elif args.get('from') == 'assigned_to_id':
                if nx_user.user_id != args['nx_user_id']:
                    continue
                else:
                    all_issues = redmine_lib.redmine.issue.filter(**default_filters)
            else:
                all_issues = redmine_lib.redmine.issue.filter(**default_filters, assigned_to_id=nx_user.plan_user_id)
            assigned_to_issue.extend([issue.id for issue in all_issues])
    return assigned_to_issue


# 取得 issue 相關的 parent & children & relations 資訊
def get_issue_family(redmine_issue, args={}, all=False, user_name=None):
    output = defaultdict(list)
    is_with_point = args.get("with_point", False)
    if user_name is None:
        user_name = get_jwt_identity()["user_account"]
    if hasattr(redmine_issue, 'parent') and not is_with_point:
        if not all:
            parent_issue = redmine_lib.rm_impersonate(user_name).issue.filter(
                issue_id=redmine_issue.parent.id, status_id='*')
        else:
            parent_issue = redmine_lib.redmine.issue.filter(
                issue_id=redmine_issue.parent.id, status_id='*')
        try:
            output['parent'] = NexusIssue().set_redmine_issue_v2(parent_issue[0]).to_json()
        except IndexError:
            output["parent"] = []
    if len(redmine_issue.children):
        children_issue_ids = [str(child.id) for child in redmine_issue.children]
        children_issue_ids_str = ','.join(children_issue_ids)   
        if not all:
            children_issues = redmine_lib.rm_impersonate(user_name).issue.filter(
                issue_id=children_issue_ids_str, status_id='*', include=['children'])
        else:
            children_issues = redmine_lib.redmine.issue.filter(
                issue_id=children_issue_ids_str, status_id='*', include=['children'])
        output['children'] = [NexusIssue().set_redmine_issue_v2(issue, with_point=is_with_point, relationship_bool=True).to_json()
                              for issue in children_issues]
    if len(redmine_issue.relations) and not is_with_point:
        for relation in redmine_issue.relations:
            rel_issue_id = 0
            if relation.issue_id != int(redmine_issue.id):
                rel_issue_id = relation.issue_id
            else:
                rel_issue_id = relation.issue_to_id
            rel_issue = redmine_lib.redmine.issue.get(rel_issue_id)
            relate_issue = NexusIssue().set_redmine_issue_v2(rel_issue).to_json()
            relate_issue['relation_id'] = relation.id
            output['relations'].append(relate_issue)
    for key in ["parent", "children", "relations"]:
        if output.get(key) == []:
            output.pop(key)
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
        plan_id = nx_project.get_project_row().plugin_relation.plan_project_id
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
        output_keys = ['assigned_to', 'priority', 'tracker', 'tags']
        # output_values 格式: {'xxxx': { "Active": 0, "Assigned": 0, "InProgress": 0 ..... }}
        output_values = defaultdict(
            lambda: defaultdict(dict, {status: 0 for status in issue_status.values()})
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
        issue_tag = model.IssueTag.query.get(issue.id)
        mappings = {
            'assigned_to': 'Unassigned',
            'priority': issue.priority.name,
            'tracker': issue.tracker.name,
        }
        if issue_tag is not None:
            mappings.update({"tags": issue_tag.tag_id})
        if hasattr(issue, 'assigned_to'):
            user_id = nexus.nx_get_user_plugin_relation(plan_user_id=issue.assigned_to.id).user_id
            user_name = user.NexusUser().set_user_id(user_id).name
            mappings['assigned_to'] = user_name

        for key in output_keys:
            if key == "tags":
                if "tags" in mappings:
                    for tag_id in mappings[key]:
                        if tag_id != "" and tag_id is not None:
                            tag_name = get_tag(tag_id)["name"]
                            if issue.status.id in issue_status:
                                output[key][tag_name][issue.status.name] += 1
                            else:
                                output[key][tag_name]['Unknown'] += 1
            else:
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


def post_issue_relation(issue_id, issue_to_id, user_account):
    return redmine_lib.rm_post_relation(issue_id, issue_to_id, user_account)


def put_issue_relation(issue_id, issue_to_ids, user_account):
    input_set = set()
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
                    redmine_lib.rm_delete_relation(relation['id'], user_account)
    need_add_set = input_set - origin_set
    for need_add in list(need_add_set):
        need_add = list(need_add)
        redmine_lib.rm_post_relation(need_add[0], need_add[1], user_account)


def delete_issue_relation(relation_id, user_account):
    return redmine_lib.rm_delete_relation(relation_id, user_account)


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


def execute_issue_alert(alert_mapping):
    '''
    若符合設定條件, 則會在該議題下新增留言
    條件: 1.Alert裡的condition 2.議題狀態並不是關閉
    因新增提醒會將issue的update_on更新, 故另外創建AlertUnchangeRecord
    來儲存update_on
    '''
    for project_id, alerts in alert_mapping.items():
        plan_project_id = project.get_plan_project_id(project_id)
        issues = redmine.rm_get_issues_by_project(plan_project_id)
        for issue in issues:
            if issue["status"]["id"] != 6:
                for alert in alerts:
                    note = None
                    condition = alert["condition"]
                    days = alert["days"]
                    issue_id = issue["id"]
                    if condition == "unchange":
                        common_note = f'已超過{days}天未異動'
                        update_time = datetime.strptime(issue["updated_on"][0:10], "%Y-%m-%d")
                        alert_unchange_record = model.AlertUnchangeRecord.query.filter_by(
                            project_id=project_id, issue_id=issue_id).first()
                        # 首次新增, 儲存當下時間(after_update_time)與實際更新時間(before_update_time)
                        if alert_unchange_record is None:
                            delta = update_time - util.get_certain_date_from_now(days)
                            if delta.days <= 0:
                                note = common_note
                                new = model.AlertUnchangeRecord(
                                    project_id=project_id,
                                    issue_id=issue_id,
                                    before_update_time=update_time,
                                    after_update_time=util.get_certain_date_from_now(0)
                                )
                                db.session.add(new)
                                db.session.commit()
                        else:
                            # 若before_update_time是None, 表示該issue已經重新計算
                            if alert_unchange_record.before_update_time is None:
                                delta = update_time - util.get_certain_date_from_now(days)
                                if delta.days <= 0:
                                    note = common_note
                                    alert_unchange_record.before_update_time = update_time
                                    alert_unchange_record.after_update_time = util.get_certain_date_from_now(0)
                                    db.session.commit()
                            else:
                                if alert_unchange_record.after_update_time == update_time:
                                    delta = alert_unchange_record.before_update_time - util.get_certain_date_from_now(
                                        days)
                                    if delta.days <= 0:
                                        note = common_note
                                        alert_unchange_record.after_update_time = util.get_certain_date_from_now(0)
                                        db.session.commit()
                                else:
                                    delta = update_time - util.get_certain_date_from_now(days)
                                    if delta.days <= 0:
                                        note = common_note
                                        alert_unchange_record.before_update_time = update_time
                                        alert_unchange_record.after_update_time = util.get_certain_date_from_now(0)
                                    else:
                                        alert_unchange_record.before_update_time = None
                                    db.session.commit()
                    if condition == "comming":
                        if issue.get("due_date") is None:
                            continue
                        delta = util.get_certain_date_from_now(-days) - datetime.strptime(issue["due_date"], "%Y-%m-%d")
                        if delta.days >= 0:
                            d_day = days - delta.days
                            if d_day >= 0:
                                note = f'{d_day}天即將到期'
                            else:
                                note = f'已經過期{-d_day}天'
                    if note is not None:
                        update_issue(
                            issue_id,
                            {"notes": f'本議題 #{issue_id} {issue["subject"]} {note} ，請確認該議題是否繼續執行？或更新狀態？'},
                        )

def get_custom_issue_filter(user_id, project_id):
    custom_issue_filters = CustomIssueFilter.query.filter_by(user_id=user_id, project_id=project_id).all()
    return [row_to_dict(custom_issue_filter) for custom_issue_filter in custom_issue_filters]


def create_custom_issue_filter(user_id, project_id, args):
    row = CustomIssueFilter(
        user_id=user_id, project_id=project_id, name=args.pop("name"), type=args.pop("type"), custom_filter=args
    )
    db.session.add(row)
    db.session.commit()

    return {"custom_filter_id": row.id}


def put_custom_issue_filter(custom_filter_id, project_id, args):
    result = {
        "id": custom_filter_id, "name": args.pop("name"), "type": args.pop("type"), "project_id": project_id, "custom_filter": args}

    custom_issue_filter = CustomIssueFilter.query.get(custom_filter_id)
    custom_issue_filter.name = result["name"]
    custom_issue_filter.type = result["type"]
    custom_issue_filter.project_id = project_id
    custom_issue_filter.custom_filter = args
    db.session.commit()
    return result


def pj_download_file_is_exist(project_id):
    file_exist = os.path.isfile(f"./logs/project_excel_file/{project_id}.xlsx")
    create_at = get_lock_status("download_pj_issues")["sync_date"] if file_exist else None
    return {"file_exist": file_exist, "create_at": str(create_at)}


class DownloadIssueAsExcel():
    def __init__(self, args, priority_id, user_id):
        self.result = []
        self.levels = args.pop("levels")
        self.deploy_column = args.pop("deploy_column")
        self.args = args
        self.project_id = priority_id
        self.__get_operator_id(user_id)
    
    def __get_operator_id(self, user_id):
        self.operator_id = model.UserPluginRelation.query. \
                    filter_by(user_id=user_id).one().plan_user_id
        self.user_name = model.User.query.get(int(user_id)).login

    def execute(self):
        try:
            logger.logger.info("Start writing issues into excel.")
            self.__update_lock_download_issues(is_lock=True, sync_date=self.__now_time()) 
            self.__append_main_issue()
            self.__update_lock_download_issues(is_lock=False, sync_date=self.__now_time()) 
            logger.logger.info("Writing complete")
        except Exception as e:
            logger.logger.exception(str(e))
            self.__update_lock_download_issues(is_lock=False, sync_date=None)


    def __now_time(self):
        return datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")


    def __append_main_issue(self):
        print(self.args)
        output = get_issue_list_by_project_helper(self.project_id, self.args, download=True, operator_id=self.operator_id)
        for index, value in enumerate(output):
            row = self.__generate_row_issue_for_excel(str(index + 1), value)
            self.result.append(row)
            self.__append_children(index + 1, value, 1)

        self.__download_as_excel()


    def __append_children(self, super_index, value, level):
        if not value["has_children"] or self.levels == level:
            return 
        redmine_issue = redmine_lib.rm_impersonate(self.user_name).issue.get(value["id"], include=['children'])
        children = get_issue_family(redmine_issue, args={'with_point': True}, user_name=self.user_name)["children"]
        for index, child in enumerate(children):
            row = self.__generate_row_issue_for_excel(f"{super_index}_{index + 1}", child)
            self.result.append(row)
            self.__append_children(f"{super_index}_{index+1}", child, level + 1)


    def __generate_row_issue_for_excel(self, index, value):
        english = len(re.findall(r'[\u4e00-\u9fff]+', self.deploy_column[0]["display"])) == 0
        result = {"index": index} if english else {"項次": index}
        for column in self.deploy_column:
            if column['field'] == 'name':
                result.update({column['display']: value['name']})
            if column['field'] == 'tracker' and not english:
                result.update({column['display']: TRACKER_TRANSLATE[value['tracker']["name"]]})
            elif column['field'] == 'tracker' and english:
                result.update({column['display']: value['tracker']["name"]})

            if column['field'] == 'status' and not english:
                result.update({column['display']: STATUS_TRANSLATE[value['status']['name']]})
            elif column['field'] == 'status' and english:
                result.update({column['display']: value['status']['name']})

            if column['field'] == 'fixed_version':
                result.update({column['display']: value['fixed_version']["name"] if value['fixed_version'] != {} else ""})
            if column['field'] == 'start_date':
                result.update({column['display']: value['start_date']})
            if column['field'] == 'due_date':
                result.update({column['display']: value['due_date']})
            if column['field'] == 'priority' and not english:
                result.update({column['display']: PRIORITY_TRANSLATE[value['priority']["name"]]})
            elif column['field'] == 'priority' and english:
                result.update({column['display']: value['priority']["name"]})

            if column['field'] == 'assigned_to':
                result.update({column['display']: value['assigned_to']['name'] if value['assigned_to'] != {} else ""})
            if column['field'] == 'done_ratio':
                result.update({column['display']: value['done_ratio']})
            if column['field'] == 'point':
                result.update({column['display']: value.get('point', 0)})
        return result


    def __download_as_excel(self):
        if not os.path.isdir("./logs/project_excel_file"):
            os.makedirs("./logs/project_excel_file", exist_ok=True)
        util.write_in_excel(f"logs/project_excel_file/{self.project_id}.xlsx", self.result)


    def __update_lock_download_issues(self, is_lock=None, sync_date=None):
        lock_redmine = model.Lock.query.filter_by(name="download_pj_issues").first()
        if is_lock is not None:
            lock_redmine.is_lock = is_lock
        if sync_date is not None:
            lock_redmine.sync_date = sync_date
        db.session.commit()

@record_activity(ActionType.MODIFY_HOOK)
def modify_hook(args):
    relation = model.IssueCommitRelation.query.get(args["commit_id"])
    relation.issue_ids = args["issue_ids"]
    db.session.commit()


def get_commit_hook_issues_helper(issue_id):
    if get_jwt_identity()["role_id"] == 5:
        return True
    pj_id = get_issue(issue_id, with_children=False, journals=False)["project"]["id"]
    user_id = get_jwt_identity()["user_id"]
    return model.ProjectUserRole.query.filter_by(project_id=pj_id, user_id=user_id).first() is not None


def get_commit_hook_issues(commit_id):   
    issue_commit_relation = model.IssueCommitRelation.query.filter_by(commit_id=commit_id).first()
    # connect_issues = list(filter(get_commit_hook_issues_helper, issue_commit_relation.issue_ids)) if issue_commit_relation is not None else None
    connect_issues = {
        issue_id:  get_commit_hook_issues_helper(issue_id) for issue_id in issue_commit_relation.issue_ids} if issue_commit_relation is not None else None
    return {"issue_ids": connect_issues}


# --------------------- Resources ---------------------

class SingleIssueV2(MethodResource):
    @doc(tags=['Issue'], description="Get single issue")
    # @marshal_with(route_model.SingleIssueGetResponse)
    @jwt_required
    def get(self, issue_id):
        issue_info = get_issue(issue_id)
        require_issue_visible(issue_id, issue_info)
        if 'parent_id' in issue_info:
            parent_info = get_issue(issue_info['parent_id'], with_children=False)
            parent_info['name'] = parent_info.pop('subject', None)
            parent_info['tags'] = get_issue_tags(parent_info["id"])
            issue_info.pop('parent_id', None)
            issue_info['parent'] = parent_info

        for items in ["children", "relations"]:
            if issue_info.get(items) is not None:
                for item in issue_info[items]:
                    item["tags"] = get_issue_tags(item["id"])
        issue_info["name"] = issue_info.pop('subject', None)
        issue_info["point"] = get_issue_point(issue_id)
        issue_info["tags"] = get_issue_tags(issue_id)

        return util.success(issue_info)

    @doc(tags=['Issue'], description="Update single issue")
    @use_kwargs(route_model.SingleIssuePutSchema, location="json")
    @marshal_with(route_model.SingleIssuePutResponse)
    @jwt_required
    def put(self, issue_id, **kwargs):
        require_issue_visible(issue_id)

        redmine_issue = redmine_lib.redmine.issue.get(issue_id, include=['children'])
        has_children = redmine_issue.children.total_count > 0
        if has_children:
            validate_field_mapping = {
                "priority_id": redmine_issue.priority.id if hasattr(redmine_issue, 'priority') else None,
                "start_date": redmine_issue.start_date.isoformat() if hasattr(redmine_issue, 'start_date') else "",
                "due_date": redmine_issue.due_date.isoformat() if hasattr(redmine_issue, 'due_date') else "",
            }
            for invalidate_field in ["priority_id", "start_date", "due_date"]:
                if kwargs.get(invalidate_field) is not None and kwargs.get(invalidate_field) != validate_field_mapping[invalidate_field]:
                    raise DevOpsError(400, f'Argument {invalidate_field} can not be alerted when children issue exist.',
                                      error=apiError.redmine_argument_error(invalidate_field))

        # Check due_date is greater than start_date
        due_date = None
        start_date = None

        if kwargs.get("due_date") is not None and len(kwargs.get("due_date")) > 0:
            due_date = kwargs.get("due_date")
        else:
            try:
                due_date = str(redmine_lib.redmine.issue.get(issue_id).due_date)
            except ResourceAttrError:
                pass

        if kwargs.get("start_date") is not None and len(kwargs.get("start_date")) > 0:
            start_date = kwargs.get("start_date")
        else:
            try:
                start_date = str(redmine_lib.redmine.issue.get(issue_id).start_date)
            except ResourceAttrError:
                pass

        if start_date is not None and due_date is not None:
            if due_date < start_date:
                arg = "due_date" if kwargs.get("due_date") is not None and len(kwargs.get("due_date")) > 0 else "start_date"
                raise DevOpsError(400, 'Due date must be greater than start date.',
                                  error=apiError.argument_error(arg))

        # Handle removable int parameters
        keys_int_or_null = ['assigned_to_id', 'fixed_version_id', 'parent_id']
        for k in keys_int_or_null:
            if kwargs.get(k) == 'null':
                kwargs[k] = ''

        kwargs["subject"] = kwargs.pop("name", None)
        output = update_issue(issue_id, kwargs, get_jwt_identity()['user_id'])
        return util.success(output)

    @doc(tags=['Issue'], description="Delete single issue")
    @use_kwargs(route_model.SingleIssueDeleteSchema, location="json")
    @marshal_with(route_model.SingleIssueDeleteResponse)
    @ jwt_required
    def delete(self, issue_id, **kwargs):
        if kwargs.get("force") is None or not kwargs.get("force"):
            redmine_issue = redmine_lib.redmine.issue.get(issue_id, include=['children'])
            children = get_issue_family(redmine_issue, all=True).get("children")
            if children is not None:
                raise DevOpsError(400, 'Unable to delete issue with children issue, unless parameter "force" is True.',
                                  error=apiError.unable_to_delete_issue_has_children(children))
        return util.success(delete_issue(issue_id))

@doc(tags=['Issue'], description="Create single issue")
@use_kwargs(route_model.SingleIssuePostSchema, location="json")
@marshal_with(route_model.SingleIssuePostResponse)
class CreateSingleIssueV2(MethodResource):
    @jwt_required
    def post(self, **kwargs):
        # Check due_date is greater than start_date
        if kwargs.get("start_date") is not None and kwargs.get("due_date") is not None:
            if kwargs["due_date"] < kwargs["start_date"]:
                raise DevOpsError(400, 'Due date must be greater than start date.',
                                  error=apiError.argument_error("due_date"))

        # Handle removable int parameters
        keys_int_or_null = ['assigned_to_id', 'fixed_version_id', 'parent_id']
        for k in keys_int_or_null:
            if kwargs.get(k) == 'null':
                kwargs[k] = ''

        kwargs["subject"] = kwargs.pop("name")
        return util.success(create_issue(kwargs, get_jwt_identity()['user_id']))

class SingleIssue(Resource):
    @ jwt_required
    def get(self, issue_id):
        issue_info = get_issue(issue_id)
        require_issue_visible(issue_id, issue_info)
        if 'parent_id' in issue_info:
            parent_info = get_issue(issue_info['parent_id'], with_children=False)
            parent_info['name'] = parent_info.pop('subject', None)
            parent_info['tags'] = get_issue_tags(parent_info["id"])
            issue_info.pop('parent_id', None)
            issue_info['parent'] = parent_info

        for items in ["children", "relations"]:
            if issue_info.get(items) is not None:
                for item in issue_info[items]:
                    item["tags"] = get_issue_tags(item["id"])
        issue_info["name"] = issue_info.pop('subject', None)
        issue_info["point"] = get_issue_point(issue_id)
        issue_info["tags"] = get_issue_tags(issue_id)

        return util.success(issue_info)

    @ jwt_required
    def post(self):
        parser = reqparse.RequestParser()
        parser.add_argument('project_id', type=int, required=True)
        parser.add_argument('tracker_id', type=int, required=True)
        parser.add_argument('status_id', type=int, required=True)
        parser.add_argument('priority_id', type=int, required=True)
        parser.add_argument('name', type=str, required=True)
        parser.add_argument('description', type=str)
        parser.add_argument('assigned_to_id', type=str)
        parser.add_argument('parent_id', type=str)
        parser.add_argument('fixed_version_id', type=str)
        parser.add_argument('start_date', type=str)
        parser.add_argument('due_date', type=str)
        parser.add_argument('done_ratio', type=int)
        parser.add_argument('estimated_hours', type=int)
        parser.add_argument('point', type=int)
        parser.add_argument('tags', action=str)

        # Attachment upload
        parser.add_argument(
            'upload_file', type=werkzeug.datastructures.FileStorage, location='files')
        parser.add_argument('upload_filename', type=str)
        parser.add_argument('upload_description', type=str)
        parser.add_argument('upload_content_type', type=str)

        args = parser.parse_args()

        # Check due_date is greater than start_date
        if args.get("start_date") is not None and args.get("due_date") is not None:
            if args["due_date"] < args["start_date"]:
                raise DevOpsError(400, 'Due date must be greater than start date.',
                                  error=apiError.argument_error("due_date"))

        # Handle removable int parameters
        keys_int_or_null = ['assigned_to_id', 'fixed_version_id', 'parent_id']
        for k in keys_int_or_null:
            if args[k] == 'null':
                args[k] = ''

        args["subject"] = args.pop("name")
        return util.success(create_issue(args, get_jwt_identity()['user_id']))

    @ jwt_required
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
        parser.add_argument('name', type=str)
        parser.add_argument('start_date', type=str)
        parser.add_argument('due_date', type=str)
        parser.add_argument('done_ratio', type=int)
        parser.add_argument('notes', type=str)
        parser.add_argument('point', type=int)
        parser.add_argument('tags', type=str)

        # Attachment upload
        parser.add_argument(
            'upload_file', type=werkzeug.datastructures.FileStorage, location='files')
        parser.add_argument('upload_filename', type=str)
        parser.add_argument('upload_description', type=str)
        parser.add_argument('upload_content_type', type=str)

        args = parser.parse_args()

        redmine_issue = redmine_lib.redmine.issue.get(issue_id, include=['children'])
        has_children = redmine_issue.children.total_count > 0
        if has_children:
            validate_field_mapping = {
                "priority_id": redmine_issue.priority.id if hasattr(redmine_issue, 'priority') else None,
                "start_date": redmine_issue.start_date.isoformat() if hasattr(redmine_issue, 'start_date') else "",
                "due_date": redmine_issue.due_date.isoformat() if hasattr(redmine_issue, 'due_date') else "",
            }
            for invalidate_field in ["priority_id", "start_date", "due_date"]:
                if args[invalidate_field] is not None and args[invalidate_field] != validate_field_mapping[invalidate_field]:
                    raise DevOpsError(400, f'Argument {invalidate_field} can not be alerted when children issue exist.',
                                      error=apiError.redmine_argument_error(invalidate_field))

        # Check due_date is greater than start_date
        due_date = None
        start_date = None

        if args.get("due_date") is not None and len(args.get("due_date")) > 0:
            due_date = args.get("due_date")
        else:
            try:
                due_date = str(redmine_lib.redmine.issue.get(issue_id).due_date)
            except ResourceAttrError:
                pass

        if args.get("start_date") is not None and len(args.get("start_date")) > 0:
            start_date = args.get("start_date")
        else:
            try:
                start_date = str(redmine_lib.redmine.issue.get(issue_id).start_date)
            except ResourceAttrError:
                pass

        if start_date is not None and due_date is not None:
            if due_date < start_date:
                arg = "due_date" if args.get("due_date") is not None and len(args.get("due_date")) > 0 else "start_date"
                raise DevOpsError(400, 'Due date must be greater than start date.',
                                  error=apiError.argument_error(arg))

        # Handle removable int parameters
        keys_int_or_null = ['assigned_to_id', 'fixed_version_id', 'parent_id']
        for k in keys_int_or_null:
            if args[k] == 'null':
                args[k] = ''

        args["subject"] = args.pop("name", None)
        output = update_issue(issue_id, args, get_jwt_identity()['user_id'])
        return util.success(output)

    @ jwt_required
    def delete(self, issue_id):
        parser = reqparse.RequestParser()
        parser.add_argument('force', type=bool)
        args = parser.parse_args()
        if args["force"] is None or not args["force"]:
            redmine_issue = redmine_lib.redmine.issue.get(issue_id, include=['children'])
            children = get_issue_family(redmine_issue, all=True).get("children")
            if children is not None:
                raise DevOpsError(400, 'Unable to delete issue with children issue, unless parameter "force" is True.',
                                  error=apiError.unable_to_delete_issue_has_children(children))
        return util.success(delete_issue(issue_id))


class DumpByIssue(Resource):
    @ jwt_required
    def get(self, issue_id):
        require_issue_visible(issue_id)
        return dump_by_issue(issue_id)


@doc(tags=['Issue'], description="Get issue list by project")
@use_kwargs(route_model.IssueByProjectSchema, location="query")
# @marshal_with(route_model.IssueByProjectResponse)
@marshal_with(route_model.IssueByProjectResponseWithPage, code="with limit and offset")
class IssueByProjectV2(MethodResource):
    @ jwt_required
    def get(self, project_id, **kwargs):
        role.require_in_project(project_id, 'Error to get issue.')
        kwargs["project_id"] = project_id
        if kwargs.get("search") is not None and len(kwargs["search"]) < 2:
            output = []
        else:
            # output = get_issue_list_by_project(project_id, args)
            output = get_issue_list_by_project_helper(project_id, kwargs)
        return util.success(output)


class IssueByProject(Resource):
    @ jwt_required
    def get(self, project_id):
        role.require_in_project(project_id, 'Error to get issue.')
        parser = reqparse.RequestParser()
        parser.add_argument('fixed_version_id', type=str)
        parser.add_argument('status_id', type=str)
        parser.add_argument('tracker_id', type=str)
        parser.add_argument('assigned_to_id', type=str)
        parser.add_argument('priority_id', type=str)
        parser.add_argument('only_subproject_issues', type=bool, default=False)
        parser.add_argument('limit', type=int)
        parser.add_argument('offset', type=int)
        parser.add_argument('search', type=str)
        parser.add_argument('selection', type=str)
        parser.add_argument('sort', type=str)
        parser.add_argument('parent_id', type=str)
        parser.add_argument('due_date_start', type=str)
        parser.add_argument('due_date_end', type=str)
        parser.add_argument('with_point', type=bool)
        parser.add_argument('tags', type=str)
        args = parser.parse_args()
        args["project_id"] = project_id
        if args.get("search") is not None and len(args["search"]) < 2:
            output = []
        else:
            # output = get_issue_list_by_project(project_id, args)
            output = get_issue_list_by_project_helper(project_id, args)
        return util.success(output)


@doc(tags=['Issue'], description="Get issue list by user")
@use_kwargs(route_model.IssueByUserSchema, location="query")
@marshal_with(route_model.IssueByUserResponseWithPage, code="with limit and offset")
class IssueByUserV2(MethodResource):
    @ jwt_required
    def get(self, user_id, **kwargs):
        print(kwargs)
        if kwargs.get("search") is not None and len(kwargs["search"]) < 2:
            output = []
        else:
            output = get_issue_list_by_user(user_id, kwargs)
        return util.success(output)


class IssueByUser(Resource):
    @ jwt_required
    def get(self, user_id):
        parser = reqparse.RequestParser()
        parser.add_argument('project_id', type=int)
        parser.add_argument('fixed_version_id', type=str)
        parser.add_argument('status_id', type=str)
        parser.add_argument('tracker_id', type=str)
        parser.add_argument('assigned_to_id', type=str)
        parser.add_argument('priority_id', type=str)
        parser.add_argument('only_subproject_issues', type=bool, default=False)
        parser.add_argument('limit', type=int)
        parser.add_argument('offset', type=int)
        parser.add_argument('search', type=str)
        parser.add_argument('selection', type=str)
        parser.add_argument('from', type=str)
        parser.add_argument('sort', type=str)
        parser.add_argument('tags', type=str)
        args = parser.parse_args()

        if args.get("search") is not None and len(args["search"]) < 2:
            output = []
        else:
            output = get_issue_list_by_user(user_id, args)
        return util.success(output)

class IssueByVersion(Resource):
    @ jwt_required
    def get(self, project_id):
        role.require_in_project(project_id, 'Error to get issue.')
        parser = reqparse.RequestParser()
        parser.add_argument('fixed_version_id')
        args = parser.parse_args()

        return util.success(get_issue_by_project(project_id, args))


@doc(tags=['Issue'], description="Get issue list by tree by project")
# @marshal_with(route_model.IssueByTreeByProjectResponse)
class IssueByTreeByProjectV2(MethodResource):
    @ jwt_required
    def get(self, project_id):
        role.require_in_project(project_id, 'Error to get issue.')
        output = get_issue_by_tree_by_project(project_id)
        return util.success(output)


class IssueByTreeByProject(Resource):
    @ jwt_required
    def get(self, project_id):
        role.require_in_project(project_id, 'Error to get issue.')
        output = get_issue_by_tree_by_project(project_id)
        return util.success(output)


@doc(tags=['Issue'], description="Get issue list by status by project")
@marshal_with(route_model.IssueByStatusByProjectResponse)
class IssueByStatusByProjectV2(MethodResource):
    @ jwt_required
    def get(self, project_id):
        role.require_in_project(project_id)
        return get_issue_by_status_by_project(project_id)


class IssueByStatusByProject(Resource):
    @ jwt_required
    def get(self, project_id):
        role.require_in_project(project_id)
        return get_issue_by_status_by_project(project_id)


class IssueByDateByProject(Resource):
    @ jwt_required
    def get(self, project_id):
        role.require_in_project(project_id)
        return get_issue_by_date_by_project(project_id)


@doc(tags=['Issue'], description="Get issue Progress by tree by project")
@use_kwargs(route_model.IssuesProgressByProjectSchema, location="query")
@marshal_with(route_model.IssuesProgressByProjectResponse)
class IssuesProgressByProjectV2(MethodResource):
    @jwt_required
    def get(self, project_id, **kwargs):
        role.require_in_project(project_id)
        output = get_issue_progress_or_statistics_by_project(project_id,
                                                             kwargs, progress=True)
        return util.success(output)


class IssuesProgressByProject(Resource):
    @ jwt_required
    def get(self, project_id):
        role.require_in_project(project_id)
        parser = reqparse.RequestParser()
        parser.add_argument('fixed_version_id', type=int)
        args = parser.parse_args()
        output = get_issue_progress_or_statistics_by_project(project_id,
                                                             args, progress=True)
        return util.success(output)
        

@doc(tags=['Issue'], description="Get issue Progress by tree by project")
@use_kwargs(route_model.IssuesProgressByProjectSchema, location="query")
@marshal_with(route_model.IssuesStatisticsByProjectResponse)  
class IssuesStatisticsByProjectV2(MethodResource):
    @ jwt_required
    def get(self, project_id):
        role.require_in_project(project_id)
        parser = reqparse.RequestParser()
        parser.add_argument('fixed_version_id', type=int)
        args = parser.parse_args()
        output = get_issue_progress_or_statistics_by_project(project_id,
                                                             args, statistics=True)
        return util.success(output)


class IssuesStatisticsByProject(Resource):
    @ jwt_required
    def get(self, project_id):
        role.require_in_project(project_id)
        parser = reqparse.RequestParser()
        parser.add_argument('fixed_version_id', type=int)
        args = parser.parse_args()
        output = get_issue_progress_or_statistics_by_project(project_id,
                                                             args, statistics=True)
        return util.success(output)


@doc(tags=['Issue'], description="Get issue available status")
@marshal_with(route_model.IssueStatusResponse)
class IssueStatusV2(MethodResource):
    @ jwt_required
    def get(self):
        return list_issue_statuses('api')


class IssueStatus(Resource):
    @ jwt_required
    def get(self):
        return list_issue_statuses('api')
        

@doc(tags=['Issue'], description="Get issue available priority")
@marshal_with(route_model.IssuePriorityResponse)
class IssuePriorityV2(MethodResource):
    @ jwt_required
    def get(self):
        return get_issue_priority()


class IssuePriority(Resource):
    @ jwt_required
    def get(self):
        return get_issue_priority()


@doc(tags=['Issue'], description="Get issue available tracker")
@marshal_with(route_model.IssueTrackerResponse)
class IssueTrackerV2(MethodResource):
    @ jwt_required
    def get(self):
        return get_issue_trackers()


class IssueTracker(Resource):
    @ jwt_required
    def get(self):
        return get_issue_trackers()


@doc(tags=['Issue'], description="Get issue's family(relation, parent, children)")
@use_kwargs(route_model.IssueIssueFamilySchema, location="query")
@marshal_with(route_model.IssueFamilyResponse)
class IssueFamilyV2(MethodResource):
    @ jwt_required
    def get(self, issue_id, **kwargs):
        redmine_issue = redmine_lib.redmine.issue.get(issue_id, include=['children', 'relations'])
        require_issue_visible(issue_id, issue_info=NexusIssue().set_redmine_issue_v2(redmine_issue).to_json())
        family = get_issue_family(redmine_issue, kwargs)
        return util.success(family)


class IssueFamily(Resource):
    @ jwt_required
    def get(self, issue_id):
        parser = reqparse.RequestParser()
        parser.add_argument('with_point', type=bool)
        args = parser.parse_args()
        redmine_issue = redmine_lib.redmine.issue.get(issue_id, include=['children', 'relations'])
        require_issue_visible(issue_id, issue_info=NexusIssue().set_redmine_issue_v2(redmine_issue).to_json())
        family = get_issue_family(redmine_issue, args)
        return util.success(family)


class MyIssueStatistics(Resource):
    @ jwt_required
    def get(self):
        parser = reqparse.RequestParser()
        parser.add_argument('from_time', type=str, required=True)
        parser.add_argument('to_time', type=str)
        parser.add_argument('status_id', type=int)
        args = parser.parse_args()
        output = get_issue_statistics(args, get_jwt_identity()['user_id'])
        return output


@doc(tags=['Issue'], description="Get my active issue number")
@marshal_with(route_model.MyOpenIssueStatisticsResponse)
class MyOpenIssueStatisticsV2(MethodResource):
    @ jwt_required
    def get(self):
        return get_open_issue_statistics(get_jwt_identity()['user_id'])


class MyOpenIssueStatistics(Resource):
    @ jwt_required
    def get(self):
        return get_open_issue_statistics(get_jwt_identity()['user_id'])


@doc(tags=['Issue'], description="Get my weekly active issue number")
@marshal_with(route_model.MyIssueWeekStatisticsResponse)
class MyIssueWeekStatisticsV2(MethodResource):
    @ jwt_required
    def get(self):
        return get_issue_statistics_in_period('week', get_jwt_identity()['user_id'])


class MyIssueWeekStatistics(Resource):
    @ jwt_required
    def get(self):
        return get_issue_statistics_in_period('week', get_jwt_identity()['user_id'])


@doc(tags=['Issue'], description="Get my monthly active issue number")
@marshal_with(route_model.MyIssueMonthStatisticsResponse)
class MyIssueMonthStatisticsV2(MethodResource):
    @ jwt_required
    def get(self):
        return get_issue_statistics_in_period('month', get_jwt_identity()['user_id'])

class MyIssueMonthStatistics(Resource):
    @ jwt_required
    def get(self):
        return get_issue_statistics_in_period('month', get_jwt_identity()['user_id'])


@doc(tags=['Issue'], description="Get user's issues' numbers of each priorities.")
@marshal_with(route_model.DashboardIssuePriorityResponse)
class DashboardIssuePriorityV2(MethodResource):
    @ jwt_required
    def get(self, user_id):
        if int(user_id) == get_jwt_identity()['user_id'] or get_jwt_identity(
        )['role_id'] in (3, 5):
            return count_priority_number_by_issues(user_id)
        else:
            return {'message': 'Access token is missing or invalid'}, 401


class DashboardIssuePriority(Resource):
    @ jwt_required
    def get(self, user_id):
        if int(user_id) == get_jwt_identity()['user_id'] or get_jwt_identity(
        )['role_id'] in (3, 5):
            return count_priority_number_by_issues(user_id)
        else:
            return {'message': 'Access token is missing or invalid'}, 401


@doc(tags=['Issue'], description="Get user's issues' numbers of each projects.")
@marshal_with(route_model.DashboardIssueProjectResponse)
class DashboardIssueProjectV2(MethodResource):
    @ jwt_required
    def get(self, user_id):
        if int(user_id) == get_jwt_identity()['user_id'] or get_jwt_identity(
        )['role_id'] in (3, 5):
            return count_project_number_by_issues(user_id)
        else:
            return {'message': 'Access token is missing or invalid'}, 401


class DashboardIssueProject(Resource):
    @ jwt_required
    def get(self, user_id):
        if int(user_id) == get_jwt_identity()['user_id'] or get_jwt_identity(
        )['role_id'] in (3, 5):
            return count_project_number_by_issues(user_id)
        else:
            return {'message': 'Access token is missing or invalid'}, 401

@doc(tags=['Issue'], description="Get user's issues' numbers of each projects.")
@marshal_with(route_model.DashboardIssueTypeResponse)
class DashboardIssueTypeV2(MethodResource):
    @ jwt_required
    def get(self, user_id):
        if int(user_id) == get_jwt_identity()['user_id'] or get_jwt_identity(
        )['role_id'] in (3, 5):
            return count_type_number_by_issues(user_id)
        else:
            return {'message': 'Access token is missing or invalid'}, 401


class DashboardIssueType(Resource):
    @ jwt_required
    def get(self, user_id):
        if int(user_id) == get_jwt_identity()['user_id'] or get_jwt_identity(
        )['role_id'] in (3, 5):
            return count_type_number_by_issues(user_id)
        else:
            return {'message': 'Access token is missing or invalid'}, 401


class RequirementByIssueV2(MethodResource):
    # 用issues ID 取得目前所有的需求清單
    @doc(tags=['Unknown'], description="Get requirement by issue_id.")
    @ jwt_required
    def get(self, issue_id):
        output = get_requirements_by_issue_id(issue_id)
        return util.success(output)

    # 用issues ID 新建立需求清單
    @doc(tags=['Unknown'], description="Create requirement by issue_id.")
    @ jwt_required
    def post(self, issue_id):
        parser = reqparse.RequestParser()
        parser.add_argument('project_id', type=int)
        # parser.add_argument('flow_info', type=str)
        args = parser.parse_args()
        output = post_requirement_by_issue_id(issue_id, args)
        return util.success(output)


class RequirementByIssue(Resource):
    # 用issues ID 取得目前所有的需求清單
    @ jwt_required
    def get(self, issue_id):
        output = get_requirements_by_issue_id(issue_id)
        return util.success(output)

    # 用issues ID 新建立需求清單
    @ jwt_required
    def post(self, issue_id):
        parser = reqparse.RequestParser()
        parser.add_argument('project_id', type=int)
        # parser.add_argument('flow_info', type=str)
        args = parser.parse_args()
        output = post_requirement_by_issue_id(issue_id, args)
        return util.success(output)


class RequirementV2(MethodResource):
    # 用requirement_id 取得目前需求流程
    @doc(tags=['Unknown'], description="Get requirement by requirement_id.")
    @ jwt_required
    def get(self, requirement_id):
        output = get_requirement_by_rqmt_id(requirement_id)
        return util.success(output)

    # 用requirement_id 刪除目前需求流程
    @doc(tags=['Unknown'], description="Delete requirement by requirement_id.")
    @ jwt_required
    def delete(self, requirement_id):
        del_requirement_by_rqmt_id(requirement_id)
        return util.success()

    # 用requirement_id 更新目前需求流程
    @doc(tags=['Unknown'], description="Update requirement by requirement_id.")
    @ jwt_required
    def put(self, requirement_id):
        parser = reqparse.RequestParser()
        parser.add_argument('flow_info', type=str)
        args = parser.parse_args()
        modify_requirement_by_rqmt_id(requirement_id, args)
        return util.success()


class Requirement(Resource):
    # 用requirement_id 取得目前需求流程
    @ jwt_required
    def get(self, requirement_id):
        output = get_requirement_by_rqmt_id(requirement_id)
        return util.success(output)

    # 用requirement_id 刪除目前需求流程
    @ jwt_required
    def delete(self, requirement_id):
        del_requirement_by_rqmt_id(requirement_id)
        return util.success()

    # 用requirement_id 更新目前需求流程
    @ jwt_required
    def put(self, requirement_id):
        parser = reqparse.RequestParser()
        parser.add_argument('flow_info', type=str)
        args = parser.parse_args()
        modify_requirement_by_rqmt_id(requirement_id, args)
        return util.success()


@doc(tags=['Unknown'], description="Get supported flow type.")
@marshal_with(route_model.GetFlowTypeResponse)
class GetFlowTypeV2(MethodResource):
    @ jwt_required
    def get(self):
        output = get_flow_support_type()
        return util.success(output)


class GetFlowType(Resource):
    @ jwt_required
    def get(self):
        output = get_flow_support_type()
        return util.success(output)


class FlowByIssueV2(MethodResource):
    @doc(tags=['Unknown'], description="Get flow by issue_id.")
    # 用issues ID 取得目前所有的需求清單
    @ jwt_required
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
    @doc(tags=['Unknown'], description="Create flow by issue_id.")
    @ jwt_required
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


class FlowByIssue(Resource):
    # 用issues ID 取得目前所有的需求清單
    @ jwt_required
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
    @ jwt_required
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


class FlowV2(MethodResource):
    @doc(tags=['Unknown'], description="Get supported flow type.")
    # 用requirement_id 取得目前需求流程
    @ jwt_required
    def get(self, flow_id):
        output = get_flow_by_flow_id(flow_id)
        return util.success(output)

    @doc(tags=['Unknown'], description="Create supported flow type.")
    # 用requirement_id 刪除目前需求流程
    @ jwt_required
    def delete(self, flow_id):
        output = disabled_flow_by_flow_id(flow_id)
        return util.success(output, has_date_etc=True)

    @doc(tags=['Unknown'], description="Delete supported flow type.")
    # 用requirement_id 更新目前需求流程
    @ jwt_required
    def put(self, flow_id):
        parser = reqparse.RequestParser()
        parser.add_argument('serial_id', type=int)
        parser.add_argument('type_id', type=int)
        parser.add_argument('name', type=str)
        parser.add_argument('description', type=str)
        args = parser.parse_args()
        output = modify_flow_by_flow_id(flow_id, args)
        return util.success(output, has_date_etc=True)


class Flow(Resource):
    # 用requirement_id 取得目前需求流程
    @ jwt_required
    def get(self, flow_id):
        output = get_flow_by_flow_id(flow_id)
        return util.success(output)

    # 用requirement_id 刪除目前需求流程
    @ jwt_required
    def delete(self, flow_id):
        output = disabled_flow_by_flow_id(flow_id)
        return util.success(output, has_date_etc=True)

    # 用requirement_id 更新目前需求流程
    @ jwt_required
    def put(self, flow_id):
        parser = reqparse.RequestParser()
        parser.add_argument('serial_id', type=int)
        parser.add_argument('type_id', type=int)
        parser.add_argument('name', type=str)
        parser.add_argument('description', type=str)
        args = parser.parse_args()
        output = modify_flow_by_flow_id(flow_id, args)
        return util.success(output, has_date_etc=True)


@doc(tags=['Unknown'], description="Get all paramenters' type.")
class ParameterTypeV2(MethodResource):
    @ jwt_required
    def get(self):
        output = get_parameter_types()
        return util.success(output)


class ParameterType(Resource):
    @ jwt_required
    def get(self):
        output = get_parameter_types()
        return util.success(output)


class ParameterByIssueV2(MethodResource):
    # 用issues ID 取得目前所有的需求清單
    @doc(tags=['Unknown'], description="Get paramenter by issue_id.")
    @ jwt_required
    def get(self, issue_id):
        output = get_parameters_by_issue_id(issue_id)
        return util.success(output)

    # 用issues ID 新建立需求清單
    @doc(tags=['Unknown'], description="Create paramenter by issue_id.")
    @ jwt_required
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

class ParameterByIssue(Resource):
    # 用issues ID 取得目前所有的需求清單
    @ jwt_required
    def get(self, issue_id):
        output = get_parameters_by_issue_id(issue_id)
        return util.success(output)

    # 用issues ID 新建立需求清單
    @ jwt_required
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


class ParameterV2(MethodResource):
    # 用requirement_id 取得目前需求流程
    @doc(tags=['Unknown'], description="Get paramenter by parameter_id.")
    @ jwt_required
    def get(self, parameter_id):
        output = get_parameters_by_param_id(parameter_id)
        return util.success(output)

    # 用requirement_id 刪除目前需求流程
    @doc(tags=['Unknown'], description="Delete paramenter by parameter_id.")
    @ jwt_required
    def delete(self, parameter_id):
        output = del_parameters_by_param_id(parameter_id)
        return util.success(output)

    # 用requirement_id 更新目前需求流程
    @doc(tags=['Unknown'], description="Update paramenter by parameter_id.")
    @ jwt_required
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


class Parameter(Resource):
    # 用requirement_id 取得目前需求流程
    @ jwt_required
    def get(self, parameter_id):
        output = get_parameters_by_param_id(parameter_id)
        return util.success(output)

    # 用requirement_id 刪除目前需求流程
    @ jwt_required
    def delete(self, parameter_id):
        output = del_parameters_by_param_id(parameter_id)
        return util.success(output)

    # 用requirement_id 更新目前需求流程
    @ jwt_required
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
    @ jwt_required
    def post(self):
        parser = reqparse.RequestParser()
        parser.add_argument('issue_id', type=int, required=True)
        parser.add_argument('issue_to_id', type=int, required=True)
        args = parser.parse_args()
        output = post_issue_relation(args['issue_id'], args['issue_to_id'], get_jwt_identity()['user_account'])
        return util.success(output)

    @ jwt_required
    def put(self):
        parser = reqparse.RequestParser()
        parser.add_argument('issue_id', type=int, required=True)
        parser.add_argument('issue_to_ids', type=list, location='json', required=True)
        args = parser.parse_args()
        put_issue_relation(args['issue_id'], args['issue_to_ids'], get_jwt_identity()['user_account'])
        return util.success()

    @ jwt_required
    def delete(self, relation_id):
        output = delete_issue_relation(relation_id, get_jwt_identity()['user_account'])
        return util.success(output)


class CheckIssueClosable(Resource):
    @ jwt_required
    def get(self, issue_id):
        output = check_issue_closable(issue_id)
        return util.success(output)


class ExecutIssueAlert(Resource):
    def post(self):
        alert_mapping = {}
        alerts = model.Alert.query.filter_by(disabled=False)
        alerts = [alert for alert in alerts if model.Project.query.get(alert.project_id).alert]
        for alert in alerts:
            alert_mapping.setdefault(alert.project_id, []).append(
                {"condition": alert.condition, "days": alert.days})

        return util.success(execute_issue_alert(alert_mapping))


class IssueSocket(Namespace):
    def on_connect(self):
        print('connect')


    def on_disconnect(self):
        print('Client disconnected')

    def on_join(self, data):
        join_room(data['project_id'])
        print('join', data['project_id'])

    def on_leave(self, data):
        leave_room(data['project_id'])
        print('leave', data['project_id'])


class IssueFilterByProject(Resource):
    @jwt_required
    def get(self, project_id):
        return util.success(get_custom_issue_filter(get_jwt_identity()['user_id'], project_id))

    @jwt_required
    def post(self, project_id):
        user_id = get_jwt_identity()['user_id']
        parser = reqparse.RequestParser()
        parser.add_argument('name', type=str, required=True)
        parser.add_argument('type', type=str, required=True)
        parser.add_argument('assigned_to_id', type=str)
        parser.add_argument('fixed_version_id', type=str)
        parser.add_argument('focus_tab', type=str)
        parser.add_argument('group_by', type=dict)
        parser.add_argument('priority_id', type=str)
        parser.add_argument('show_closed_issues', type=bool)
        parser.add_argument('show_closed_versions', type=bool)
        parser.add_argument('status_id', type=str)
        parser.add_argument('tags', type=str)
        parser.add_argument('tracker_id', type=str)
        args = parser.parse_args()

        if args["type"] != "issue_board" and args.get("group_by") is not None:
            raise DevOpsError(400, "Column group_by is only available when type is issue_board",
                              error=apiError.argument_error("group_by"))
        if args["type"] != "my_work" and args.get("focus_tab") is not None:
            raise DevOpsError(400, "Column focus_tab is only available when type is my_work",
                              error=apiError.argument_error("focus_tab"))

        return util.success(create_custom_issue_filter(user_id, project_id, args))

    @jwt_required
    def put(self, project_id, custom_filter_id):
        parser = reqparse.RequestParser()
        parser.add_argument('name', type=str, required=True)
        parser.add_argument('type', type=str, required=True)
        parser.add_argument('assigned_to_id', type=str)
        parser.add_argument('fixed_version_id', type=str)
        parser.add_argument('focus_tab', type=str)
        parser.add_argument('group_by', type=dict)
        parser.add_argument('priority_id', type=str)
        parser.add_argument('show_closed_issues', type=bool)
        parser.add_argument('show_closed_versions', type=bool)
        parser.add_argument('status_id', type=str)
        parser.add_argument('tags', type=str)
        parser.add_argument('tracker_id', type=str)
        args = parser.parse_args()

        if args["type"] != "issue_board" and args.get("group_by") is not None:
            raise DevOpsError(400, "Column group_by is only available when type is issue_board",
                              error=apiError.argument_error("group_by"))
        if args["type"] != "my_work" and args.get("focus_tab") is not None:
            raise DevOpsError(400, "Column focus_tab is only available when type is my_work",
                              error=apiError.argument_error("focus_tab"))

        return util.success(put_custom_issue_filter(custom_filter_id, project_id, args))

    @jwt_required
    def delete(self, project_id, custom_filter_id):
        CustomIssueFilter.query.filter_by(id=custom_filter_id).delete()
        db.session.commit()


class DownloadProject(Resource):
    # download/execute
    @jwt_required
    def post(self, project_id):
        parser = reqparse.RequestParser()
        parser.add_argument('fixed_version_id', type=str)
        parser.add_argument('status_id', type=str)
        parser.add_argument('tracker_id', type=str)
        parser.add_argument('assigned_to_id', type=str)
        parser.add_argument('priority_id', type=str)
        parser.add_argument('search', type=str)
        parser.add_argument('selection', type=str)
        parser.add_argument('sort', type=str)
        parser.add_argument('parent_id', type=str)
        parser.add_argument('due_date_start', type=str)
        parser.add_argument('due_date_end', type=str)
        parser.add_argument('with_point', type=bool, default=True)
        parser.add_argument('levels', type=int, default=3)
        parser.add_argument('deploy_column', type=dict, action='append', required=True)
        args = parser.parse_args()

        if get_lock_status("download_pj_issues")["is_lock"]:
            return util.success("previous is still running")
        download_issue_excel = DownloadIssueAsExcel(args, project_id, get_jwt_identity()["user_id"])
        threading.Thread(target=download_issue_excel.execute).start()
        return util.success()

    # download/is_exist
    @jwt_required 
    def get(self, project_id):
        return util.success(pj_download_file_is_exist(project_id))

    # download/execute
    @jwt_required    
    def patch(self, project_id):
        if not pj_download_file_is_exist(project_id)["file_exist"]:
            raise apiError.DevOpsError(
                404, 'This file can not be downloaded because it is not exist.',
                apiError.project_issue_file_not_exits(project_id))

        return send_file(f"../logs/project_excel_file/{project_id}.xlsx")

class IssueCommitRelation(Resource):    
    @jwt_required
    def get(self):
        parser = reqparse.RequestParser()
        parser.add_argument('commit_id', type=str, required=True)
        args = parser.parse_args()
        return util.success(get_commit_hook_issues(commit_id=args["commit_id"]))

    @jwt_required
    def patch(self):
        parser = reqparse.RequestParser()
        parser.add_argument('commit_id', type=str, required=True)
        parser.add_argument('issue_ids', type=int, action='append', required=True)
        args = parser.parse_args()
        return util.success(modify_hook(args))