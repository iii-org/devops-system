import inspect
from datetime import datetime, timedelta
from functools import wraps
from time import strptime, mktime

from flask_jwt_extended import get_jwt_identity, jwt_required
from flask_restful import Resource, reqparse
from sqlalchemy import desc, or_

import model
import nexus
import util
from enums.action_type import ActionType
from model import db
from resources import role, apiError
from resources.apiError import DevOpsError


def record_activity(action_type):
    # Must be used after @jwt_required decorator!
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            identity = get_jwt_identity()
            if identity is None:
                identity = {'user_id': -1, 'user_account': 'anonymous'}
            new = Activity(
                operator_id=identity['user_id'],
                action_type=action_type,
                operator_name=identity['user_account'],
                act_at=datetime.now()
            )
            itargs = kwargs.copy()
            for i, key in enumerate(inspect.getfullargspec(fn).args):
                if i >= len(args):
                    break
                if key == 'self':
                    continue
                itargs[key] = args[i]
            new.fill_by_arguments(itargs)
            ret = fn(*args, **kwargs)
            new.fill_by_return_value(ret)
            db.session.add(new)
            db.session.commit()
            return ret

        return wrapper

    return decorator


def get_activities(query):
    ret = []
    rows = query.all()
    for row in rows:
        ret.append({
            'id': row.id,
            'action_type': row.action_type.name,
            'action_parts': row.action_parts,
            'operator_id': row.operator_id,
            'operator_name': row.operator_name,
            'object_id': row.object_id,
            'act_at': str(row.act_at)
        })
    return ret


def build_query(args, base_query=None):
    if base_query is not None:
        query = base_query
    else:
        query = model.Activity.query
    query = query.order_by(desc(model.Activity.act_at))

    a_actions = args['actions']
    if a_actions is not None:
        ors = []
        for s_action in [x.strip() for x in a_actions.split(',')]:
            try:
                action = ActionType[s_action.upper()]
            except KeyError:
                raise DevOpsError(400, 'unknown action',
                                  error=apiError.invalid_code_path(
                                      f'unknown action type:{s_action}'))
            ors.append(model.Activity.action_type == action)
        query = query.filter(or_(*ors))

    object_id = args['object_id']
    if object_id is not None:
        if object_id[0] == '@':
            query = query.filter(model.Activity.object_id.like(f'%{object_id}'))
        elif object_id[-1] == '@':
            query = query.filter(model.Activity.object_id.like(f'{object_id}%'))
        else:
            query = query.filter(model.Activity.object_id == str(object_id))

    parts_search = args['parts_search']
    if parts_search is not None:
        query = query.filter(model.Activity.action_parts.like(f'%{parts_search}%'))

    a_from_date = args['from_date']
    a_to_date = args['to_date']
    if a_from_date is not None:
        from_date = datetime.fromtimestamp(mktime(strptime(a_from_date, '%Y-%m-%d')))
        query = query.filter(model.Activity.act_at >= from_date)
    if a_to_date is not None:
        to_date = datetime.fromtimestamp(mktime(strptime(a_to_date, '%Y-%m-%d')))
        to_date += timedelta(days=1)
        query = query.filter(model.Activity.act_at < to_date)

    limit = args['limit']
    page = args['page']
    query = query.offset(limit * page).limit(limit)

    return query


def limit_to_project(project_id):
    query = model.Activity.query.filter(model.Activity.action_type.in_([
        ActionType.CREATE_PROJECT, ActionType.UPDATE_PROJECT, ActionType.DELETE_PROJECT,
        ActionType.ADD_MEMBER, ActionType.REMOVE_MEMBER]
    ))
    query = query.filter(or_(
        model.Activity.object_id.like(f'%@{project_id}'),
        model.Activity.object_id == str(project_id)
    ))
    return query


class Activity(model.Activity):
    def fill_by_arguments(self, args):
        if self.action_type in [ActionType.UPDATE_PROJECT, ActionType.DELETE_PROJECT]:
            self.fill_project(args['project_id'])
        if self.action_type == ActionType.UPDATE_PROJECT:
            self.action_parts += f'@{str(args["args"])}'
        if self.action_type in [ActionType.ADD_MEMBER, ActionType.REMOVE_MEMBER]:
            self.object_id = f'{args["user_id"]}@{args["project_id"]}'
            project = nexus.nx_get_project(id=args['project_id'])
            user = nexus.nx_get_user(id=args['user_id'])
            self.action_parts = f'{user.name}@{project.name}'
        if self.action_type in [ActionType.UPDATE_USER, ActionType.DELETE_USER]:
            self.fill_user(args['user_id'])
        if self.action_type == ActionType.UPDATE_USER:
            content = args["args"].copy()
            for sensitive_key in ['password', 'old_password']:
                if sensitive_key in content:
                    content[sensitive_key] = '********'
            self.action_parts += f'@{str(content)}'

    def fill_by_return_value(self, ret):
        if self.action_type == ActionType.CREATE_PROJECT:
            self.fill_project(ret['project_id'])
        if self.action_type == ActionType.CREATE_USER:
            self.fill_user(ret['user_id'])

    def fill_project(self, project_id):
        project = nexus.nx_get_project(id=project_id)
        self.object_id = project_id
        self.action_parts = f'{project.display}({project.name}/{project.id})'

    def fill_user(self, user_id):
        user = nexus.nx_get_user(id=user_id)
        self.object_id = user_id
        self.action_parts = f'{user.name}({user.login}/{user.id})'


# --------------------- Resources ---------------------
class AllActivities(Resource):
    @jwt_required
    def get(self):
        role.require_admin()
        parser = reqparse.RequestParser()
        parser.add_argument('limit', type=int, default=100)
        parser.add_argument('page', type=int, default=0)
        parser.add_argument('from_date', type=str)
        parser.add_argument('to_date', type=str)
        parser.add_argument('actions', type=str)
        parser.add_argument('object_id', type=str)
        parser.add_argument('parts_search', type=str)
        args = parser.parse_args()
        query = build_query(args)
        return util.success(get_activities(query))


class ProjectActivities(Resource):
    @jwt_required
    def get(self, project_id):
        role.require_pm()
        role.require_in_project(project_id)
        parser = reqparse.RequestParser()
        parser.add_argument('limit', type=int, default=100)
        parser.add_argument('page', type=int, default=0)
        parser.add_argument('from_date', type=str)
        parser.add_argument('to_date', type=str)
        parser.add_argument('actions', type=str)
        parser.add_argument('object_id', type=str)
        parser.add_argument('parts_search', type=str)
        args = parser.parse_args()
        query = build_query(args, base_query=limit_to_project(project_id))
        return util.success(get_activities(query))
