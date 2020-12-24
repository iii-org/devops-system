import inspect
from datetime import datetime
from functools import wraps
from pprint import pprint

from flask_jwt_extended import get_jwt_identity

import model
import nexus
from enums.action_type import ActionType
from model import db


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
            pprint(new)
            # db.session.add(new)
            # db.session.commit()
            return ret

        return wrapper

    return decorator


class Activity(model.Activity):
    def fill_by_arguments(self, args):
        if self.action_type in [ActionType.UPDATE_PROJECT, ActionType.DELETE_PROJECT]:
            self.fill_project(args['project_id'])
        if self.action_type == ActionType.UPDATE_PROJECT:
            self.action_parts += f'@{args["args"]}'
        if self.action_type in [ActionType.ADD_MEMBER, ActionType.REMOVE_MEMBER]:
            self.object_id = f'{args["user_id"]}@{args["project_id"]}'
            project = nexus.nx_get_project(id=args['project_id'])
            user = nexus.nx_get_user(id=args['user_id'])
            self.action_parts = f'{user.name}@{project.name}'
        if self.action_type in [ActionType.UPDATE_USER, ActionType.DELETE_USER]:
            self.fill_user(args['user_id'])
        if self.action_type == ActionType.UPDATE_USER:
            self.action_parts += f'@{args["args"]}'

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
