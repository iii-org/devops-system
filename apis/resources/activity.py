from datetime import datetime
from enum import Enum
from functools import wraps

from pprint import pprint

from flask_jwt_extended import get_jwt_identity

import model
import nexus


def record_activity(action_type):
    # Must be used after @jwt_required decorator!
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            identity = get_jwt_identity()
            new = model.Activity(
                operator_id=identity['user_id'],
                action_type=action_type,
                operator_name=identity['user_account'],
                act_at=datetime.now()
            )
            # Extract action_parts and object_id
            object_id = None
            action_parts = None
            if action_type == ActionType.DELETE_PROJECT:
                project_id = kwargs['project_id']
                project = nexus.nx_get_project(id=project_id)
                object_id = project_id
                action_parts = f'{project.display}({project.name}/{project.id})'
            new.object_id = object_id
            new.action_parts = action_parts
            print(new)
            return fn(*args, **kwargs)

        return wrapper

    return decorator


class ActionType(Enum):
    CREATE_PROJECT = 1
    UPDATE_PROJECT = 2  # Requires parameter "project_id"
    DELETE_PROJECT = 3  # Requires parameter "project_id"
    ADD_MEMBER = 4  # Requires parameter "project_id" and "user_id"
    REMOVE_MEMBER = 5  # Requires parameter "project_id" and "user_id"
    CREATE_USER = 6
    UPDATE_USER = 7  # Requires parameter "user_id"
    DELETE_USER = 8  # Requires parameter "user_id"

    def is_user_action(self):
        return self in [self.CREATE_USER, self.UPDATE_USER, self.DELETE_USER]

    def is_project_action(self):
        return self in [self.CREATE_PROJECT, self.UPDATE_PROJECT, self.DELETE_PROJECT]

    def is_member_action(self):
        return self in [self.ADD_MEMBER, self.REMOVE_MEMBER]

    @staticmethod
    def repr(row):
        if row.action_type == ActionType.DELETE_PROJECT:
            return f'<{row.id}:{str(row.action_type).split(".")[1]}>' \
                   f' {row.operator_name}({row.operator_id})' \
                   f' deleted project {row.action_parts} at {str(row.act_at)}.'
