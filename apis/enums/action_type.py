from enum import Enum


class ActionType(Enum):
    CREATE_PROJECT = 1  # Must return a dict with key "project_id"
    UPDATE_PROJECT = 2  # Requires argument "project_id"
    DELETE_PROJECT = 3  # Requires argument "project_id"
    ADD_MEMBER = 4  # Requires argument "project_id" and "user_id"
    REMOVE_MEMBER = 5  # Requires argument "project_id" and "user_id"
    CREATE_USER = 6 # Must return a dict with key "user_id"
    UPDATE_USER = 7  # Requires argument "user_id"
    DELETE_USER = 8  # Requires argument "user_id"

    def is_user_action(self):
        return self in [self.CREATE_USER, self.UPDATE_USER, self.DELETE_USER]

    def is_project_action(self):
        return self in [self.CREATE_PROJECT, self.UPDATE_PROJECT, self.DELETE_PROJECT]

    def is_member_action(self):
        return self in [self.ADD_MEMBER, self.REMOVE_MEMBER]

    @staticmethod
    def repr(act):
        return f'<{act.id}:{str(act.action_type).split(".")[1]}>' \
               f' {act.operator_name}({act.operator_id})' \
               f' on {act.action_parts} at {str(act.act_at)}.'
