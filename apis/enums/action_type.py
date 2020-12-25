from enum import Enum


class ActionType(Enum):
    CREATE_PROJECT = 1  # Must return a dict with key "project_id"
    UPDATE_PROJECT = 2  # Requires argument "project_id"
    DELETE_PROJECT = 3  # Requires argument "project_id"
    ADD_MEMBER = 4  # Requires argument "project_id" and "user_id"
    REMOVE_MEMBER = 5  # Requires argument "project_id" and "user_id"
    CREATE_USER = 6  # Must return a dict with key "user_id"
    UPDATE_USER = 7  # Requires argument "user_id"
    DELETE_USER = 8  # Requires argument "user_id"
