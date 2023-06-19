from resources import role
from nexus import nx_get_project_plugin_relation


def role_require_in_repo_project(repository_id: int):
    project_id = nx_get_project_plugin_relation(repo_id=repository_id).project_id
    role.require_in_project(project_id)
