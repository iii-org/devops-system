from flask_jwt_extended import get_jwt_identity
from flask_restful import Resource

from resources import apiError, project, issue, util


class Role:
    def __init__(self, id_, name):
        self.id = id_
        self.name = name


RD = Role(1, 'Engineer')
PM = Role(3, 'Project Manager')
ADMIN = Role(5, 'Administrator')
ALL_ROLES = [RD, PM, ADMIN]


def require_role(allowed_roles,
                 err_message='Your role does not have the permission for this operation.'):
    if type(allowed_roles) is int:
        allowed_roles = [allowed_roles]
    for allowed_role in allowed_roles:
        if allowed_role == get_jwt_identity()['role_id']:
            return
    raise apiError.NotAllowedError(err_message)


def require_admin(err_message='You must be an admin for this operation.'):
    require_role([ADMIN.id], err_message)


def require_pm(err_message='You must be a PM for this operation.', exclude_admin=False):
    if exclude_admin:
        require_role([PM.id], err_message)
    else:
        require_role([PM.id, ADMIN.id], err_message)


def require_in_project(project_id,
                       err_message='You need to be in the project for this operation.',
                       even_admin=False):
    identity = get_jwt_identity()
    user_id = identity['user_id']
    if not even_admin and identity['role_id'] == ADMIN.id:
        return
    check_result = project.verify_project_user(project_id, user_id)
    if check_result:
        return
    else:
        raise apiError.NotInProjectError(err_message)


def require_issue_visible(issue_id,
                          err_message="You don't have the permission to access this issue.",
                          even_admin=False):
    identity = get_jwt_identity()
    user_id = identity['user_id']
    if not even_admin and identity['role_id'] == ADMIN.id:
        return
    check_result = issue.verify_issue_user(issue_id, user_id)
    if check_result:
        return
    else:
        raise apiError.NotInProjectError(err_message)


def require_user_himself(user_id,
                         err_message="You must be admin to access another user's data.",
                         even_pm=True,
                         even_admin=False):
    identity = get_jwt_identity()
    my_user_id = identity['user_id']
    role_id = identity['role_id']
    if my_user_id == int(user_id):
        return
    if (role_id == RD.id or
            even_pm and role_id == PM.id or
            even_admin and role_id == ADMIN.id):
        raise apiError.NotUserHimselfError(err_message)
    return


def get_role_list():
    output_array = []
    for r in ALL_ROLES:
        role_info = {"id": r.id, "name": r.name}
        output_array.append(role_info)

    return util.success({"role_list": output_array})


# --------------------- Resources ---------------------
class RoleList(Resource):
    # noinspection PyMethodMayBeStatic
    def get(self):
        return get_role_list()
