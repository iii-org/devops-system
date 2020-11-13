from flask_jwt_extended import get_jwt_identity

from resources import apiError, project

RD = 1
PM = 3
ADMIN = 5


def require_role(allowed_roles,
                 err_message='Your role does not have the permission for this operation.'):
    if type(allowed_roles) is int:
        allowed_roles = [allowed_roles]
    for allowed_role in allowed_roles:
        if allowed_role == get_jwt_identity()['role_id']:
            return
    raise apiError.NotAllowedError(err_message)


def require_admin(err_message='You must be an admin for this operation.'):
    require_role([ADMIN], err_message)


def require_pm(err_message='You must be a PM for this operation.', exclude_admin=False):
    if exclude_admin:
        require_role([PM], err_message)
    else:
        require_role([PM, ADMIN], err_message)


def require_in_project(project_id,
                       err_message='You need to be in the project for this operation.',
                       even_admin=False):
    identity = get_jwt_identity()
    user_id = identity['user_id']
    if not even_admin and identity['role_id'] == ADMIN:
        return
    status = project.verify_project_user(project_id, user_id)
    if status:
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
    if role_id == RD or (even_pm and role_id == PM) or (even_admin and role_id == ADMIN):
        raise apiError.NotUserHimselfError(err_message)
    return
