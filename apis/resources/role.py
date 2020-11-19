from flask_jwt_extended import get_jwt_identity
from flask_restful import Resource

from model import db, ProjectUserRole
from resources import apiError, util
import model


class Role:
    def __init__(self, id_, name):
        self.id = id_
        self.name = name


RD = Role(1, 'Engineer')
PM = Role(3, 'Project Manager')
ADMIN = Role(5, 'Administrator')
ALL_ROLES = [RD, PM, ADMIN]


def get_role_name(role_id):
    for role in ALL_ROLES:
        if role.id == role_id:
            return role.name
    return 'Unknown Role'


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
    check_result = verify_project_user(project_id, user_id)
    if check_result:
        return
    else:
        raise apiError.NotInProjectError(err_message)


def require_user_himself(user_id,
                         err_message=None,
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
        if err_message is None:
            if even_admin:
                err_message = "Only the user himself can access another user's data."
            elif even_pm:
                err_message = "Only admin can access another user's data."
            else:
                err_message = "Only admin and PM can access another user's data."
        raise apiError.NotUserHimselfError(err_message)
    return


def verify_project_user(project_id, user_id):
    if util.is_dummy_project(project_id):
        return True
    count = model.ProjectUserRole.query.filter_by(
        project_id=project_id, user_id=user_id).count()
    return count > 0


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
