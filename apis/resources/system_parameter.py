from flask_restful import Resource, reqparse
from github import Github

import json
import model
import util as util
from model import db, SystemParameter
from resources import apiError


def row_to_dict(row):
    if row is None:
        return row
    return {key: getattr(row, key) for key in type(row).__table__.columns.keys()}


def verify_github_info(value):
    account = value["account"]
    token = value["token"]
    g = Github(login_or_token=token)
    try:
        login = g.get_user().login
    except:
        raise apiError.DevOpsError(
            400,
            'Token is invalid.',
            apiError.error_3rd_party_api('GitHub', 'Token is invalid.'))

    if login != account:
        raise apiError.DevOpsError(
            400,
            'Token is not belong to this account.',
            apiError.error_3rd_party_api('GitHub', 'Token is not belong to this account.'))

    if len([repo for repo in g.search_repositories(query='iiidevops in:name')]) == 0:
        raise apiError.DevOpsError(
            400,
            'Token is not belong to project(iiidevops).',
            apiError.error_3rd_party_api('GitHub', 'Token is not belong to our project(iiidevops).'))


def get_system_parameter():
    return [
        row_to_dict(system_parameter) for system_parameter in SystemParameter.query.all()]


def update_system_parameter(id, args):
    id_mapping = {
        2: verify_github_info
    }
    value = args["value"]
    active = args.get("active") 
    if id in id_mapping:
        id_mapping[id](value)

    system_parameter = SystemParameter.query.get(id)
    system_parameter.value = value
    if args.get("active") is not None:
        system_parameter.active = args["active"]
    db.session.commit()


# --------------------- Resources ---------------------


class SystemParameters(Resource):
    def get(self):
        return util.success(get_system_parameter())

    def put(self, param_id):
        parser = reqparse.RequestParser()
        parser.add_argument('value', type=str, location='json', required=True)
        parser.add_argument('active', type=bool)
        args = parser.parse_args()
        args["value"] = json.loads(args["value"].replace("\'", "\""))
        return util.success(update_system_parameter(param_id, args))
