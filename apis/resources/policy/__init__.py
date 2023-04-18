import json
import os.path
import re

from flask_jwt_extended import jwt_required, get_jwt_identity
from flask_restful import Resource, reqparse
import util


def check_pswd_policy(db_type, db_user, db_pswd):
    policy = json.load(open(os.getcwd()+ "/apis/resource/policy/db_policy.json"))
    db_policy = policy[db_type]
    if db_policy:
        output = {"pass": True}
        if db_policy["RE"]:
            result = re.match(db_policy["RE"], db_pswd)
            if result is None:
                output["pass"] = False
                output["description"] = db_policy["Policy"]
            if db_type == "MSSQL" or db_type == "postgreSQL":
                if db_user in db_pswd:
                    output["pass"] = False
                    output["description"] = db_policy["Policy"]
        return output
    return None


class DBPSWDPolicy(Resource):
    @jwt_required()
    def post(self):
        parser = reqparse.RequestParser()
        parser.add_argument("db_type", type=str, required=True)
        parser.add_argument("db_user", type=str, required=True)
        parser.add_argument("db_pswd", type=str, required=True)
        args = parser.parse_args()
        output = check_pswd_policy(args.get("db_type"), args.get("db_user"), args.get("db_pswd"))
        if output:
            return util.success(output)
        else:
            return util.respond(404, f'{args.get("db_type")}')