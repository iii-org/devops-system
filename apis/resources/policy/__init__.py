import json
import os.path
import re

from flask_jwt_extended import jwt_required, get_jwt_identity
from flask_restful import Resource, reqparse
import util


DB_POLICY = dict({
	"MSSQL": {
		"RE": "^((?=.{8,128}$)(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).*|(?=.{8,128}$)(?=.*\d)(?=.*[a-zA-Z])(?=.*[!\u0022#$%&'()*+,./:;<=>?@[\]\^_`{|}~-]).*)",
		"Policy": "The password doesn't contain the account name of the user.\nThe password is at least eight characters long.\nThe password contains characters from three of the following four categories:\n	Latin uppercase letters (A through Z)\n	Latin lowercase letters (a through z)\n	Base 10 digits (0 through 9)\n	Non-alphanumeric characters such as: exclamation point (!), dollar sign ($), number sign (#), or percent (%).\nPasswords can be up to 128 characters long. Use passwords that are as long and complex as possible."
	},
	"MySQL": {
		"RE": "^((?=.{8,}$)(?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?=.*[!\u0022#$%&'()*+,./:;<=>?@[\]\^_`{|}~-]).*)",
		"Policy": "The password is at least eight characters long.\nThe passwords must contain at least 1 numeric character, 1 lowercase character, 1 uppercase character, and 1 special (nonalphanumeric) character."
	},
	"mariaDB": {
		"RE": "^((?=.{8,}$)(?=.*\d)(?=.*[a-zA-Z])(?=.*[!\u0022#$%&'()*+,./:;<=>?@[\]\^_`{|}~-]).*)",
		"Policy": "The password is at least eight characters long.\nThe passwords must contain at least 1 numeric character, 1 lowercase character or 1 uppercase character, and 1 special (nonalphanumeric) character."
	},
	"influxDB": {
		"RE": "",
		"Policy": ""
	},
	"Elasticsearch": {
		"RE": "^((?=.{6,}$))",
		"Policy": "The password is at least six characters long."
	},
	"mongoDB": {
		"RE": "",
		"Policy": []
	},
	"SQLite": {
		"RE": "",
		"Policy": []
	},
	"postgreSQL": {
		"RE": "^((?=.{8,}$)(?=.*\d)(?=.*[a-zA-Z])(?=.*[!\u0022#$%&'()*+,./:;<=>?@[\]\^_`{|}~-]).*)",
		"Policy": "The password doesn't contain the account name of the user.\nThe password is at least eight characters long.\nThe passwords must contain at least 1 numeric character, 1 lowercase character or 1 uppercase character."
	}
})


def check_pswd_policy(db_type, db_user, db_pswd):
    db_policy = DB_POLICY[db_type]
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