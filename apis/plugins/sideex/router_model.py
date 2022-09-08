from marshmallow import Schema, fields
from util import CommonBasicResponse



#################################### Schema ####################################


class SideexGetVariableRes(Schema):
    filename = fields.Str(required=False, example="sideex.json")