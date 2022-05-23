from marshmallow import Schema, fields
from util import CommonBasicResponse


class CreateTemplateFormProjectScheme(Schema):
    branch = fields.Str(required=True, description='Branch name', example="master")
    commit_id = fields.Str(required=True, description='commit short id',
                           example="d45736e4")
