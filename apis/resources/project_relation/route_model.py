from marshmallow import Schema, fields
from numpy import require
from util import CommonBasicResponse


class CheckhasSonProjectResponse(Schema):
    has_child = fields.Bool(required=True)


class GetProjectRootIDResponse(Schema):
    root_project_id = fields.Int(required=True)


class GetProjectFamilymembersByUserDataSchema(Schema):
    id = fields.Int(required=True)
    name = fields.Str(required=True)
    role_id = fields.Int(required=True)
    role_name = fields.Str(required=True)


class GetProjectFamilymembersByUserResponse(CommonBasicResponse):
    data = fields.List(fields.Nested(
        GetProjectFamilymembersByUserDataSchema, required=True))

