from marshmallow import Schema, fields
from util import CommonBasicResponse

### Project Relation

#################################### Schema ####################################

########## API Action ##########

class GetProjectFamilymembersByUserDataSchema(Schema):
    id = fields.Int(required=True)
    name = fields.Str(required=True)
    role_id = fields.Int(required=True)
    role_name = fields.Str(required=True)

#################################### Response ####################################

########## Module ##########

class GetProjectFamilymembersByUserDataSchema(Schema):
    id = fields.Int(required=True)
    name = fields.Str(required=True)
    role_id = fields.Int(required=True)
    role_name = fields.Str(required=True)

########## API Action ##########

class CheckhasSonProjectResponse(Schema):
    has_child = fields.Bool(required=True)

class GetProjectRootIDResponse(Schema):
    root_project_id = fields.Int(required=True)

class GetProjectFamilymembersByUserResponse(CommonBasicResponse):
    data = fields.List(fields.Nested(
        GetProjectFamilymembersByUserDataSchema, required=True))

