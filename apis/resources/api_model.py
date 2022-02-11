
from marshmallow import Schema, fields

class PassSchema(Schema):
    pass

class LoginAdInfoJsonSchema(Schema):
    is_pass = fields.Boolean(required=True)
    login = fields.Str(required=True)
    data = fields.Nested(PassSchema,required=False)

class LoginJsonSchema(Schema):
    status = fields.Str(required=True)
    token = fields.Str(required=True)
    ad_info = fields.Nested(LoginAdInfoJsonSchema,required=True)

class LoginSchema(Schema):
    username = fields.Str(required=True, doc='username',example="admin")
    password = fields.Str(required=True, default=0, doc='password',example="III")

class LoginSuccessResponse(Schema):
    message = fields.Str(required=True)
    # input class
    data = fields.Nested(LoginJsonSchema,required=True)
    datetime = fields.Str(required=True)

    class Meta:
        strict = True