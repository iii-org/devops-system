from marshmallow import Schema, fields
from util import CommonBasicResponse, CommonResponse


class UIRouteResponse(Schema):
    created_at = fields.Str(required=True)
    id = fields.Int(required=True)
    route_name = fields.Str(required=True)
    updated_at = fields.Str(required=True)


class UIRouteListResponse(Schema):
    data = fields.List(fields.Nested(UIRouteResponse), required=True)
