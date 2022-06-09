from marshmallow import Schema, fields
from util import CommonBasicResponse


#################################### Schema ####################################

########## API Action ##########

class ExcalidrawCreateSchema(Schema):
    name = fields.Str(required=True)
    project_id = fields.Int(doc='project_id', example="-1", required=True)
    issue_ids = fields.Str(doc='issue_ids', example="1,2,3")

class ExcalidrawGetSchema(Schema):
    project_id = fields.Int(doc='project_id', example="-1")
    name = fields.Str()

class ExcalidrawPatchSchema(Schema):
    name = fields.Str()
    issue_ids = fields.Str(doc='issue_ids', example="1,2,3")

#################################### Response ####################################


########## Module ##########


########## API Action ##########
class ExcalidrawGetRes(CommonBasicResponse):
    data = fields.List(fields.Dict(
        example={
            "created_at": "1970-01-01 00:00:00.000000",
            "id": 1,
            "issue_ids": [1],
            "name": "name",
            "operator": {
                "id": 1,
                "login": "sysadmin",
                "name": "初始管理者"
            },
            "project_id": 1,
            "updated_at": "1970-01-01 00:00:00.000000",
            "url": "https://excalidraw.ingress-dev3.iiidevops.org/#room=0e31e20d11e62bc6c8ea,sf4U2sfVIqY9-WVrBNb-Ft"
        }
    ), required=True)


class ExcalidrawPatchRes(CommonBasicResponse):
    data = fields.Dict(
        example={
            "id": 1,
            "issue_ids": [1],
            "name": "name",
            "url": "https://excalidraw.ingress-dev3.iiidevops.org/#room=0e31e20d11e62bc6c8ea,sf4U2sfVIqY9-WVrBNb-Ft"
        }
    , required=True)

class CheckExcalidrawAliveRes(CommonBasicResponse):
    data = fields.Dict(
        example={"alive": True}
    , required=True)