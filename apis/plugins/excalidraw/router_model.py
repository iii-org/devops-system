from marshmallow import Schema, fields
from util import CommonBasicResponse


TIMESAMPLE = "1970-01-01 00:00:00.000000"
EXCALIDRAW_SAMPLE_URL = (
    "https://excalidraw.ingress-dev3.iiidevops.org/#room=0e31e20d11e62bc6c8ea,sf4U2sfVIqY9-WVrBNb-Ft"
)

#################################### Schema ####################################

########## API Action ##########


class ExcalidrawCreateSchema(Schema):
    name = fields.Str(required=True)
    project_id = fields.Int(doc="project_id", example="-1", required=True)
    issue_ids = fields.Str(doc="issue_ids", example="1,2,3")


class ExcalidrawGetSchema(Schema):
    project_id = fields.Int(doc="project_id", example="-1")
    name = fields.Str()


class ExcalidrawPatchSchema(Schema):
    name = fields.Str()
    issue_ids = fields.Str(doc="issue_ids", example="1,2,3")


class ExcalidrawFilePostSchema(Schema):
    file_key = fields.Str(doc="file_key", example="PgStCvMNgpMv_Zk27zsnQQ", required=True)
    room_key = fields.Str(doc="room_key", example="45665b05adfbac27b1d9", required=True)


#################################### Response ####################################


########## Module ##########


########## API Action ##########
class ExcalidrawGetRes(CommonBasicResponse):
    data = fields.List(
        fields.Dict(
            example={
                "created_at": TIMESAMPLE,
                "id": 1,
                "issue_ids": [1],
                "name": "name",
                "operator": {"id": 1, "login": "sysadmin", "name": "初始管理者"},
                "project": {"display": "display", "id": 1, "name": "name"},
                "updated_at": TIMESAMPLE,
                "url": EXCALIDRAW_SAMPLE_URL,
            }
        ),
        required=True,
    )


class ExcalidrawPostRes(CommonBasicResponse):
    data = fields.Dict(
        example={
            "created_at": TIMESAMPLE,
            "id": 1,
            "issue_ids": [1],
            "name": "name",
            "project_id": 1,
            "url": EXCALIDRAW_SAMPLE_URL,
        },
        required=True,
    )


class ExcalidrawPatchRes(CommonBasicResponse):
    data = fields.Dict(
        example={
            "id": 1,
            "issue_ids": [1],
            "name": "name",
            "url": EXCALIDRAW_SAMPLE_URL,
        },
        required=True,
    )


class CheckExcalidrawAliveRes(CommonBasicResponse):
    data = fields.Dict(
        example={"alive": True, "services": {"API": True, "UI": True, "Socket": True}},
        required=True,
    )


class ExcalidrawHistoryGetRes(CommonBasicResponse):
    data = fields.List(
        fields.Dict(
            example={
                "excalidraw_id": 3,
                "id": 42,
                "updated_at": "2022-10-05 02:41:34.317525",
                "user_id": 1,
                "value": {
                    "expires": "null",
                    "value": ":base64:hkjGR4TiFtcGX0krgEE+T5Dd6qxiWa1vsRdwGkqz",
                },
            }
        ),
        required=True,
    )


class ExcalidrawGetIDRes(CommonBasicResponse):
    data = fields.Dict(example={"excalidraw": 3})


class ExcalidrawGetSingleRes(CommonBasicResponse):
    data = fields.Dict(
        example={
            "created_at": TIMESAMPLE,
            "id": 1,
            "issue_ids": [1],
            "name": "name",
            "operator": {"id": 1, "login": "sysadmin", "name": "初始管理者"},
            "project": {"display": "display", "id": 1, "name": "name"},
            "updated_at": TIMESAMPLE,
            "url": EXCALIDRAW_SAMPLE_URL,
        }

    )
