import mimetypes
from marshmallow import Schema, fields, validate
from util import CommonBasicResponse



################### Schema ######################

class UpdateFilesPostSchema(Schema):
    mimetype = fields.Str(validate=lambda x: "/" in x, required=True)
    file_extension = fields.Str(validate=lambda x: x.startswith("."), required=True)
    name = fields.Str()


class UpdateFilesPatchSchema(Schema):
    mimetype = fields.Str(validate=lambda x: "/" in x)
    file_extension = fields.Str(validate=lambda x: x.startswith("."))
    name = fields.Str()


class ReceiveMailFromNotificationSchema(Schema):
    receive = fields.Bool(required=True)

################### Response ######################


###### Module ######

class UpdateFileGetData(Schema):
    upload_file_types = fields.List(fields.Dict(
        example={
            "MIME Type": "audio/aac",
            "file extension": ".aac",
            "id": 1,
            "name": None
        },)
    )


###### API action ######

class UpdateFileGetResponse(CommonBasicResponse):
    data = fields.Nested(UpdateFileGetData)


class UpdateFilePostResponse(CommonBasicResponse):
    data = fields.Dict(example={
        "MIME Type": "test123/test123",
        "file extension": ".file",
        "id": 1,
        "name": "name"
    })

class GetUploadFileDistinctNameResponse(CommonBasicResponse):
    data = fields.List(fields.Str())


class ReceiveMailFromNotificationRepsonse(CommonBasicResponse):
    data = fields.Dict(example={
        "active": True,
        "id": 9,
        "name": "receive_mail_from_notification",
        "receive": True
    })