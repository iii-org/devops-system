from marshmallow import Schema, fields
from util import CommonBasicResponse


#################################### Schema ####################################


class WIEScanPostSchema(Schema):
    scan_id = fields.Str(required=True, example="1234")
    project_name = fields.Str(required=True, example="project_name")
    branch = fields.Str(required=True, example="master")
    commit_id = fields.Str(required=True, example="#77777")


class WIEScanGetSchema(Schema):
    limit = fields.Int(doc="limit", example=1)
    offset = fields.Int(doc="offset", example=1)


class WIEScanUpdateSchema(Schema):
    scan_id = fields.Str(example="1234")
    log = fields.Str(example="error log")
    status = fields.Str(example="Complete")
    finished = fields.Bool(example=True)
    finished_at = fields.DateTime(example="1970-01-01T00:00:00")


#################################### Response ####################################


class SbomGetRes(CommonBasicResponse):
    data = fields.List(
        fields.Dict(
            example={
                "branch": "master",
                "commit": "Z7777777",
                "commit_url": "https://",
                "created_at": "1970-01-01T00:00:00",
                "finished": True,
                "finished_at": "1970-01-01T00:00:00",
                "id": 1,
                "logs": "",
                "package_nums": 1,
                "project_id": 1,
                "scan_overview": {},
                "scan_status": "Finished",
            }
        )
    )


class SbomPostRes(Schema):
    id = fields.Int(required=True)


class SbomListResponse(Schema):
    per_page = fields.Int(required=False, description="Show how many items at one page", example="10")
    page = fields.Int(required=False, description="Page number", example="1")
    search = fields.Str(required=False, description="params", example="master")


class SbomDetailResponse(Schema):
    per_page = fields.Int(required=False, description="Show how many items at one page", example="10")
    page = fields.Int(required=False, description="Page number", example="1")
    sort = fields.Str(required=False, description="sort", example="versions")
    ascending = fields.Boolean(required=False, description="ascending", example=True)


class SbomGetSbomsResponse(Schema):
    latest = fields.Boolean()


class SbomGetFileList(CommonBasicResponse):
    data = fields.List(fields.Str())


class SbomGetProjectID(Schema):
    project_id = fields.Int(example=3)


class SbomGetSbomID(Schema):
    sbom_id = fields.Int(example=3)
