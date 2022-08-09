from marshmallow import Schema, fields
from util import CommonBasicResponse



#################################### Schema ####################################


class SbomPostSchema(Schema):
    project_name = fields.Str(required=True, example="admin")
    branch = fields.Str(required=True, example="master")
    commit = fields.Str(required=True, example="#77777")


class SbomPatchSchema(Schema):
    scan_status = fields.Str(example="Finished")
    package_nums = fields.Int(example=1)
    scan_overview = fields.Dict(example={
        "severity": "Critical", 
        "size": "53.92MB", 
        "fixable": 4, 
        "total": 67, 
        "Critical": 1, 
        "High": 2, 
        "Low": 6, 
        "Medium": 8, 
        "Negligible": 40, 
        "Unknown": 10
    })
    finished = fields.Boolean(example=True)
    finished_at = fields.Str(example="1970-01-01T00:00:00")
    logs = fields.Str(example="logs")


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
                "scan_status": "Finished"
            }
        )
    )

class SbomPostRes(Schema):
    id = fields.Int(required=True)

