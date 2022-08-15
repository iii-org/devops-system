from marshmallow import Schema, fields
from util import CommonBasicResponse



#################################### Schema ####################################


class SbomPostSchema(Schema):
    project_name = fields.Str(required=True, example="admin")
    branch = fields.Str(required=True, example="master")
    commit = fields.Str(required=True, example="#77777")
    sequence = fields.Int(example=1)


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


class SbomGetProjectID(Schema):
    project_id = fields.Int(example=3)


class SbomGetSbomID(Schema):
    sbom_id = fields.Int(example=3)

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


class SbomListResponse(Schema):
    per_page = fields.Int(required=False, description='Show how many items at one page', example="2")
    page = fields.Int(required=False, description='Page number', example="2")


class SbomGetRiskDetailRes(CommonBasicResponse):
    data = fields.List(fields.Dict(example={
            "description": "description",
            "id": "id",
            "name": "name",
            "severity": "severity",
            "version": "version",
            "versions": "versions"
        }), required=True)


class SbomGetSbonListRes(CommonBasicResponse):
    data = fields.Dict(example={
        "Sbom_list": [
            {
                "branch": "develop",
                "commit": "Z7777777",
                "created_at": "1970-01-01 00:00:00",
                "finished": "true",
                "finished_at": "1970-01-01 00:00:00",
                "id": 1,
                "logs": "Nice",
                "package_nums": 10,
                "project_id": 137,
                "scan_overview": {},
                "scan_status": "Running",
                "sequence": ""
            },
            {
                "branch": "develops",
                "commit": "a123445",
                "created_at": "1970-01-01 00:00:00",
                "finished": "true",
                "finished_at": "2022-08-10 14:26:56",
                "id": 4,
                "logs": "didn't find the file",
                "package_nums": 143,
                "project_id": 137,
                "scan_overview": {
                    "Critical": 7,
                    "High": 22,
                    "Low": 10,
                    "Medium": 22,
                    "Negligible": 82,
                    "Unknown": 4,
                    "total": 147
                },
                "scan_status": "Success",
                "sequence": 11
            }
        ],
        "page": {
            "current": 2,
            "next": 3,
            "pages": 3,
            "per_page": 2,
            "prev": 1,
            "total": 6
        }})


class SbomGetRiskOverviewRes(CommonBasicResponse):
    data = fields.Dict(example={
            "Critical": 7,
            "High": 22,
            "Low": 10,
            "Medium": 22,
            "Negligible": 82,
            "Unknown": 4,
            "total": 147
        }, required=True)