from marshmallow import Schema, fields
from util import CommonBasicResponse


class CreateCheckmarxScan(Schema):
    cm_project_id = fields.Int(required=True, description="Checkmarx Project ID", example=1)
    repo_id = fields.Int(required=True, description="Gitlab Project ID", example=1)
    scan_id = fields.Int(required=True, description="Checkmarx Scan ID", example=1)
    branch = fields.Str(required=True, description="Git branch name", example="master")
    commit_id = fields.Str(required=True, description="Git Commit ID", example="df1e209")


class GetCheckmarxScansResponse(CommonBasicResponse):
    data = fields.Raw(
        example=[
            {
                "scan_id": 1,
                "branch": "master",
                "commit_id": "fde6a2c",
                "commit_url": "https://gitlab.dev7.iiidevops.org/root/project_name/-/commit/fde6a2c",
                "status": "Finished",
                "stats": {
                    "highSeverity": 0,
                    "mediumSeverity": 2,
                    "lowSeverity": 4,
                    "infoSeverity": 0,
                    "statisticsCalculationDate": "2022-02-11T15:50:00.8"
                },
                "run_at": "2022-02-11 07:36:36.319",
                "report_id": 3,
                "report_ready": True,
                "logs": None,
            }
        ]
    )


class GetCheckmarxProjectResponse(CommonBasicResponse):
    data = fields.Dict(example={"cm_project_id": 1})


class GetCheckmarxLatestScanResponse(CommonBasicResponse):
    data = fields.Dict(example={"scan_id": 1})


class GetCheckmarxScanStatisticsResponse(CommonBasicResponse):
    data = fields.Dict(example={
                    "highSeverity": 0,
                    "mediumSeverity": 2,
                    "lowSeverity": 4,
                    "infoSeverity": 0,
                    "statisticsCalculationDate": "2022-02-11T15:50:00.8"
                })


class GetCheckmarxScanStatusResponse(CommonBasicResponse):
    data = fields.Dict(example={"id": 7, "name": "Finished"})


class RegisterCheckmarxReportResponse(CommonBasicResponse):
    data = fields.Dict(example={"scanId": 1, "reportId": 3})


class GetCheckmarxReportStatusResponse(CommonBasicResponse):
    data = fields.Dict(example={"id": 1, "value": "string"})


class CancelCheckmarxScanResponse(Schema):
    status = fields.Int(required=True, example=200)
    status_code = fields.Str(required=True, example="success")
