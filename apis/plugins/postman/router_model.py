from marshmallow import Schema, fields
from util import CommonBasicResponse

TIMESAMPLE = "1970-01-01 00:00:00.000000"


class ExportToPostmanGet(Schema):
    target = fields.Str(required=True, doc="target", example="")


class ExportToPostmanGetRes(CommonBasicResponse):
    data = fields.Dict(
        example={
            "info": {
                "name": "Project id 1",
                "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json",
            },
            "item": [],
        }
    )


class PostmanResultsGet(Schema):
    target = fields.Str(required=True, doc="target", example="")


class PostmanResultsGetRes(CommonBasicResponse):
    data = fields.List(
        fields.Dict(
            example={
                "id": 1,
                "branch": "master",
                "commit_id": "acdf059",
                "commit_url": "https://gitlab.dev7.iiidevops.org/root/project_name/-/commit/acdf059",
                "run_at": TIMESAMPLE,
                "logs": "",
                "status": "Finished",
                "success": 10,
                "failure": 1
            }
        ),
        required=True
    )


class PostmanReportGetRes(CommonBasicResponse):
    data = fields.Dict(
        required=True,
        example={
            "report": {
                "json_file": {
                    "PM 登入": {
                        "assertions": {
                            "total": 1,
                            "pending": 0,
                            "failed": 1
                        },
                        "executions": [
                            {
                                "name": "PM登入",
                                "method": "POST",
                                "path": "/user/login",
                                "assertions": [
                                    {
                                        "assertion": "JWT Token 檢查",
                                        "error_message": "Unexpected token '<' at 1:1\n<html>\n^"
                                    }
                                ]
                            }
                        ]
                    },
                    "AM 登入": {
                        "assertions": {
                            "total": 1,
                            "pending": 0,
                            "failed": 1
                        },
                        "executions": [
                            {
                                "name": "AM登入",
                                "method": "POST",
                                "path": "/user/login",
                                "assertions": [
                                    {
                                        "assertion": "JWT Token 檢查",
                                        "error_message": "Unexpected token '<' at 1:1\n<html>\n^"
                                    }
                                ]
                            }
                        ]
                    },
                    "RD 登入": {
                        "assertions": {
                            "total": 1,
                            "pending": 0,
                            "failed": 1
                        },
                        "executions": [
                            {
                                "name": "RD登入",
                                "method": "POST",
                                "path": "/user/login",
                                "assertions": [
                                    {
                                        "assertion": "JWT Token 檢查",
                                        "error_message": "Unexpected token '<' at 1:1\n<html>\n^"
                                    }
                                ]
                            }
                        ]
                    },
                    "RD 分支測試": {
                        "assertions": {
                            "total": 1,
                            "pending": 0,
                            "failed": 1
                        },
                        "executions": [
                            {
                                "name": "RD登入",
                                "method": "POST",
                                "path": "/user/login",
                                "assertions": [
                                    {
                                        "assertion": "JWT Token 檢查",
                                        "error_message": "Unexpected token '<' at 1:1\n<html>\n^"
                                    }
                                ]
                            },
                        ]
                    },
                    "完整關連測試": {
                        "assertions": {
                            "total": 12,
                            "pending": 0,
                            "failed": 12
                        },
                        "executions": [
                            {
                                "name": "PM登入",
                                "method": "POST",
                                "path": "/user/login",
                                "assertions": [
                                    {
                                        "assertion": "JWT Token 檢查",
                                        "error_message": "Unexpected token '<' at 1:1\n<html>\n^"
                                    }
                                ]
                            },
                        ]
                    }
                },
                "in_db": {
                    "assertions": {
                        "total": 0,
                        "pending": 0,
                        "failed": 0
                    },
                    "executions": []
                }
            },
            "branch": "master",
            "commit_id": "acdf059",
            "commit_url": "https://gitlab.dev7.iiidevops.org/root/project_name/-/commit/acdf059",
            "start_time": TIMESAMPLE,
            "logs": "",
            "status": "Finished",
        }
    )


class PostmanReportPut(Schema):
    scan_id = fields.Int(required=True, doc="scan id", example=1)
    project_id = fields.Int(required=True, doc="Project", example=1)
    total = fields.Int(required=True, doc="total", example=12)
    fail = fields.Int(required=True, doc="fail", example=1)
    report = fields.Str(required=True, doc="report", example="")
    status = fields.Str(required=False, doc="status", example="")
    logs = fields.Str(required=False, doc="logs", example="")


class PostmanReportPutRes(CommonBasicResponse):
    data = None


class PostmanReportPost(Schema):
    project_id = fields.Int(required=True, doc="Project", example=1)
    branch = fields.Str(required=True, doc="branch", example="")
    commit_id = fields.Str(required=True, doc="commit id", example="")
    status = fields.Str(required=False, doc="status", example="")
    logs = fields.Str(required=False, doc="logs", example="")


class PostmanReportPostRes(CommonBasicResponse):
    data = fields.Dict(required=True, example={"scan_id": 1})
