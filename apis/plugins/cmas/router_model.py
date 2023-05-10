from marshmallow import Schema, fields
from util import CommonBasicResponse


class CMASTaskGetResponse(CommonBasicResponse):
    data = fields.Raw(
        example=[
            {
                "task_id": "ff76184b-5cdd-4614-92c8-e24eb5c36d03",
                "branch": "master",
                "commit_id": "fde6a2c",
                "commit_url": "https://gitlab.dev7.iiidevops.org/root/project_name/-/commit/fde6a2c",
                "run_at": "2022-02-11 07:36:36.319",
                "status": "SUCCESS",
                "stats": {
                    "OWASP": {"High": 0, "Medium": 1, "Low": 0, "summary": "1 OWASP/CVE vulnerability found"},
                    "MOEA": {"High": 0, "Medium": 0, "Low": 0, "summary": "MOEA rules all pass"}
                },
                "finished_at": "2022-02-11 07:36:36.319",
                "filenames": {"pdf": "72_app-debug-cht.pdf", "json": "72-en.json"},
                "upload_id": 1,
                "size": 433254,
                "sha256": "6BF03F073F74497D8DF3193D94ED7B1400484786B9573CCFD563756EF00A3F67",
                "a_mode": 24,
                "a_report_type": 3,
                "a_ert": 16,
                "logs": None,
            }
        ]
    )


class CMASTaskPost(Schema):
    task_id = fields.Str(required=True, description="CMAS task ID.", example="ff76184b-5cdd-4614-92c8-e24eb5c36d03")
    branch = fields.Str(required=True, description="Branch of Project Policy name", example="master")
    commit_id = fields.Str(required=True, description="Commit of Project", example="caef257")
    a_mode = fields.Int(required=True, description="", example=24)
    a_ert = fields.Int(required=True, description="", example=90)


class CMASTaskPostResponse(CommonBasicResponse):
    data = None


class CMASTaskPut(Schema):
    task_id = fields.Str(required=True, description="CMAS task ID.", example="policy_test")
    upload_id = fields.Int(required=False, description="", example=77)
    size = fields.Int(required=False, description="", example=1673430)
    sha256 = fields.Str(required=False, description="", example="6BF03F073F74497D8DF3193D94ED7B1400484786B9573CCFD563756EF00A3F67")
    stats = fields.Str(required=False, description="",
                       example='{"OWASP": {"High": 0, "Medium": 1, "Low": 0, "summary": "1 OWASP/CVE vulnerability found"}, "MOEA": {"High": 0, "Medium": 0, "Low": 0, "summary": "MOEA rules all pass"}}')
    scan_final_status = fields.Str(required=False, description="", example="SUCCESS")
    logs = fields.Str(required=False, description="", example="App-debug.apk not exists.")


class CMASTaskPutResponse(CommonBasicResponse):
    data = None


class CMASRemoteGetResponse(CommonBasicResponse):
    data = fields.Raw(
        example=[
            {
                "task_id": "ff76184b-5cdd-4614-92c8-e24eb5c36d03",
                "status": "SUCCESS",
                "Pdf-link-list": ["/M3AS-REST/api/report/pdf?filename=72_app-debug-cht.pdf"],
                "JSON-link": "/M3AS-REST/api/report/json?filename=72-en.json",
                "upload_id": 1,
                "sha256": "6BF03F073F74497D8DF3193D94ED7B1400484786B9573CCFD563756EF00A3F67",
            }
        ]
    )


class CMASSecretGetResponse(Schema):
    auth_key = fields.Str(required=True, example="0xe32e37e22f88c5dd0f1e424355ddf9f509972f94")
    cm_url = fields.Str(required=True, example="https://CMAS.dev7.iiidevops.org")
    a_report_type = fields.Str(required=True, example="pdf")
