from marshmallow import Schema, fields
from util import CommonBasicResponse



#################################### Schema ####################################


class SideexPostSch(Schema):
    project_name = fields.Str(example='ui-create')
    branch = fields.Str(example='master')
    commit_id = fields.Str(example='445af71')
    

class SideexPutSch(Schema):
    test_id = fields.Int(example=661, required=True)
    result = fields.Str(example={"suitesPassed":1,"suitesTotal":1,"casesPassed":1,"casesTotal":1,"suites":{"django-sqlite-todo":{"passed":1,"total":1}}})
    report = fields.Str(example="<html>")


class SideexGetVariableSch(Schema):
    filename = fields.Str(required=False, example="sideex.json")


class SideexPutVariableSch(Schema):
    var = fields.List(fields.Dict(), required=False, example=[
        {"name": "abc", "type": "int", "value": [2, 3, 3, 10, 123]},
        {"name": "def", "type": "str", "value": ["abc", "xyz", "a54"]},
        {"name": "xx2", "type": "str", "value": ["12", "ab", "56", "99"]}
      ])
    rule = fields.List(fields.Str(), required=False, example=[
        "IF [def] = 'abc' THEN [abc] <= 5;", "IF [xx2] = 'ab' THEN [abc] >= 5;"])


#################################### Response ####################################


class SideexPostRes(CommonBasicResponse):
    data = fields.Dict(example={
        "test_id": 661
    })


class SideexGetTestResultRes(CommonBasicResponse):
    data = fields.List(fields.Dict(example={
            "branch": "master",
            "commit_id": "dea7c1c2",
            "finished_at": None,
            "id": 46,
            "project_name": "ui-create-case",
            "has_report": False,
            "result": "None",
            "run_at": "2021-09-10 09:57:37.283586",
            "status": "Aborted",
            "issue_link": "http://gitlab-dev.iiidevops.org/root/ui-create-case/-/commit/dea7c1c2"
        }))


class SideexGetVariableRes(CommonBasicResponse):
    data = fields.Dict(example={
        "rule": [
            "IF [def] = 'abc' THEN [abc] <= 5;",
            "IF [xx2] = 'ab' THEN [abc] >= 5;"
        ],
        "var": [
            {
                "name": "abc",
                "type": "int",
                "value": [
                    2,
                    3,
                    3,
                    10,
                    123
                ]
            },
            {
                "name": "def",
                "type": "str",
                "value": [
                    "abc",
                    "xyz",
                    "a54"
                ]
            }
        ]
    })


class SideexGenerateResultRes(CommonBasicResponse):
    data = fields.List(fields.Dict(
        example=[
        {
            "abc": "x5",
            "def": "xyz",
            "xx2": "56"
        },
        {
            "abc": "x5",
            "def": "測試",
            "xx2": "99"
        }])
    )


class SideexPictStatusRes(CommonBasicResponse):
    data = fields.Dict(example={
        "finish": True,
        "branch": "master",
        "commit_id": "6cdbe6b"
    })


class SideexCheckResultFileRes(CommonBasicResponse):
    data = fields.Dict(example={
        "result_file_exist": True
    })


class SideexGetReportRes(CommonBasicResponse):
    data = fields.Str(example="<html></html>")