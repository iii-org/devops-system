from marshmallow import Schema, fields
from util import CommonBasicResponse


#################################### Schema ####################################


class GitlabPostProjectBranchesSch(Schema):
    branch = fields.Str(doc="branch", example="new branch name")
    ref = fields.Str(doc="ref", example="branch name")


#################################### Response ####################################


class GitlabGetProjectBranchesRes(CommonBasicResponse):
    data = fields.Dict(
        example={
            "branch_list": [
                {
                    "name": "allow-nothing",
                    "last_commit_message": "UI 編輯 .rancher-pipeline.yaml 啟用 checkmarx.",
                    "last_commit_time": "2022-11-14T03:37:36.000+00:00",
                    "short_id": "6191154",
                    "id": "6191154fb259a711e3b2172ceb8eb6a230bbb515",
                    "commit_url": "http://gitlab-dev.iiidevops.org/root/ui-create-case/-/commit/6191154f",
                },
                {
                    "name": "master",
                    "last_commit_message": "UI 編輯 .rancher-pipeline.yaml 啟用 checkmarx.",
                    "last_commit_time": "2022-11-14T03:37:39.000+00:00",
                    "short_id": "7297500",
                    "id": "7297500ee16248e9d837e11046f80418a893ef7d",
                    "commit_url": "http://gitlab-dev.iiidevops.org/root/ui-create-case/-/commit/7297500e",
                },
            ]
        }
    )


class GitlabPostProjectBranchesRes(CommonBasicResponse):
    data = fields.Dict(
        example={
            "name": "postman_test",
            "commit": {
                "id": "9f5bc8fcf41cba25be0e27b4aa0c0759119aeba5",
                "short_id": "9f5bc8fc",
                "created_at": "2020-10-21T07:25:18.000+00:00",
                "parent_ids": ["7c53e711f281a2d30323d452f6f559f15b69f464"],
                "title": "add .rancher-pipeline.yml",
                "message": "add .rancher-pipeline.yml",
                "author_name": "admin",
                "author_email": "admin@example.com",
                "authored_date": "2020-10-21T07:25:18.000+00:00",
                "committer_name": "Administrator",
                "committer_email": "admin@example.com",
                "committed_date": "2020-10-21T07:25:18.000+00:00",
                "web_url": "http://10.50.1.53/root/newtest/-/commit/9f5bc8fcf41cba25be0e27b4aa0c0759119aeba5",
            },
            "merged": False,
            "protected": False,
            "developers_can_push": False,
            "developers_can_merge": False,
            "can_push": True,
            "default": False,
        }
    )


class GitlabGetProjectBranchRes(CommonBasicResponse):
    data = fields.Dict(
        example={
            "name": "master",
            "commit": {
                "id": "7297500ee16248e9d837e11046f80418a893ef7d",
                "short_id": "7297500e",
                "created_at": "2022-11-14T03:37:39.000+00:00",
                "parent_ids": ["1037ecf258c27ca7a2583c5b458dbed2e53f8252"],
                "title": "UI 編輯 .rancher-pipeline.yaml 啟用 checkmarx.",
                "message": "UI 編輯 .rancher-pipeline.yaml 啟用 checkmarx.",
                "author_name": "iiidevops",
                "author_email": "system@iiidevops.org.tw",
                "authored_date": "2022-11-14T03:37:39.000+00:00",
                "committer_name": "Administrator",
                "committer_email": "admin@example.com",
                "committed_date": "2022-11-14T03:37:39.000+00:00",
                "web_url": "http://gitlab-dev.iiidevops.org/root/ui-create-case/-/commit/7297500ee16248e9d837e11046f80418a893ef7d",
            },
            "merged": False,
            "protected": True,
            "developers_can_push": True,
            "developers_can_merge": True,
            "can_push": True,
            "default": True,
        }
    )


class GitGetProjectRepositoriesRes(CommonBasicResponse):
    data = fields.Dict(
        example={
            "file_list": [
                {
                    "id": "c2ec416b4b0031972b933ac8e39597d8318d84ae",
                    "name": ".rancher-pipeline.yml",
                    "type": "blob",
                    "path": ".rancher-pipeline.yml",
                    "mode": "100644",
                },
                {
                    "id": "e69de29bb2d1d6434b8b29ae775ad8c2e48c5391",
                    "name": "file0721",
                    "type": "blob",
                    "path": "file0721",
                    "mode": "100644",
                },
                {
                    "id": "d5ca058c35040faa0ec459ffe82d21a6e0e3450b",
                    "name": "file0730",
                    "type": "blob",
                    "path": "file0730",
                    "mode": "100644",
                },
            ]
        }
    )
