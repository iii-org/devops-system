from flask_restful import Resource
import json

from nexus import nx_get_project_plugin_relation
from .gitlab import gitlab
from resources.redmine import redmine
from . import issue
import util as util

paths = [{
    "software_name": "Postman",
    "path": "iiidevops/postman",
    "file_name_key": "postman_collection.json"
}, {
    "software_name": "SideeX",
    "path": "iiidevops/sideex",
    "file_name_key": "sideex.json"
}]


class PostmanJSON:
    def __init__(self, input_dict):
        self.info = input_dict.get("info")
        self.item = input_dict.get("item")


class PostmanJSONInfo:
    def __init__(self, info_dict):
        self.name = info_dict.get("name")


class PostmanJSONItem:
    def __init__(self, item_dict):
        self.name = item_dict.get("name")


class SideeXJSON:
    def __init__(self, input_dict):
        self.suites = input_dict.get("suites")


class SideeXJSONSuite:
    def __init__(self, input_dict):
        self.title = input_dict.get("title")
        self.cases = input_dict.get("cases")


class SideeXJSONCase:
    def __init__(self, input_dict):
        self.title = input_dict.get("title")
        self.records = input_dict.get("records")


class SideeXJSONRecord:
    def __init__(self, record_dict):
        self.name = record_dict.get("name")


def qu_get_testplan_list(project_id):
    testplan = "Test Plan"
    testplan_id = -1
    for tracker in redmine.rm_get_trackers()["trackers"]:
        if tracker["name"] == testplan:
            testplan_id = tracker["id"]
    if testplan_id != -1:
        args= {"tracker_id": testplan_id}
        issues = issue.get_issue_by_project(project_id, args)
        return issues


def qu_get_collection_list(project_id):
    repository_id = nx_get_project_plugin_relation(nexus_project_id=project_id).git_repository_id
    out_dict = {}
    for path in paths:
        out_dict[path["software_name"]] = []
        trees = gitlab.ql_get_collection(repository_id, path['path'])
        for tree in trees:
            if path["file_name_key"] in tree["name"]:
                path_file = f'{path["path"]}/{tree["name"]}'
                coll_json = json.loads(
                    gitlab.gl_get_file(repository_id, path_file))
                if path["file_name_key"] == "postman_collection.json":
                    collection_obj = PostmanJSON(coll_json)
                    postman_info_obj = PostmanJSONInfo(collection_obj.info)
                    items = []
                    for item in collection_obj.item:
                        postman_item_obj = PostmanJSONItem(item)
                        items.append({"name": postman_item_obj.name})
                    out_dict[path["software_name"]].append({
                        "file_name":
                        tree["name"],
                        "name":
                        postman_info_obj.name,
                        "items":
                        items
                    })
                elif path["file_name_key"] == "sideex.json":
                    sideex_obj = SideeXJSON(coll_json)
                    for suite_dict in sideex_obj.suites:
                        suite_obj = SideeXJSONSuite(suite_dict)
                        for case_dict in suite_obj.cases:
                            records = []
                            case_obj = SideeXJSONCase(case_dict)
                            for record_dict in case_obj.records:
                                record_obj = SideeXJSONRecord(record_dict)
                                records.append({"name": record_obj.name})
                            out_dict[path["software_name"]].append({
                                "file_name":
                                tree["name"],
                                "parent_name":
                                suite_obj.title,
                                "name":
                                case_obj.title,
                                "items":
                                records
                            })
    return out_dict


class TestPlanList(Resource):
    def get(self, project_id):
        out = qu_get_testplan_list(project_id)
        return util.success(out)


class CollectionList(Resource):
    def get(self, project_id):
        out = qu_get_collection_list(project_id)
        return util.success(out)