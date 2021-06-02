from flask_restful import Resource, reqparse
import json

from nexus import nx_get_project_plugin_relation
from .gitlab import gitlab
from resources.redmine import redmine
from resources import apiTest, sideex
from . import issue
import util as util
import model
from model import db

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
        args = {"tracker_id": testplan_id}
        issue_infos = issue.get_issue_by_project(project_id, args)
        test_plan_file_conn_list = qu_get_testplan_testfile_relate_list(
            project_id)
        for issue_info in issue_infos:
            issue_info["test_files"] = []
            for test_plan_file_conn in test_plan_file_conn_list:
                if issue_info['id'] == test_plan_file_conn['issue_id']:
                    issue_info["test_files"].append(test_plan_file_conn)
        return issue_infos


def qu_get_testfile_list(project_id):
    repository_id = nx_get_project_plugin_relation(
        nexus_project_id=project_id).git_repository_id
    out_list = []
    issues_info = qu_get_testplan_list(project_id)
    postman_results = apiTest.list_results(project_id)
    sideex_results = sideex.sd_get_tests(project_id)
    for path in paths:
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
                    test_plans = []
                    rows = get_test_plans_from_params(project_id,
                                                      path["software_name"],
                                                      tree["name"],
                                                      postman_info_obj.name)
                    for row in rows:
                        for issue_info in issues_info:
                            if row["issue_id"] == issue_info["id"]:
                                test_plans.append(issue_info)
                                break
                    the_last_result = None
                    if len(postman_results) != 0:
                        the_last_result = postman_results[0]
                    out_list.append({
                        "software_name": path["software_name"],
                        "file_name": tree["name"],
                        "name": postman_info_obj.name,
                        "items": items,
                        "test_plans": test_plans,
                        "the_last_test_result": the_last_result
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
                            test_plans = []
                            rows = get_test_plans_from_params(
                                project_id, path["software_name"],
                                tree["name"], case_obj.title)
                            for row in rows:
                                for issue_info in issues_info:
                                    if row["issue_id"] == issue_info["id"]:
                                        test_plans.append(issue_info)
                                        break
                            the_last_result = None
                            if len(sideex_results) != 0:
                                the_last_result = sideex_results[0]
                            out_list.append({
                                "software_name":
                                path["software_name"],
                                "file_name":
                                tree["name"],
                                "parent_name":
                                suite_obj.title,
                                "name":
                                case_obj.title,
                                "items":
                                records,
                                "test_plans":
                                test_plans,
                                "the_last_test_result":
                                the_last_result
                            })
    return out_list


def get_test_plans_from_params(project_id, software_name, file_name,
                               plan_name):
    rows = model.IssueCollectionRelation.query.filter_by(
        project_id=project_id,
        software_name=software_name,
        file_name=file_name,
        plan_name=plan_name).all()
    return util.rows_to_list(rows)


def qu_create_testplan_testfile_relate(project_id, issue_id, software_name,
                                       file_name, plan_name):
    row_num = model.IssueCollectionRelation.query.filter_by(
        project_id=project_id,
        issue_id=issue_id,
        software_name=software_name,
        file_name=file_name,
        plan_name=plan_name).count()
    if row_num == 0:
        new = model.IssueCollectionRelation(project_id=project_id,
                                            issue_id=issue_id,
                                            software_name=software_name,
                                            file_name=file_name,
                                            plan_name=plan_name)
        db.session.add(new)
        db.session.commit()
        return {"id": new.id}


def qu_get_testplan_testfile_relate_list(project_id):
    rows = model.IssueCollectionRelation.query.filter_by(
        project_id=project_id).all()
    return util.rows_to_list(rows)


def qu_del_testplan_testfile_relate_list(project_id, item_id):
    row = model.IssueCollectionRelation.query.filter_by(id=item_id).first()
    if row is not None:
        db.session.delete(row)
        db.session.commit()


class TestPlanList(Resource):
    def get(self, project_id):
        out = qu_get_testplan_list(project_id)
        return util.success(out)


class TestFileList(Resource):
    def get(self, project_id):
        out = qu_get_testfile_list(project_id)
        return util.success(out)


class TestPlanWithTestFile(Resource):
    def post(self, project_id):
        parser = reqparse.RequestParser()
        parser.add_argument('issue_id', type=int, required=True)
        parser.add_argument('software_name', type=str, required=True)
        parser.add_argument('file_name', type=str, required=True)
        parser.add_argument('plan_name', type=str, required=True)
        args = parser.parse_args()
        out = qu_create_testplan_testfile_relate(project_id, args['issue_id'],
                                                 args['software_name'],
                                                 args['file_name'],
                                                 args['plan_name'])
        return util.success(out)

    def get(self, project_id):
        out = qu_get_testplan_testfile_relate_list(project_id)
        return util.success(out)

    def delete(self, project_id, item_id):
        qu_del_testplan_testfile_relate_list(project_id, item_id)
        return util.success()