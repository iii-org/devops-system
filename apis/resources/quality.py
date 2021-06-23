import json
import urllib.parse
from distutils.util import strtobool

import model
import util as util
import werkzeug
from flask_restful import Resource, reqparse
from model import db
from nexus import nx_get_project_plugin_relation

import resources.apiError as apiError
import resources.pipeline as pipeline
from resources import apiTest, sideex
from resources.redmine import redmine

from . import issue
from .gitlab import gitlab

paths = [{
    "software_name": "Postman",
    "path": "iiidevops/postman",
    "file_name_key": "collection"
}, {
    "software_name": "SideeX",
    "path": "iiidevops/sideex",
    "file_name_key": "sideex"
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


def qu_get_testplan(project_id, testplan_id, journals=0):
    journals = True if journals == 1 else False
    issue_info = issue.get_issue(testplan_id, journals=journals)
    test_plan_file_conn_list = qu_get_testplan_testfile_relate_list(project_id)
    issue_info["test_files"] = []
    for test_plan_file_conn in test_plan_file_conn_list:
        if issue_info['id'] == test_plan_file_conn['issue_id']:
            the_last_result ={}
            if test_plan_file_conn['software_name'] == "Postman":
                the_last_result = apiTest.get_the_last_result(project_id)
            elif test_plan_file_conn['software_name'] == "SideeX":
                the_last_result = sideex.sd_get_latest_test(project_id)
            test_plan_file_conn["the_last_test_result"] = the_last_result
            issue_info["test_files"].append(test_plan_file_conn)
    return issue_info


def qu_get_testfile_list(project_id):
    repository_id = nx_get_project_plugin_relation(
        nexus_project_id=project_id).git_repository_id
    out_list = []
    issues_info = qu_get_testplan_list(project_id)
    for path in paths:
        trees = gitlab.ql_get_collection(repository_id, path['path'])
        for tree in trees:
            if path["file_name_key"] in tree["name"] and tree["name"][
                    -5:] == ".json":
                path_file = f'{path["path"]}/{tree["name"]}'
                coll_json = json.loads(
                    gitlab.gl_get_file(repository_id, path_file))
                if path["file_name_key"] == "collection":
                    collection_obj = PostmanJSON(coll_json)
                    postman_info_obj = PostmanJSONInfo(collection_obj.info)
                    test_plans = []
                    rows = get_test_plans_from_params(project_id,
                                                      path["software_name"],
                                                      tree["name"])
                    for row in rows:
                        for issue_info in issues_info:
                            if row["issue_id"] == issue_info["id"]:
                                test_plans.append(issue_info)
                                break
                    the_last_result = apiTest.get_the_last_result(project_id, tree['name'].split('postman')[0])
                    out_list.append({
                        "software_name": path["software_name"],
                        "file_name": tree["name"],
                        "name": postman_info_obj.name,
                        "test_plans": test_plans,
                        "the_last_test_result": the_last_result
                    })
                elif path["file_name_key"] == "sideex":
                    sideex_obj = SideeXJSON(coll_json)
                    for suite_dict in sideex_obj.suites:
                        suite_obj = SideeXJSONSuite(suite_dict)
                        test_plans = []
                        rows = get_test_plans_from_params(
                            project_id, path["software_name"],
                            tree["name"])
                        for row in rows:
                            for issue_info in issues_info:
                                if row["issue_id"] == issue_info["id"]:
                                    test_plans.append(issue_info)
                                    break
                        the_last_result = sideex.sd_get_latest_test(project_id)
                        out_list.append({
                            "software_name":
                            path["software_name"],
                            "file_name":
                            tree["name"],
                            "name":
                            suite_obj.title,
                            "test_plans":
                            test_plans,
                            "the_last_test_result":
                            the_last_result
                        })
    return out_list


def get_test_plans_from_params(project_id, software_name, file_name):
    rows = model.IssueCollectionRelation.query.filter_by(
        project_id=project_id,
        software_name=software_name,
        file_name=file_name).all()
    return util.rows_to_list(rows)


def qu_create_testplan_testfile_relate(project_id, issue_id, software_name,
                                       file_name):
    row_num = model.IssueCollectionRelation.query.filter_by(
        project_id=project_id,
        issue_id=issue_id,
        software_name=software_name,
        file_name=file_name).count()
    if row_num == 0:
        new = model.IssueCollectionRelation(project_id=project_id,
                                            issue_id=issue_id,
                                            software_name=software_name,
                                            file_name=file_name)
        db.session.add(new)
        db.session.commit()
        return {"id": new.id}


def qu_put_testplan_testfiles_relate(project_id, issue_id, test_files):
    rows = model.IssueCollectionRelation.query.filter_by(
        project_id=project_id, issue_id=issue_id).all()
    for row in rows:
        db.session.delete(row)
        db.session.commit()
    for test_file in test_files:
        qu_create_testplan_testfile_relate(project_id, issue_id,
                                           test_file["software_name"],
                                           test_file["file_name"])


def qu_get_testplan_testfile_relate_list(project_id):
    rows = model.IssueCollectionRelation.query.filter_by(
        project_id=project_id).all()
    return util.rows_to_list(rows)


def qu_del_testplan_testfile_relate_list(project_id, item_id):
    row = model.IssueCollectionRelation.query.filter_by(id=item_id).first()
    if row is not None:
        db.session.delete(row)
        db.session.commit()


def qu_upload_testfile(project_id, file, software_name):
    repository_id = nx_get_project_plugin_relation(
        nexus_project_id=project_id).git_repository_id
    soft_path = next(path for path in paths
                     if path["software_name"].lower() == software_name.lower())
    trees = gitlab.ql_get_collection(repository_id, soft_path['path'])
    file_exist = next(
        (True for tree in trees if tree["name"] == file.filename), False)
    if file_exist:
        raise apiError.DevOpsError(
            409, f"Test File {file.filename} already exists in git repository")
    file_path = f"{soft_path['path']}/{file.filename}"
    next_run = pipeline.get_pipeline_next_run(repository_id)
    gitlab.gl_create_file(repository_id, file_path, file)
    pipeline.stop_and_delete_pipeline(repository_id, next_run)


def qu_del_testfile(project_id, software_name, test_file_name):
    rows = model.IssueCollectionRelation.query.filter_by(software_name=software_name.capitalize(),
        file_name=test_file_name).all()
    if len(rows) > 0:
        for row in rows:
            db.session.delete(row)
        db.session.commit()
    repository_id = nx_get_project_plugin_relation(
        nexus_project_id=project_id).git_repository_id
    for path in paths:
        if path["software_name"].lower() == software_name.lower() and \
        path["file_name_key"] in test_file_name and test_file_name[-5:] == ".json":
            url = urllib.parse.quote(f"{path['path']}/{test_file_name}",
                                     safe='')
            gitlab.gl_delete_file(
                repository_id, url, {
                    "commit_message":
                    f"Delete {software_name} test file {path['path']}/{test_file_name} from UI"
                })
            next_run = pipeline.get_pipeline_next_run(repository_id)
            pipeline.stop_and_delete_pipeline(repository_id, next_run)


class TestPlanList(Resource):
    def get(self, project_id):
        out = qu_get_testplan_list(project_id)
        return util.success(out)


class TestPlan(Resource):
    def get(self, project_id, testplan_id):
        parser = reqparse.RequestParser()
        parser.add_argument('journals', type=str)
        args = parser.parse_args()
        journals = None
        if args['journals'] is not None:
            journals = strtobool(args['journals'])
        out = qu_get_testplan(project_id, testplan_id, journals)
        return util.success(out)


class TestFileList(Resource):
    def get(self, project_id):
        out = qu_get_testfile_list(project_id)
        return util.success(out)


class TestFile(Resource):
    def post(self, project_id, software_name):
        parser = reqparse.RequestParser()
        parser.add_argument('test_file',
                            type=werkzeug.datastructures.FileStorage,
                            location='files',
                            required=True)
        args = parser.parse_args()
        qu_upload_testfile(project_id, args['test_file'], software_name)
        return util.success()

    def delete(self, project_id, software_name, test_file_name):
        out = qu_del_testfile(project_id, software_name, test_file_name)
        return util.success(out)


class TestPlanWithTestFile(Resource):
    def post(self, project_id):
        parser = reqparse.RequestParser()
        parser.add_argument('issue_id', type=int, required=True)
        parser.add_argument('software_name', type=str, required=True)
        parser.add_argument('file_name', type=str, required=True)
        args = parser.parse_args()
        out = qu_create_testplan_testfile_relate(project_id, args['issue_id'],
                                                 args['software_name'],
                                                 args['file_name'])
        return util.success(out)

    def put(self, project_id):
        parser = reqparse.RequestParser()
        parser.add_argument('issue_id', type=int, required=True)
        parser.add_argument('test_files',
                            type=list,
                            location='json',
                            required=True)
        args = parser.parse_args()
        qu_put_testplan_testfiles_relate(project_id, args['issue_id'],
                                         args['test_files'])
        return util.success()

    def get(self, project_id):
        out = qu_get_testplan_testfile_relate_list(project_id)
        return util.success(out)

    def delete(self, project_id, item_id):
        qu_del_testplan_testfile_relate_list(project_id, item_id)
        return util.success()
