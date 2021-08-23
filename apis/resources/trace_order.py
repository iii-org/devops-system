from flask_jwt_extended import jwt_required
from flask_restful import Resource, reqparse

import model
import resources.project as project
import resources.issue as issue

from resources.issue import NexusIssue
import util as util
from model import db, TraceOrder
import resources.apiError as apiError 
from resources.apiError import DevOpsError
from sqlalchemy.orm.exc import NoResultFound
from accessories import redmine_lib
from resources.redmine import redmine
from resources.quality import qu_get_testfile_by_testplan
'''
order_mapping
"Epic": 需求規格
"Audit": 合規需求
"Feature": 功能設計
"Bug": 程式錯誤
"Issue": 議題
"Change Request": 變更需求
"Risk": 風險管理
"Test Plan": 測試計畫
"Fail Management": 異常管理
'''

def validate_order_value(order):
    validate_order_list = [
        {
            "condition": not all(x in ['Epic', 'Audit', 'Feature', 'Bug', 'Issue', 'Change Request', 'Risk', 'Test Plan', 'Fail Management'] for x in order), 
            "log": "Order's elements must be in ['Epic', 'Audit', 'Feature', 'Bug', 'Issue', 'Change Request', 'Risk', 'Test Plan', 'Fail Management']",
        },
        {"condition": len(order) != len(set(order)), "log": "Elements must not be duplicated"},
        {"condition": not len(order) <= 5, "log": "Numbers of order's elements must be in range [0, 5]"},
    ]
    for validate_order in validate_order_list:
        if validate_order["condition"]:
            raise DevOpsError(400, validate_order["log"],
                              error=apiError.argument_error('order'))

def handle_default_value(project_id):
    for trace_order in TraceOrder.query.filter_by(project_id=project_id).all():
        if trace_order.default:
            trace_order.default = False
            db.session.commit()


def get_trace_order_by_project(project_id):
    if util.is_dummy_project(project_id):
        return []
    try:
        project.get_plan_project_id(project_id)
    except NoResultFound:
        raise DevOpsError(404, "Error while getting trace_orders.",
                          error=apiError.project_not_found(project_id))
    rows = TraceOrder.query.filter_by(project_id=project_id).all()
    return {"trace_order_list": [
        {
            "id": row.id,
            "name": row.name,
            "order": row.order,
            "default": row.default
        } for row in rows
    ]}

def create_trace_order_by_project(project_id, args):
    order = args["order"]
    validate_order_value(order)
    default = args["default"]

    if default:
        handle_default_value(project_id)

    new = TraceOrder(
        name=args["name"],
        order=order,
        project_id=project_id,
        default=default,
    )
    db.session.add(new)
    db.session.commit()
    return {"trace_order_id": new.id}

def update_trace_order(trace_order_id, args):
    trace_order = model.TraceOrder.query.get(trace_order_id)

    order = args.get("order")
    if order is not None:
        validate_order_value(order)
        trace_order.order = order

    default = args.get("default")
    if default is not None:
        if default:
            handle_default_value(trace_order.project_id)
        else:
            if trace_order.default:
                raise DevOpsError(400, "Must not change to False, this trace_order is the only true in this project",
                                  error=apiError.argument_error('default'))
        trace_order.default = default

    trace_order.name = args.get("name", trace_order.name)
    db.session.commit()


class TraceList:
    def __init__(self, plan_project_id, trace_order, issues):
        self.pj_id = plan_project_id
        self.result = []
        self.trace_order = trace_order
        self.__check_test_plan_exist()
        self.issues = issues
        self.not_alone_mid_id_list = []
        self.not_alone_final_id_list = []
        self.mention_id = []

    def __check_test_plan_exist(self):
        for index, track in enumerate(self.trace_order):
            if track == "Test Plan":
                self.test_plan_index = index
            else:
                self.test_plan_index = None

    def __get_family(self, issue_id):
        redmine_issue = redmine_lib.redmine.issue.get(issue_id, include=['children', 'relations'])
        family = issue.get_issue_family(redmine_issue)
        return family

    def __remove_id(self, id):
        if id in self.tracker_issue_list:
            self.tracker_issue_list.remove(id)

    def __combine_family(self, family, index):
        if family.get("parent") is not None:
            parent = [family["parent"]]
        else:
            parent = []       
        familys = parent + family.get("children", []) + family.get("relations", [])
        trace_order = self.trace_order.copy()
        trace_order.pop(index)
        return [family for family in familys if family["tracker"]["name"] in trace_order]

    def __append_result(self, alone_issue_mapping):
        if alone_issue_mapping not in self.result:
            self.result.append(alone_issue_mapping)

    def __get_test_plan_content(self, test_plan_id):
        mapping = {"test_file": [], "test_result": []}
        test_files = qu_get_testfile_by_testplan(self.pj_id, test_plan_id)
        if test_files == []:
            return {}
        else:
            for test_file in test_files:
                mapping["test_file"].append({
                    k: test_file[k] for k in [
                        "software_name", "file_name"]
                })
                test_result = {
                    k: test_file[k] for k in [
                        "branch", "commit_id"]
                }
                if test_file["the_last_test_result"].get("result") is not None:
                    test_result.update({
                        "result": test_file["the_last_test_result"]["result"]
                    })
                else:
                    test_result.update({
                        "result": {k: test_file["the_last_test_result"][k] for k in ["success", "failure"]}
                    })
                mapping["test_result"].append(test_result)
        return mapping

    def __generate_alon_issue_mapping(self, track, id):
        alone_issue_mapping = {track: self.issues[id]}
        if track == "Test Plan":
            alone_issue_mapping.update(self.__get_test_plan_content(id))
        return alone_issue_mapping

    def generate_output(self, id, family, index):
        index_list = [i for i in range(len(self.trace_order)) if i != index]
        alone_issue_mapping = self.__generate_alon_issue_mapping(self.trace_order[index], id)
        familys = self.__combine_family(family, index)
        if familys == []:
            self.__append_result(alone_issue_mapping)
        else:
            for family in familys:
                for index in index_list:
                    if family["tracker"]["name"] == self.trace_order[index]:
                        if index == self.test_plan_index:
                            alone_issue_mapping.update(self.__get_test_plan_content(family["id"]))
                        alone_issue_mapping.update({self.trace_order[index]: self.issues[family["id"]]})     
                        self.__append_result(alone_issue_mapping)

    def generate_head_mapping(self):
        mapping = {}
        self.first_track = self.trace_order[0]  
        self.secound_track = self.trace_order[1] 
        first_tracker_issue_list = [id for id, issue in self.issues.items() if issue["tracker"] == self.first_track]

        for id in first_tracker_issue_list:
            value = {"same_level": [], "next_level": []}
            family = self.__get_family(id)
            for relation_type in ["relations", "children"]:
                if family.get(relation_type) is not None:
                    for item in family[relation_type]:
                        if item["tracker"]["name"] == self.first_track:
                            value["same_level"].append(item["id"])
                        if item["tracker"]["name"] == self.secound_track:
                            value["next_level"].append(item["id"])              
            if value["next_level"] == []:
                if value["same_level"] == []:
                    self.generate_output(id, family, 0)
                continue
            mapping[id] = value

        not_alone_mid_id_list = []
        for _, value in mapping.items():
            not_alone_mid_id_list += value.get("next_level")
        self.not_alone_mid_id_list = not_alone_mid_id_list

    def generate_middle_mapping(self):          
        self.first_track = self.trace_order[1]
        self.secound_track = self.trace_order[2]
        self.tracker_issue_list = [id for id, issue in self.issues.items() if issue["tracker"] == self.first_track and id not in self.not_alone_mid_id_list]
        for id in self.not_alone_mid_id_list:
            self.__check_middle_id(id)
        for id in self.tracker_issue_list:
            self.generate_output(id, self.__get_family(id), 1)

        for id in [id for id, issue in self.issues.items() if issue["tracker"] == self.first_track and id not in self.tracker_issue_list]:
            family = self.__get_family(id)
            for relation_type in ["relations", "children"]:
                if family.get(relation_type) is not None:
                    for item in family[relation_type]:
                        if item["tracker"]["name"] == self.secound_track:
                            self.not_alone_final_id_list.append(item["id"])

        self.not_alone_final_id_list = list(set(self.not_alone_final_id_list))

    def __check_middle_id(self, id):
        self.mention_id.append(id)
        value = {"same_level": [], "next_level": []}
        family = self.__get_family(id)
        for relation_type in ["relations", "children"]:
            if family.get(relation_type) is not None:
                for item in family[relation_type]:
                    if item["tracker"]["name"] == self.first_track:
                        value["same_level"].append(item["id"])
                    if item["tracker"]["name"] == self.secound_track:
                        value["next_level"].append(item["id"])
        if value["same_level"] != []:
            check_complete = True
            for same_id in value["same_level"]:
                if same_id in self.mention_id:
                    continue
                else:
                    check_complete = False
                    if same_id in self.not_alone_mid_id_list:
                        continue
                    if same_id in self.tracker_issue_list:
                        self.__remove_id(same_id)
                        self.__check_middle_id(same_id)  
        if check_complete:
            if value["next_level"] == []:
                self.generate_output(id, family, 1)
            else:
                self.__remove_id(id)
                self.not_alone_final_id_list += value.get("next_level")

    def generate_final_mapping(self):
        self.first_track = self.trace_order[-1]
        self.tracker_issue_list = [id for id, issue in self.issues.items() if issue["tracker"] == self.first_track and id not in self.not_alone_final_id_list]
        for id in self.not_alone_final_id_list:
            self.__check_final_id(id)
        for id in self.tracker_issue_list:
            self.generate_output(id, self.__get_family(id), 2)

    def __check_final_id(self, id):
        value = {"same_level": []}
        family = self.__get_family(id)
        for relation_type in ["relations", "children"]:
            if family.get(relation_type) is not None:
                for item in family[relation_type]:
                    if item["tracker"]["name"] == self.first_track:
                        value["same_level"].append(item["id"])
        if value["same_level"] != []:
            for same_id in value["same_level"]:
                if same_id not in self.not_alone_final_id_list:
                    self.__remove_id(same_id)
                    if id not in self.mention_id:
                        self.mention_id.append(id)
                        self.__check_final_id(same_id)

    def execute_trace_order(self):
        self.generate_head_mapping()
        self.generate_middle_mapping()
        self.generate_final_mapping()
        return self.result

# --------------------- Resources ---------------------
class ProjectTraceOrder(Resource):
    def get(self, project_id):
        return util.success(get_trace_order_by_project(project_id))

    @jwt_required
    def post(self, project_id):
        parser = reqparse.RequestParser()
        parser.add_argument('name', type=str, required=True)
        parser.add_argument('order', type=str, action='append', required=True)
        parser.add_argument('default', type=bool, required=True)
        args = parser.parse_args()
        return util.success(create_trace_order_by_project(project_id, args))

    # Execute_trade_order
    @jwt_required
    def patch(self, project_id): 
        trace_order = TraceOrder.query.filter_by(
            project_id=project_id, 
            default=True, 
        ).one()
        plan_project_id = project.get_plan_project_id(project_id)

        trackers = redmine_lib.redmine.tracker.all()
        issues = redmine_lib.redmine.issue.filter(
            project_id=plan_project_id,
            tracker_id="|".join([str(tracker.id) for tracker in trackers if tracker.name in trace_order.order]),
            status_id="*"
        )
        issues = {issue.id: {
            "id": issue.id,
            "name": issue.subject, 
            "tracker": issue.tracker.name, 
            "status": {"id": issue.status.id, "name": issue.status.name}, 
        } for issue in issues}

        return util.success(TraceList(plan_project_id, trace_order.order, issues).execute_trace_order())

class SingleTraceOrder(Resource):
    @jwt_required
    def patch(self, trace_order_id):
        parser = reqparse.RequestParser()
        parser.add_argument('name', type=str)
        parser.add_argument('order', type=str, action='append')
        parser.add_argument('default', type=bool)
        args = parser.parse_args()
        args = {k: v for k, v in args.items() if v is not None}
        return util.success(update_trace_order(trace_order_id, args))

    @jwt_required
    def delete(self, trace_order_id):
        trace_order = TraceOrder.query.filter_by(id=trace_order_id).one()
        db.session.delete(trace_order)
        db.session.commit()
        return util.success()
