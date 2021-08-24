from flask_jwt_extended import jwt_required
from flask_restful import Resource, reqparse

import config
import model
import resources.project as project
import resources.issue as issue

from copy import deepcopy
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

def trace_order_is_allow_to_change(project_id):
    allow = False
    for trace_order in TraceOrder.query.filter_by(project_id=project_id).all():
        if trace_order.default:
            allow = True
    return allow            

def get_trace_order_by_project(project_id):
    if util.is_dummy_project(project_id):
        return []
    try:
        project.get_plan_project_id(project_id)
    except NoResultFound:
        raise DevOpsError(404, "Error while getting trace_orders.",
                          error=apiError.project_not_found(project_id))

    results = []
    has_default = False
    rows = TraceOrder.query.filter_by(project_id=project_id).order_by(TraceOrder.id).all()
    for row in rows:
        if row.default:
            has_default = True
        results.append({
            "id": row.id,
            "name": row.name,
            "order": row.order,
            "default": row.default
        })
    default_trace_order = config.get("DEFAULT_TRACE_ORDER")
    return [{
        "id": -1,
        "name": "標準檢測模組",
        "order": default_trace_order,
        "default": has_default is False
    }] + results

def create_trace_order_by_project(args):
    project_id = args["project_id"]
    num = TraceOrder.query.filter_by(project_id=project_id).count()
    if not num < 4:
        raise DevOpsError(400, "Maximum number of trace_order in a project is 5.",
                          error=apiError.no_detail())

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
    default = args.get("default")

    if trace_order_id == -1:
        project = args.get("project_id")
        if project is None:
            raise DevOpsError(400, "Must provide project_id when trace_order_id is -1",
                              error=apiError.argument_error('project_id')) 
        if default:
            handle_default_value(project)
        else:
            if not trace_order_is_allow_to_change(project):
                raise DevOpsError(400, "Not allow to change default value because the trace_order default is the only True",
                                  error=apiError.no_detail()) 
        return 

    trace_order = model.TraceOrder.query.get(trace_order_id)
    if trace_order is None:
        raise DevOpsError(400, "The trace_order not exist.",
                          error=apiError.resource_not_found())

    order = args.get("order")
    if order is not None:
        validate_order_value(order)
        trace_order.order = order

    default = args.get("default")
    if default is not None:
        if default:
            handle_default_value(trace_order.project_id)
        trace_order.default = default

    trace_order.name = args.get("name", trace_order.name)
    db.session.commit()

def delete_trace_order(trace_order_id):
    trace_order = TraceOrder.query.filter_by(id=trace_order_id).one()
    if trace_order.default:
        raise DevOpsError(400, "Not allow to delete the trace_order because this is default",
                          error=apiError.no_detail()) 
    db.session.delete(trace_order)
    db.session.commit()

class TraceList:
    def __init__(self, plan_project_id, trace_order, issues):
        self.pj_id = plan_project_id
        self.trace_order = trace_order
        self.issues = issues
        self.__check_test_plan_exist()
        self.result = []
        self.not_alone_id_mapping = {track: [] for track in trace_order[1:]}
        self.mention_id = []

    def __check_test_plan_exist(self):
        for index, track in enumerate(self.trace_order):
            if track == "Test Plan":
                self.test_plan_index = index
            else:
                self.test_plan_index = None

    def __get_family(self, issue_id):
        redmine_issue = redmine_lib.redmine.issue.get(issue_id, include=['children', 'relations'])
        return issue.get_issue_family(redmine_issue)

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
        if self.result == []:
            self.result.append(alone_issue_mapping)
        else:
            if alone_issue_mapping not in self.result:  
                can_append = True       
                for result in deepcopy(self.result):
                    same = True
                    if len(alone_issue_mapping) >= len(result):
                        for k, v in result.items():
                            if k not in alone_issue_mapping or v != alone_issue_mapping[k]:
                                same = False    
                        if same:
                            self.result.remove(result)                                       
                    else:
                        for k, v in alone_issue_mapping.items():
                            if k not in result or v != result[k]:
                                same = False    
                        if same:
                            can_append = False
                if can_append:
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
        if familys != []:
            for family in familys:
                for index in index_list:
                    if family["tracker"]["name"] == self.trace_order[index]:
                        if index == self.test_plan_index:
                            alone_issue_mapping.update(self.__get_test_plan_content(family["id"]))
                        alone_issue_mapping.update({self.trace_order[index]: self.issues[family["id"]]})     
        self.__append_result(alone_issue_mapping)

    def generate_head_mapping(self):
        mapping = {}
        self.same_track = self.trace_order[0]  
        self.next_track = self.trace_order[1] 
        first_tracker_issue_list = [id for id, issue in self.issues.items() if issue["tracker"] == self.same_track]

        for id in first_tracker_issue_list:
            value = {"same_level": [], "next_level": []}
            family = self.__get_family(id)
            for relation_type in ["relations", "children"]:
                if family.get(relation_type) is not None:
                    for item in family[relation_type]:
                        if item["tracker"]["name"] == self.same_track:
                            value["same_level"].append(item["id"])
                        if item["tracker"]["name"] == self.next_track:
                            value["next_level"].append(item["id"])              
            if value["next_level"] == []:
                if value["same_level"] == []:
                    self.generate_output(id, family, 0)
                continue
            mapping[id] = value

        not_alone_next_id_list = []
        for _, value in mapping.items():
            not_alone_next_id_list += value.get("next_level")
        self.not_alone_id_mapping[self.next_track] = not_alone_next_id_list

    def generate_middle_mapping(self, index):          
        self.same_track = self.trace_order[index]
        self.next_track = self.trace_order[index + 1]
        self.tracker_issue_list = [id for id, issue in self.issues.items() if issue["tracker"] == self.same_track and id not in self.not_alone_id_mapping[self.same_track]]
        for id in self.not_alone_id_mapping[self.same_track]:
            self.__check_middle_id(id, index)
        for id in self.tracker_issue_list:
            self.generate_output(id, self.__get_family(id), index)

        for id in [id for id, issue in self.issues.items() if issue["tracker"] == self.same_track and id not in self.tracker_issue_list]:
            family = self.__get_family(id)
            for relation_type in ["relations", "children"]:
                if family.get(relation_type) is not None:
                    for item in family[relation_type]:
                        if item["tracker"]["name"] == self.next_track:
                            self.not_alone_id_mapping[self.next_track].append(item["id"])

        self.not_alone_id_mapping[self.next_track] = list(set(self.not_alone_id_mapping[self.next_track]))

    def __check_middle_id(self, id, index):
        check_complete = True
        self.mention_id.append(id)
        value = {"same_level": [], "next_level": []}
        family = self.__get_family(id)
        for relation_type in ["relations", "children"]:
            if family.get(relation_type) is not None:
                for item in family[relation_type]:
                    if item["tracker"]["name"] == self.same_track:
                        value["same_level"].append(item["id"])
                    if item["tracker"]["name"] == self.next_track:
                        value["next_level"].append(item["id"])
        if value["same_level"] != []:
            for same_id in value["same_level"]:
                if same_id in self.mention_id:
                    continue
                else:
                    check_complete = False
                    if same_id in self.not_alone_id_mapping[self.same_track]:
                        continue
                    if same_id in self.tracker_issue_list:
                        self.__remove_id(same_id)
                        self.__check_middle_id(same_id, index)  
        if check_complete:
            if value["next_level"] == []:
                self.generate_output(id, family, index)
            else:
                self.__remove_id(id)
                self.not_alone_id_mapping[self.next_track] += value.get("next_level")

    def generate_final_mapping(self):
        self.same_track = self.trace_order[-1]
        self.tracker_issue_list = [id for id, issue in self.issues.items() if issue["tracker"] == self.same_track and id not in self.not_alone_id_mapping[self.same_track]]
        for id in self.not_alone_id_mapping[self.same_track]:
            self.__check_final_id(id)
        for id in self.tracker_issue_list:
            self.generate_output(id, self.__get_family(id), len(self.trace_order) - 1)

    def __check_final_id(self, id):
        value = {"same_level": []}
        family = self.__get_family(id)
        for relation_type in ["relations", "children"]:
            if family.get(relation_type) is not None:
                for item in family[relation_type]:
                    if item["tracker"]["name"] == self.same_track:
                        value["same_level"].append(item["id"])
        if value["same_level"] != []:
            for same_id in value["same_level"]:
                if same_id not in self.not_alone_id_mapping[self.same_track]:
                    self.__remove_id(same_id)
                    if id not in self.mention_id:
                        self.mention_id.append(id)
                        self.__check_final_id(same_id)

    def execute_trace_order(self, order_length):
        self.generate_head_mapping()

        for i in range(order_length - 2):
            self.generate_middle_mapping(i + 1)

        self.generate_final_mapping()

        return self.result

# --------------------- Resources ---------------------
class TraceOrders(Resource):
    def get(self):
        parser = reqparse.RequestParser()
        parser.add_argument('project_id', type=int, required=True)
        args = parser.parse_args()
        return util.success(get_trace_order_by_project(args["project_id"]))

    @jwt_required
    def post(self):
        parser = reqparse.RequestParser()
        parser.add_argument('name', type=str, required=True)
        parser.add_argument('project_id', type=int, required=True)
        parser.add_argument('order', type=str, action='append', required=True)
        parser.add_argument('default', type=bool, required=True)
        args = parser.parse_args()
        return util.success(create_trace_order_by_project(args))

class SingleTraceOrder(Resource):
    @jwt_required
    def patch(self, trace_order_id):
        parser = reqparse.RequestParser()
        parser.add_argument('name', type=str)
        parser.add_argument('project_id', type=int)
        parser.add_argument('order', type=str, action='append')
        parser.add_argument('default', type=bool)
        args = parser.parse_args()
        args = {k: v for k, v in args.items() if v is not None}
        return util.success(update_trace_order(trace_order_id, args))

    @jwt_required
    def delete(self, trace_order_id):
        return util.success(delete_trace_order(trace_order_id))


class ExecuteTraceOrder(Resource):
    @jwt_required
    def patch(self): 
        parser = reqparse.RequestParser()
        parser.add_argument('project_id', type=int, required=True)
        args = parser.parse_args()
        project_id = args["project_id"]

        trace_order = TraceOrder.query.filter_by(
            project_id=project_id, 
            default=True, 
        ).first()
        if trace_order is not None:
            order = trace_order.order
        else:
            order = config.get("DEFAULT_TRACE_ORDER")

        plan_project_id = project.get_plan_project_id(project_id)

        trackers = redmine_lib.redmine.tracker.all()
        issues = redmine_lib.redmine.issue.filter(
            project_id=plan_project_id,
            tracker_id="|".join([str(tracker.id) for tracker in trackers if tracker.name in order]),
            status_id="*"
        )
        issues = {issue.id: {
            "id": issue.id,
            "name": issue.subject, 
            "tracker": issue.tracker.name, 
            "status": {"id": issue.status.id, "name": issue.status.name}, 
        } for issue in issues}

        return util.success(TraceList(plan_project_id, order, issues).execute_trace_order(len(order)))
