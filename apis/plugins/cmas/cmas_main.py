import datetime
import json
import time
from io import BytesIO
import os
import hashlib
import werkzeug
import requests
from flask import send_file
from flask_jwt_extended import jwt_required
from flask_restful import Resource, reqparse
from sqlalchemy import desc
from sqlalchemy.orm.exc import NoResultFound

import util
from model import CMAS as Model
from model import db, ProjectPluginRelation
from plugins import get_plugin_config
from resources import apiError, gitlab
from resources.apiError import DevOpsError


def cm_get_config(key):
    for arg in get_plugin_config("cmas")["arguments"]:
        if arg['key'] == key:
            return arg['value']
    return None


def build_url(path):
    return f'{cm_get_config("cm-url")}{path}'


class CMAS(object):
    def __init__(self, task_id):
        self.task = check_cmas_exist(task_id)
        self.authKey = cm_get_config("authKey")

    def __api_request(self, method, path, headers={}, params=(), data={}):
        url = build_url(path)
        if method.upper() == 'GET':
            res = requests.get(url, headers=headers, params=params, verify=False)
        elif method.upper() == 'POST':
            res = requests.post(url, headers=headers, params=params, data=data, verify=False)
        else:
            raise DevOpsError(500, 'Only GET and POST is allowed.',
                              error=apiError.invalid_code_path('Only GET and POST is allowed, but'
                                                               '{0} provided.'.format(method)))
        if int(res.status_code / 100) != 2:
            raise apiError.DevOpsError(
                res.status_code, 'Got non-2xx response from CMAS.',
                apiError.error_3rd_party_api('CMAS', res))
        return res

    def __api_get(self, path, headers={}, params=()):
        return self.__api_request('GET', path, headers=headers, params=params)

    def __api_post(self, path, headers={}, params=(), data={}, files={}):
        url = build_url(path)
        res = requests.post(url, headers=headers, data=data, params=params, files=files, verify=False)
        return res

    def query_report_task(self):
        ret = self.__api_post(
            '/M3AS-REST/api/query/report',
            data={
                'authKey': self.authKey,
                'uploadId': self.task.upload_id,
                'sha256': self.task.sha256,
                'taskId': self.task.task_id,
            },
        ).json()
        if ret.get("Pdf-link-list") is not None:
            pdf_file = ""
            for filename in ret["Pdf-link-list"]:
                if "cht" in filename:
                    pdf_file = filename.replace("/M3AS-REST/api/report/pdf?filename=", "")
                    break
            json_file = ret.get("JSON-link", "").replace("/M3AS-REST/api/report/json?filename=", "")

            self.task.scan_final_status = "SUCCESS"
            self.task.finished = True
            self.task.finished_at = datetime.datetime.utcnow()
            self.task.filenames = {"pdf": pdf_file, "json": json_file}
            self.task.stats = self.__pharse_state_info()
            db.session.commit()
            ret["status"] = "SUCCESS"
            return ret
        else:
            ret["status"] = ret["status"].replace("APP_", "")
            return ret

    def download_report(self):
        ret = self.__api_get(
            '/M3AS-REST/api/report/pdf',
            params=(
                ('filename', self.task.filenames.get("pdf")),
            )
        )
        # with open(f"./logs/cmas/{self.task.task_id}/{self.task.task_id}.pdf", "wb") as f:
        #     f.write(ret.content)

        return send_file(
            # f"../logs/cmas/{self.task.task_id}/{self.task.task_id}.pdf",
            BytesIO(ret.content),
            mimetype="application/pdf",
            attachment_filename=f"{self.task.task_id}/{self.task.task_id}.pdf"
        )

    def return_content(self):
        json_file_name = self.task.filenames.get("json")
        if json_file_name is None:
            return {}
        ret = self.__api_get(
            '/M3AS-REST/api/report/json',
            params=(
                ('filename', json_file_name),
            )
        )
        return json.loads(ret.content.decode("utf-8"))

    def __pharse_state_info(self):
        self.json_content = self.return_content()
        self.state = {
            key: {level: 0 for level in ["High", "Medium", "Low"]} for key in ["OWASP", "MOEA"]
        }
        self.__update_state_summary()
        self.__update_state_owasp()
        self.__update_state_moea()

        return json.dumps(self.state)

    def __update_state_summary(self):
        for summary_type in ["MOEA", "OWASP"]:
            self.state[summary_type]["summary"] = self.__state_summary_pharse(
                self.json_content["Summary"]["VulSummaryTotalRecord"][f"{summary_type.lower()}Summary"])

    def __state_summary_pharse(self, content):
        return content.split(":")[0].rstrip()

    def __update_state_owasp(self):
        for owasp in self.json_content["OWASPRuleReport"]:
            if owasp["result"] == "Find" and owasp["level"] in ["High", "Medium", "Low"]:
                self.state["OWASP"][owasp["level"]] += 1

    def __update_state_moea(self):
        level_mapping = {
            "level1": "Low",
            "level2": "Medium",
            "level3": "High",
        }
        for moea in self.json_content["GovernmentScanRule"]:
            if moea["result"] == "Find":
                for level in level_mapping:
                    self.state["MOEA"][level_mapping[level]] += moea[level]


def get_secrets():
    return {
        "auth_key": cm_get_config("authKey"),
        "cm_url": cm_get_config("cm-url"),
        "a_report_type": cm_get_config("a_report_type"),
    }


def convert_repo_to_project_id(repo_id):
    return ProjectPluginRelation.query.filter_by(git_repository_id=repo_id).first().project_id


def check_cmas_exist(task_id):
    task = Model.query.filter_by(task_id=task_id).first()
    if task is None:
        raise apiError.DevOpsError(400, 'Task not found', apiError.resource_not_found())
    return task


def get_tasks(repository_id):
    return [{
        "task_id": task.task_id,
        "branch": task.branch,
        "commit_id": task.commit_id,
        'commit_url': gitlab.commit_id_to_url(convert_repo_to_project_id(repository_id), task.commit_id),
        "run_at": str(task.run_at),
        "status": task.scan_final_status,
        "stats": util.is_json(task.stats),
        "finished_at": str(task.finished_at),
        "filenames": task.filenames,
        "upload_id": task.upload_id,
        "size": task.size,
        "sha256": task.sha256,
        "a_mode": task.a_mode,
        "a_report_type": task.a_report_type,
        "a_ert": task.a_ert,
    } for task in Model.query.filter_by(repo_id=repository_id).order_by(desc(Model.run_at)).all()]


def get_task_state(project_id, commit_id=None):
    repo_id = ProjectPluginRelation.query.filter_by(project_id=project_id).first().git_repository_id

    if commit_id is None:  # Get latest project test if commit_id is None
        cmas_test = Model.query.filter_by(repo_id=repo_id).filter_by(finished=True).order_by(desc(Model.run_at)).first()
    else:
        cmas_test = Model.query.filter_by(repo_id=repo_id).filter_by(commit_id=commit_id).first()

    if cmas_test is not None:
        stats = util.is_json(cmas_test.stats)
        if isinstance(stats, dict):
            stats["run_at"] = str(cmas_test.run_at)
        return stats
    return ""


def create_task(args, repository_id):
    new = Model(
        task_id=args['task_id'],
        repo_id=repository_id,
        branch=args['branch'],
        commit_id=args['commit_id'],
        run_at=datetime.datetime.utcnow(),
        scan_final_status=None,
        finished=False,
        a_mode=args['a_mode'],
        a_report_type=cm_get_config("a_report_type"),
        a_ert=args['a_ert'],
    )
    db.session.add(new)
    db.session.commit()

    if not os.path.isdir(f"./logs/cmas/{new.task_id}"):
        os.makedirs(f"./logs/cmas/{new.task_id}", exist_ok=True)
    return util.success()


def update_task(args, task_id):
    task = check_cmas_exist(task_id)
    if args.get("upload_id") is not None:
        task.upload_id = args["upload_id"]
    if args.get("size") is not None:
        task.size = args["size"]
    if args.get("sha256") is not None:
        task.sha256 = args["sha256"]
    if args.get("stats") is not None:
        task.stats = args["stats"]
    if args.get("scan_final_status") is not None:
        task.scan_final_status = args["scan_final_status"]
    if args.get("logs") is not None:
        task.logs = args["logs"]

    db.session.commit()

    # --------------------- Resources ---------------------


class CMASTask(Resource):
    # Get all tasks
    @jwt_required
    def get(self, repository_id):
        return util.success(get_tasks(repository_id))

    # Create new tasks
    @jwt_required
    def post(self, repository_id):
        parser = reqparse.RequestParser()
        parser.add_argument('task_id', type=str, required=True)
        parser.add_argument('branch', type=str, required=True)
        parser.add_argument('commit_id', type=str, required=True)
        parser.add_argument('a_mode', type=int, required=True)
        parser.add_argument('a_ert', type=int, required=True)
        args = parser.parse_args()
        return create_task(args, repository_id)

    def put(self):
        parser = reqparse.RequestParser()
        parser.add_argument('task_id', type=str, required=True)
        parser.add_argument('upload_id', type=int)
        parser.add_argument('size', type=int)
        parser.add_argument('sha256', type=str)
        parser.add_argument('stats', type=str)
        parser.add_argument('scan_final_status', type=str)
        parser.add_argument('logs', type=str)

        args = parser.parse_args()
        return update_task(args, args.pop("task_id"))


class CMASRemote(Resource):
    # get task status
    @jwt_required
    def get(self, task_id):
        return util.success(CMAS(task_id).query_report_task())


class CMASDonwload(Resource):
    # Download reports
    @jwt_required
    def get(self, task_id, file_type):
        if file_type == "pdf":
            return CMAS(task_id).download_report()
        elif file_type == "json":
            return CMAS(task_id).return_content()


class CMASSecret(Resource):
    @jwt_required
    def get(self):
        return get_secrets()
