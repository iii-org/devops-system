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

import nexus
import util
from model import CMAS as Model
from model import db
from plugins import get_plugin_config
from resources import apiError, gitlab
from resources.apiError import DevOpsError


def build_url(path):
    return f'https://61.216.83.38:8443{path}'


class CMAS(object):
    def __init__(self, task_id):
        self.task = check_cmas_exist(task_id)
        self.authKey = "00000000000000000000000000000000"


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

    def upload_task(self):
        ret = self.__api_post(
            '/M3AS-REST/api/csf/task/upload', 
            params=( 
                ('authKey', self.authKey),
            ),
            files={
                'sampleFile': open(f"./logs/cmas/{self.task.task_id}/app-debug.apk", "rb"),
                'fileName': (None, self.task.filename),
                'sha256': (None, get_file_sha256(self.task.task_id)),
                'size': (None, get_file_size(self.task.task_id)),
                'taskId': (None, self.task.task_id),
                'a_mode': (None, self.task.a_mode),
                'a_reportType': (None, self.task.a_report_type),
                'a_ert': (None, self.task.a_ert),
            },
        ).json()
        if ret["status"] == "SUCCESS":
            self.task.sha256 = ret["AppCheckSum-sha256"]
            self.task.size = get_file_size(self.task.task_id)
            self.task.upload_id = ret["uploadId"]
            db.session.commit()

            return {
                "status": "SUCCESS",
                "sha256": ret["AppCheckSum-sha256"], 
                "upload_id": ret["uploadId"],
                "report_id": ret["reportId"],
            }
        else:
            return {
                "status": "FAIL",
                "message": ret["message"]
            }

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
            filename = ""
            for filename in ret["Pdf-link-list"]:
                if "cht" in filename:
                    filename = filename.replace("/M3AS-REST/api/report/pdf?filename=", "")
                    break

            self.task.scan_final_status = "SUCCESS"
            self.task.finished = True
            self.task.finished_at = datetime.datetime.utcnow()
            self.task.filename = filename
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
                ('filename', self.task.filename),
            )
        )
        with open(f"./logs/cmas/{self.task.task_id}/{self.task.task_id}.pdf", "wb") as f:
            f.write(ret.content)

        return send_file(f"../logs/cmas/{self.task.task_id}/{self.task.task_id}.pdf")

def get_file_sha256(task_id):
    sha256_hash = hashlib.sha256()
    with open(f"./logs/cmas/{task_id}/app-debug.apk", "rb") as f:
        # Read and update hash string value in blocks of 4K
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()

def get_file_size(task_id):
    return os.path.getsize(f"./logs/cmas/{task_id}/app-debug.apk")

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
        "run_at": str(task.run_at),
        "status": task.scan_final_status,
        "finished_at": str(task.finished_at),
        "filename": task.filename,
        "upload_id": task.upload_id,
        "size": task.size,
        "sha256": task.sha256,
        "a_mode": task.a_mode,
        "a_report_type": task.a_report_type,
        "a_ert": task.a_ert,
    } for task in Model.query.filter_by(repo_id=repository_id).order_by(Model.run_at).all()]


def create_task(args, repository_id):
    filename = "app-debug.apk"

    new = Model(
        task_id=args['task_id'],
        repo_id=repository_id,
        branch=args['branch'],
        commit_id=args['commit_id'],
        run_at=datetime.datetime.utcnow(),
        scan_final_status=None,
        finished=False,
        filename=filename,
        a_mode=args['a_mode'],
        a_report_type=args['a_report_type'],
        a_ert=args['a_ert'],
    )
    db.session.add(new)
    db.session.commit()

    if not os.path.isdir(f"./logs/cmas/{new.task_id}"):
        os.makedirs(f"./logs/cmas/{new.task_id}", exist_ok=True)
    args["sample_file"].save(os.path.join(f"logs/cmas/{new.task_id}", filename))
    return util.success()


# --------------------- Resources ---------------------
class CMASTask(Resource):
    # Get all tasks
    def get(self, repository_id):
        return util.success(get_tasks(repository_id))

    # Create new tasks
    @jwt_required
    def post(self, repository_id):
        parser = reqparse.RequestParser()
        parser.add_argument(
            'sample_file', type=werkzeug.datastructures.FileStorage, location='files', required=True)
        parser.add_argument('task_id', type=str, required=True)
        parser.add_argument('branch', type=str, required=True)
        parser.add_argument('commit_id', type=str, required=True)
        parser.add_argument('a_mode', type=int, required=True)
        parser.add_argument('a_report_type', type=int, required=True)
        parser.add_argument('a_ert', type=int, required=True)
        args = parser.parse_args()
        return create_task(args, repository_id)


class CMASRemote(Resource):
    # get task status
    @jwt_required
    def get(self, task_id):
        return util.success(CMAS(task_id).query_report_task())

    # upload file
    def post(self, task_id):
        return util.success(CMAS(task_id).upload_task())

    # Download reports
    @jwt_required
    def put(self, task_id):
        return CMAS(task_id).download_report()
