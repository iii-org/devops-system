import base64
import json
from sqlalchemy.sql.operators import exists

from resources.handler.jwt import jwt_required
from flask_restful import Resource, reqparse
from flask import send_file

import time
from flask_socketio import emit, disconnect, Namespace
import resources.apiError as apiError
import util as util
from model import db
from resources import role
from .gitlab import GitLab, commit_id_to_url, get_nexus_project_id
from os import listdir, makedirs
from shutil import rmtree
from typing import Union, Any

gitlab = GitLab()


def pipeline_exec_action(git_repository_id: int, args: dict[str, Union[int, str]]) -> None:
    """
    :param args: must provide: action[create, rerun, stop] & pipelines_exec_run(pipeline_id)
    """
    action, pipeline_id, branch = args["action"], args["pipelines_exec_run"], args.get("branch")
    if action == "rerun":
        return gitlab.gl_rerun_pipeline_job(git_repository_id, pipeline_id)
    elif action == "stop":
        return gitlab.gl_stop_pipeline_job(git_repository_id, pipeline_id)
    elif action == "create":
        return gitlab.create_pipeline(git_repository_id, branch)


def pipeline_exec_list(git_repository_id: int, limit: int = 10, start: int = 0) -> dict[str, Any]:
    """The list sort in descending order
    :param limit: how many data per page
    :param start: start from
    """
    pipelines_info, pagination = gitlab.gl_list_pipelines(git_repository_id, limit, start, with_pagination=True)
    ret = []
    for pipeline_info in pipelines_info:
        sha = pipeline_info["sha"]
        pipeline_info["commit_id"] = sha[:8]
        pipeline_info["commit_url"] = commit_id_to_url(get_nexus_project_id(git_repository_id), sha)
        pipeline_info["execution_state"] = pipeline_info["status"].capitalize()
        pipeline_info.update(
            gitlab.get_pipeline_jobs_status(git_repository_id, pipeline_info["id"], with_commit_msg=True)
        )
        # It can not get commit message when all jobs is failed.
        if not pipeline_info["commit_message"]:
            pipeline_info["commit_message"] = gitlab.single_commit(git_repository_id, sha)["title"]
        ret.append(pipeline_info)
    return {"pagination": pagination, "pipe_execs": ret}


def get_pipeline_job_status(repo_id: int, pipeline_id: int) -> list[dict[str, Any]]:
    jobs = gitlab.gl_pipeline_jobs(repo_id, pipeline_id)
    ret = [
        {
            "stage_id": job["id"],
            "name": job["name"],
            "state": job["status"].capitalize(),
        }
        for job in jobs
    ]
    return sorted(ret, key=lambda r: r["stage_id"])


def get_pipe_log_websocket(data):
    repo_id, job_id = data["repository_id"], data["stage_id"]
    ws_start_time = time.time()
    success_end_word = "Job succeeded"
    failure_end_word = "ERROR: Job failed"
    i, last_index, first_time = 0, 0, True
    while True:
        ret = gitlab.gl_get_pipeline_console(repo_id, job_id)
        ws_end_time = time.time() - ws_start_time

        if (success_end_word in ret or failure_end_word in ret) and first_time:
            first_time = False

        if ret != "":
            # Calculate last_index, next time emit from last_index.
            ret_list = ret.split("\n")
            ret = "\n".join(ret_list[last_index:])
            last_index = len(ret_list)
        emit(
            "pipeline_log",
            {
                "data": ret,
                "repository_id": repo_id,
                "repo_id": job_id,
                "final": not first_time,
                "last_index": last_index,
            },
        )
        i += 1

        if not first_time or ws_end_time >= 600 or i >= 1000:
            i, last_index, first_time = 0, 0, True
            break


# --------------------- Resources ---------------------


class PipelineExecAction(Resource):
    @jwt_required
    def post(self, repository_id):
        parser = reqparse.RequestParser()
        parser.add_argument("pipelines_exec_run", type=int, required=True)
        parser.add_argument("action", type=str, required=True)
        parser.add_argument("branch", type=str)
        args = parser.parse_args()
        return pipeline_exec_action(repository_id, args)


class PipelineExec(Resource):
    @jwt_required
    def get(self, repository_id):
        parser = reqparse.RequestParser()
        parser.add_argument("limit", default=10, type=int, location="args")
        parser.add_argument("start", default=0, type=int, location="args")
        args = parser.parse_args()
        return util.success(pipeline_exec_list(repository_id, args["limit"], args["start"]))


class PipelineConfig(Resource):
    @jwt_required
    def get(self, repository_id):
        parser = reqparse.RequestParser()
        parser.add_argument("pipelines_exec_run", type=int, required=True, location="args")
        args = parser.parse_args()
        return get_pipeline_job_status(repository_id, args["pipelines_exec_run"])


class Pipeline(Resource):
    @jwt_required
    def post(self, repository_id):
        role.require_in_project(repository_id=repository_id)
        parser = reqparse.RequestParser()
        parser.add_argument("branch", type=str, required=True, location="form")
        args = parser.parse_args()
        gitlab.create_pipeline(repository_id, args["branch"])
        return util.success()


class PipelineWebsocketLog(Namespace):
    def on_connect(self):
        print("connect")

    def on_disconnect(self):
        print("Client disconnected")

    def on_get_pipe_log(self, data):
        print("get_pipe_log")
        get_pipe_log_websocket(data)

