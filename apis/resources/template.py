from datetime import datetime
import dateutil.parser
import sys
import yaml

from flask_jwt_extended import jwt_required, get_jwt_identity
from flask_restful import Resource, reqparse
import config
from . import role
from .logger import logger

from gitlab import Gitlab


'''
"registry": "harbor-demo.iiidevops.org", 
"PLUGIN_MIRROR": "https://harbor-demo.iiidevops.org",
"harbor.host": "harbor-demo.iiidevops.org",
"git.host": "gitlab-demo.iiidevops.org"
'''
template_replace_dict = {
    "registry": config.get("HARBOR_EXTERNAL_BASE_URL").replace("https://", ""), 
    "PLUGIN_MIRROR": config.get("HARBOR_EXTERNAL_BASE_URL"),
    "harbor.host": config.get("HARBOR_EXTERNAL_BASE_URL").replace("https://", ""),
    "git.host": config.get("GITLAB_BASE_URL").replace("http://", "")
    }

template_user_option = ["db.username", "db.password", "db.name"]


def __tm_get_git_pipline_json(repository_id, tag_name):
    gl = Gitlab(config.get("GITLAB_BASE_URL"), private_token=config.get("GITLAB_PRIVATE_TOKEN"))
    pj = gl.projects.get(repository_id)
    pipeline_yaml = ".rancher-pipeline.yaml"
    for item in  pj.repository_tree():
        if item["path"] == ".rancher-pipeline.yml":
            pipeline_yaml = ".rancher-pipeline.yml"
    tag_info_dict = {"tag_name": None, "commit_time": sys.float_info.max, "commit_id": None}
    if tag_name is None:
        # Get the last tag
        for tag in pj.tags.list():
            seconds = (datetime.now() - dateutil.parser.parse(tag.commit["committed_date"])
                       .replace(tzinfo=None)).total_seconds()
            if seconds < tag_info_dict["commit_time"]:
                tag_info_dict["tag_name"] = tag.name
                tag_info_dict["commit_time"] = seconds
                tag_info_dict["commit_id"] = tag.commit["id"]
    else:
        for tag in pj.tags.list():
            if tag_name == tag.name:
                tag_info_dict["tag_name"] = tag.name
                tag_info_dict["commit_id"] = tag.commit["id"]
    f_raw = pj.files.raw(file_path = pipeline_yaml, ref = tag_info_dict["commit_id"])
    pipe_json = yaml.safe_load(f_raw.decode())
    return pipe_json, tag_info_dict


def tm_get_template_list():
    output = []
    gl = Gitlab(config.get("GITLAB_BASE_URL"), private_token=config.get("GITLAB_PRIVATE_TOKEN"))
    group = gl.groups.get("iii-org-app", all=True)
    for group_project in group.projects.list():
        pj = gl.projects.get(group_project.id)
        # get all tags
        tag_list = []
        for tag in pj.tags.list():
            tag_list.append({"name": tag.name, "commit_id": tag.commit["id"], 
                             "commit_time":tag.commit["committed_date"]})
        summary = {"h1": [], "h2": []}
        files = pj.repository_tree()
        for file in files:
            if file["name"] == "README.md":
                f_raw = pj.files.raw(file_path="README.md", ref = pj.default_branch)
                
                for line in f_raw.decode().split('\n'):
                    if line.count("#", 0, 5) == 2:
                        summary["h2"].append(line[2:])
                    elif line.count("#", 0, 5) == 1:
                        summary["h1"].append(line[1:])
        output.append({"id": pj.id,
                       "name": pj.name, 
                       "path": pj.path, 
                       "version": tag_list,
                       "summary": summary})
    return output


def tm_get_template(repository_id, tag_name):
    pipe_json, tag_info_dict = __tm_get_git_pipline_json(repository_id, tag_name)
    output = {"template_id": int(repository_id), "tag_name": tag_info_dict["tag_name"], "template_param": []}
    for stage in pipe_json["stages"]:
        output_dict = {}
        output_dict["branchs"] = None
        output_dict["name"] = stage["name"]
        if "when" in stage:
            output_dict["branchs"] = stage["when"]["branch"]["include"]
        if "steps" in stage:
            for step in stage["steps"]:
                for fun_key, fun_value in step.items():
                    if "when" == fun_key:
                        output_dict["branchs"] = fun_value["branch"]["include"]
                    elif "applyAppConfig" == fun_key:
                        for ans_key, ans_value in fun_value["answers"].items():
                            if ans_key in template_user_option:
                                output_dict[ans_key] = ans_value
                    else:
                        for key, value in fun_value.items():
                            if key in template_user_option:
                                output_dict[key] = value
        output["template_param"].append(output_dict)
    return output


def tm_create_template(repository_id, tag_name, db_username, db_password, db_name):
    pipe_json, tag_info_dict = __tm_get_git_pipline_json(repository_id, tag_name)
    for stage in pipe_json["stages"]:
        output_dict = {}
        output_dict["branchs"] = None
        output_dict["name"] = stage["name"]
        if "steps" in stage:
            for step in stage["steps"]:
                for fun_key, fun_value in step.items():
                    # Replace Sysytem parameters, like harbor.host, registry.
                    if fun_key == "applyAppConfig":
                        for ans_key in  fun_value["answers"].keys():
                            if ans_key in template_replace_dict:
                                fun_value["answers"][ans_key] = template_replace_dict[ans_key]
                            # Replace user input parameter.
                            if db_username is not None and ans_key == "db.username":
                                fun_value["answers"][ans_key] = db_username
                            if db_password is not None and ans_key == "db.username":
                                fun_value["answers"][ans_key] = db_password
                            if db_name is not None and ans_key == "db.username":
                                fun_value["answers"][ans_key] = db_name
                    for parm_key in fun_value.keys():
                        if parm_key in template_replace_dict:
                            fun_value[parm_key] = template_replace_dict[parm_key]
    print(pipe_json)


class TemplateList(Resource):
    @jwt_required
    def get(self):
        role.require_pm("Error while getting template list.")
        return tm_get_template_list()


class SingleTemplate(Resource):
    @jwt_required
    def get(self, repository_id):
        role.require_pm("Error while getting template list.")
        parser = reqparse.RequestParser()
        parser.add_argument('tag_name', type=str)
        args = parser.parse_args()
        return tm_get_template(repository_id, args["tag_name"])
    
    
    # temporary api, only for develop
    @jwt_required
    def post(self, repository_id):
        role.require_pm("Error while getting template list.")
        parser = reqparse.RequestParser()
        parser.add_argument('tag_name', type=str)
        parser.add_argument('db_username', type=str)
        parser.add_argument('db_password', type=str)
        parser.add_argument('db_name', type=str)
        args = parser.parse_args()
        return tm_create_template(repository_id, args["tag_name"], args["db_username"], 
                                  args["db_password"], args["db_name"])
    