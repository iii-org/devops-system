from datetime import datetime
import dateutil.parser
import sys
import subprocess
import shutil
import yaml

from flask_jwt_extended import jwt_required, get_jwt_identity
from flask_restful import Resource, reqparse
import config
from . import role
from .logger import logger

from gitlab import Gitlab


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
    pipe_yaml_file_name = ".rancher-pipeline.yaml"
    for item in  pj.repository_tree():
        if item["path"] == ".rancher-pipeline.yml":
            pipe_yaml_file_name = ".rancher-pipeline.yml"
    tag_info_dict = {"tag_name": None, "commit_time": sys.float_info.max, "commit_id": None}
    tags = pj.tags.list()
    if len(tags) !=0:
        if tag_name is None:
            # Get the last tag
            for tag in tags:
                seconds = (datetime.now() - dateutil.parser.parse(tag.commit["committed_date"])
                        .replace(tzinfo=None)).total_seconds()
                if seconds < tag_info_dict["commit_time"]:
                    tag_info_dict["tag_name"] = tag.name
                    tag_info_dict["commit_time"] = seconds
                    tag_info_dict["commit_id"] = tag.commit["id"]
        else:
            for tag in tags:
                if tag_name == tag.name:
                    tag_info_dict["tag_name"] = tag.name
                    tag_info_dict["commit_id"] = tag.commit["id"]
    else:
        tag_info_dict = {"tag_name": pj.default_branch, "commit_time": sys.float_info.max, "commit_id": pj.default_branch}
    f_raw = pj.files.raw(file_path = pipe_yaml_file_name, ref = tag_info_dict["commit_id"])
    pipe_json = yaml.safe_load(f_raw.decode())
    return pipe_json, tag_info_dict, pipe_yaml_file_name


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
    pipe_json, tag_info_dict, pipe_yaml_file_name = __tm_get_git_pipline_json(repository_id, tag_name)
    output = {"template_id": int(repository_id), "tag_name": tag_info_dict["tag_name"], "template_param": []}
    for stage in pipe_json["stages"]:
        output_dict = {}
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
                    elif "envFrom" == fun_key:
                        pass
                    else:
                        for key, value in fun_value.items():
                            if key in template_user_option:
                                output_dict[key] = value
        output["template_param"].append(output_dict)
    return output


def tm_use_template_push_into_pj(template_repository_id, user_repository_id, tag_name, db_username, db_password, db_name):
    pipe_json, tag_info_dict, pipe_yaml_file_name = __tm_get_git_pipline_json(template_repository_id, tag_name)
    gitlab_private_token = config.get("GITLAB_PRIVATE_TOKEN")
    gl = Gitlab(config.get("GITLAB_BASE_URL"), private_token=gitlab_private_token)
    
    template_pj = gl.projects.get(template_repository_id)
    temp_http_url = template_pj.http_url_to_repo
    secret_temp_http_url = temp_http_url[:7] + f"root:{gitlab_private_token}@" + temp_http_url[7:]

    pj = gl.projects.get(user_repository_id)
    pj_http_url = pj.http_url_to_repo
    secret_pj_http_url = pj_http_url[:7] + f"root:{gitlab_private_token}@" + pj_http_url[7:]
    subprocess.call(['git', 'clone', '--branch', tag_info_dict["tag_name"], secret_temp_http_url
                     , pj.path])
    subprocess.call(['git', 'config', '--global', 'user.email', '"system@iiidevops.org"'], cwd=pj.path)
    subprocess.call(['git', 'config', '--global', 'user.name', '"system"'], cwd=pj.path)
    pipe_json = None
    with open(f'{pj.path}/{pipe_yaml_file_name}') as file:
        pipe_json = yaml.safe_load(file)
        for stage in pipe_json["stages"]:
            if "steps" in stage:
                for step in stage["steps"]:
                    for fun_key, fun_value in step.items():
                        # Replace System parameters, like harbor.host, registry.
                        if fun_key == "applyAppConfig":
                            for ans_key in  fun_value["answers"].keys():
                                if ans_key in template_replace_dict:
                                    fun_value["answers"][ans_key] = template_replace_dict[ans_key]
                                # Replace user input parameter.
                                if db_username is not None and ans_key == "db.username":
                                    fun_value["answers"][ans_key] = db_username
                                if db_password is not None and ans_key == "db.password":
                                    fun_value["answers"][ans_key] = db_password
                                if db_name is not None and ans_key == "db.name":
                                    fun_value["answers"][ans_key] = db_name
                        elif fun_key == "envFrom":
                            pass
                        else:
                            for parm_key in fun_value.keys():
                                if parm_key in template_replace_dict:
                                    fun_value[parm_key] = template_replace_dict[parm_key]
    with open(f'{pj.path}/{pipe_yaml_file_name}', 'w') as file:
        documents = yaml.dump(pipe_json, file)
    subprocess.call(['git', 'branch'], cwd=pj.path)
    shutil.rmtree(f'{pj.path}/.git')
    subprocess.call(['git', 'init'], cwd=pj.path)
    subprocess.call(['git', 'remote', 'add', 'origin', secret_pj_http_url], cwd=pj.path)
    subprocess.call(['git', 'add', '.'], cwd=pj.path)
    subprocess.call(['git', 'commit', '-m', '"範本 commit"'], cwd=pj.path)
    subprocess.call(['git', 'push', '-u', 'origin', 'master'], cwd=pj.path)
    shutil.rmtree(pj.path, ignore_errors=True)


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
    
    '''
    # temporary api, only for develop
    @jwt_required
    def post(self, repository_id):
        role.require_pm("Error while getting template list.")
        parser = reqparse.RequestParser()
        parser.add_argument('user_repository_id', type=int)
        parser.add_argument('tag_name', type=str)
        parser.add_argument('db_username', type=str)
        parser.add_argument('db_password', type=str)
        parser.add_argument('db_name', type=str)
        args = parser.parse_args()
        return tm_use_template_push_into_pj(repository_id, args["user_repository_id"], 
                                  args["tag_name"], args["db_username"], 
                                  args["db_password"], args["db_name"])
    '''