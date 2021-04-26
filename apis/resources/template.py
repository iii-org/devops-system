from datetime import datetime
import dateutil.parser
import sys
import subprocess
import shutil
from pathlib import Path
import json
import yaml

from flask_jwt_extended import jwt_required, get_jwt_identity
from flask_restful import Resource, reqparse
import util
import config
import resources.yaml_OO as pipeline_yaml_OO
import util
from . import role
from model import db, TemplateListCache
from sqlalchemy import func, or_, and_

from gitlab import Gitlab


template_replace_dict = {
    "registry": config.get("HARBOR_EXTERNAL_BASE_URL").replace("https://", ""), 
    "PLUGIN_MIRROR": config.get("HARBOR_EXTERNAL_BASE_URL"),
    "harbor.host": config.get("HARBOR_EXTERNAL_BASE_URL").replace("https://", ""),
    "git.host": config.get("GITLAB_BASE_URL").replace("http://", "")
    }

support_software = [{"key": "scan-sonarqube", "display": "SonarQube"}, 
                    {"key": "scan-checkmarx", "display": "Checkmarx"}, 
                    {"key": "test-postman", "display": "Postman"}, 
                    {"key": "test-sideex", "display": "SideeX"}, 
                    {"key": "test-webinspect", "display": "WebInspect"},
                    {"key": "db", "display": "Database"},
                    {"key": "web", "display": "Web"}]

gitlab_private_token = config.get("GITLAB_PRIVATE_TOKEN")
gl = Gitlab(config.get("GITLAB_BASE_URL"), private_token=gitlab_private_token)


def __tm_get_tag_info(pj, tag_name):
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
    return tag_info_dict


def __tm_get_pipe_yamlfile_name(pj, tag_name=None):
    pipe_yaml_file_name = None
    if tag_name is None:
        ref=pj.default_branch
    else:
        tag_info_dict = __tm_get_tag_info(pj, tag_name)
        ref = tag_info_dict["commit_id"]
    for item in  pj.repository_tree(ref=ref):
        if item["path"] == ".rancher-pipeline.yml":
            pipe_yaml_file_name = ".rancher-pipeline.yml"
        elif item["path"] == ".rancher-pipeline.yaml":
            pipe_yaml_file_name = ".rancher-pipeline.yaml"
    return pipe_yaml_file_name

def __tm_get_git_pipline_json(pj, tag_name=None):
    if tag_name == None:
        pipe_yaml_file_name = __tm_get_pipe_yamlfile_name(pj)
        ref = pj.default_branch
    else:
        pipe_yaml_file_name = __tm_get_pipe_yamlfile_name(pj, tag_name=tag_name)
        tag_info_dict = __tm_get_tag_info(pj, tag_name)
        ref = tag_info_dict["commit_id"]
    
    f_raw = pj.files.raw(file_path = pipe_yaml_file_name, ref = ref)
    pipe_json = yaml.safe_load(f_raw.decode())
    return pipe_json


def __tm_read_pipe_set_json(pj, tag_name=None):
    pip_set_json = {}
    if tag_name is None:
        iiidevops_folder = pj.repository_tree(path="iiidevops")
    else:
        tag_info_dict = __tm_get_tag_info(pj, tag_name)
        iiidevops_folder = pj.repository_tree(path="iiidevops", ref = tag_info_dict["commit_id"])
    for file in iiidevops_folder:
        if file["name"] == "pipeline_settings.json":
            f_raw = pj.files.raw(file_path="iiidevops/pipeline_settings.json", 
                                    ref = pj.default_branch)
            pip_set_json = json.loads(f_raw.decode())
    return pip_set_json


def __tm_git_clone_file(pj, dest_folder_name, create_time=None, branch_name=None):
    temp_http_url = pj.http_url_to_repo
    secret_temp_http_url = temp_http_url[:7] + f"root:{gitlab_private_token}@" + temp_http_url[7:]
    Path(f"{dest_folder_name}").mkdir(exist_ok=True)
    if create_time is not None:
        pj_name = f"{pj.path}_{create_time}"
    else:
        pj_name = f"{pj.path}"
    if branch_name is None:
        branch_name = pj.default_branch
    subprocess.call(['git', 'clone', '-b', branch_name, secret_temp_http_url
                     , f"{dest_folder_name}/{pj_name}"])


def __set_git_username_config(path):
    git_user_email_proc = subprocess.Popen(['git', 'config', 'user.email'], stdout=subprocess.PIPE, shell=False)
    git_user_name_proc = subprocess.Popen(['git', 'config', 'user.name'], stdout=subprocess.PIPE, shell=False)
    git_user_email = git_user_email_proc.stdout.read().decode("utf-8")
    git_user_name = git_user_name_proc.stdout.read().decode("utf-8")
    if git_user_email == "":
        subprocess.call(['git', 'config', '--global', 'user.email', '"system@iiidevops.org"'], cwd=path)
    if git_user_name == "":
        subprocess.call(['git', 'config', '--global', 'user.name', '"system"'], cwd=path)


def __check_git_project_is_empty(pj):
    if pj.default_branch is None or pj.repository_tree() is None:
        return True


def __force_update_template_cache_table():
    for template_list_cache in  TemplateListCache.query.all():
        db.session.delete(template_list_cache)
        db.session.commit()
    output = []
    for group in gl.groups.list(all=True):
        if group.name in ["iiidevops-templates", "local-templates"]:
            for group_project in group.projects.list(all=True):
                pj = gl.projects.get(group_project.id)
                # get all tags
                tag_list = []
                for tag in pj.tags.list(all=True):
                    tag_list.append({"name": tag.name, "commit_id": tag.commit["id"], 
                                    "commit_time":tag.commit["committed_date"]})
                pip_set_json = __tm_read_pipe_set_json(pj)
                output.append({"id": pj.id,
                            "name": pj.name, 
                            "path": pj.path,
                            "display": pj.name if "name" not in pip_set_json else pip_set_json["name"],
                            "description": 
                                "" if "description" not in pip_set_json else pip_set_json["description"],
                            "version": tag_list})
                cache_temp = TemplateListCache(temp_repo_id=pj.id,
                                name=pj.name,
                                path=pj.path,
                                display=pj.name if "name" not in pip_set_json else pip_set_json["name"],
                                description="" if "description" not in pip_set_json else pip_set_json["description"],
                                version=tag_list,
                                update_at=datetime.now())
                db.session.add(cache_temp)
                db.session.commit()
    return output


def tm_get_template_list(force_update=0):
    one_day_ago = datetime.fromtimestamp(datetime.utcnow().timestamp() - 86400)
    total_data = TemplateListCache.query.all()
    one_day_ago_data = TemplateListCache.query.filter(TemplateListCache.update_at < one_day_ago).all()
    if force_update == 1:
        return __force_update_template_cache_table()
    elif len(total_data) ==0 or len(one_day_ago_data) > 1:
        return __force_update_template_cache_table()
    else:
        output = []
        for data in total_data:
            output.append({
            "id": data.temp_repo_id,
            "name": data.name, 
            "path": data.path,
            "display": data.display,
            "description": data.description,
            "version": data.version})
        return output





def tm_get_template(repository_id, tag_name):
    pj = gl.projects.get(repository_id)
    tag_info_dict = __tm_get_tag_info(pj, tag_name)
    pip_set_json= __tm_read_pipe_set_json(pj, tag_name)
    output = {"id": int(repository_id), "tag_name": tag_info_dict["tag_name"]}
    if "arguments" in pip_set_json:
        output["arguments"] = pip_set_json["arguments"]
    return output


def tm_use_template_push_into_pj(template_repository_id, user_repository_id, tag_name, arguments):
    template_pj = gl.projects.get(template_repository_id)
    temp_http_url = template_pj.http_url_to_repo
    secret_temp_http_url = temp_http_url[:7] + f"root:{gitlab_private_token}@" + temp_http_url[7:]
    pipe_json = __tm_get_git_pipline_json(template_pj, tag_name=tag_name)
    tag_info_dict= __tm_get_tag_info(template_pj, tag_name)
    pipe_yaml_file_name = __tm_get_pipe_yamlfile_name(template_pj, tag_name=tag_name)
    pip_set_json= __tm_read_pipe_set_json(template_pj, tag_name)
    
    pj = gl.projects.get(user_repository_id)
    pj_http_url = pj.http_url_to_repo
    secret_pj_http_url = pj_http_url[:7] + f"root:{gitlab_private_token}@" + pj_http_url[7:]

    Path("pj_push_template").mkdir(exist_ok=True)
    subprocess.call(['git', 'clone', '--branch', tag_info_dict["tag_name"], secret_temp_http_url
                     , f"pj_push_template/{pj.path}"])
    pipe_json = None
    with open(f'pj_push_template/{pj.path}/{pipe_yaml_file_name}') as file:
        pipe_json = yaml.safe_load(file)
        for stage in pipe_json["stages"]:
            if "steps" in stage:
                for step in stage["steps"]:
                    for fun_key, fun_value in step.items():
                        # Replace System parameters, like harbor.host, registry.
                        if fun_key == "applyAppConfig":
                            for ans_key in fun_value["answers"].keys():
                                if ans_key in template_replace_dict:
                                    fun_value["answers"][ans_key] = template_replace_dict[ans_key]
                                # Replace by pipeline_settings.json default value
                                if "arguments" in pip_set_json:
                                    for argument in pip_set_json["arguments"]:
                                        if "default_value" in argument and argument["key"] == ans_key:
                                            fun_value["answers"][ans_key] = argument["default_value"]
                                # Replace by user input parameter.
                                if arguments is not None and ans_key in arguments:
                                    for arg_key, arg_value in arguments.items():
                                        if arg_key is not None and ans_key == arg_key:
                                            fun_value["answers"][ans_key] = arg_value
                        elif fun_key == "envFrom":
                            pass
                        else:
                            for parm_key in fun_value.keys():
                                if parm_key in template_replace_dict:
                                    fun_value[parm_key] = template_replace_dict[parm_key]
    with open(f'pj_push_template/{pj.path}/{pipe_yaml_file_name}', 'w') as file:
        documents = yaml.dump(pipe_json, file)
    __set_git_username_config(f"pj_push_template/{pj.path}")
    subprocess.call(['git', 'branch'], cwd=f"pj_push_template/{pj.path}")
    shutil.rmtree(f'pj_push_template/{pj.path}/.git')
    subprocess.call(['git', 'init'], cwd=f"pj_push_template/{pj.path}")
    subprocess.call(['git', 'remote', 'add', 'origin', secret_pj_http_url], cwd=f"pj_push_template/{pj.path}")
    subprocess.call(['git', 'add', '.'], cwd=f"pj_push_template/{pj.path}")
    subprocess.call(['git', 'commit', '-m', '"範本 commit"'], cwd=f"pj_push_template/{pj.path}")
    subprocess.call(['git', 'push', '-u', 'origin', 'master'], cwd=f"pj_push_template/{pj.path}")
    shutil.rmtree(f"pj_push_template/{pj.path}", ignore_errors=True)


def tm_get_pipeline_branches(repository_id):
    pj = gl.projects.get(repository_id)
    if __check_git_project_is_empty(pj):
        return {}
    create_time = datetime.now().strftime("%y%m%d_%H%M%S")
    __tm_git_clone_file(pj, "pj_edit_pipe_yaml", create_time)
    pipe_yaml_file_name = __tm_get_pipe_yamlfile_name(pj)
    if pipe_yaml_file_name == None:
        return {}
    with open(f'pj_edit_pipe_yaml/{pj.path}_{create_time}/{pipe_yaml_file_name}') as file:
        stage_list = yaml.safe_load(file)["stages"]
        out = {}
        stages_info = {}
        stages_info["stages"] = []
        for stage in stage_list:
            stage_out_list={}
            catalogTemplate_value =stage.get("steps")[0].get("applyAppConfig", {}).get("catalogTemplate")
            if catalogTemplate_value is not None:
                catalogTemplate_value = catalogTemplate_value.split(":")[1].replace("iii-dev-charts3-","")
            for software in  support_software:
                if catalogTemplate_value is not None and software["key"] == catalogTemplate_value:
                    stage_out_list["name"] = software["display"]
                    stage_out_list["key"] = software["key"]
                    if "when" in stage:
                        stage_when = pipeline_yaml_OO.RancherPipelineWhen(stage["when"]["branch"])
                        stage_out_list["branches"] = stage_when.branch.include
                        if stage_out_list["key"] == "web":
                            stages_info["has_environment_branch_list"] = stage_out_list["branches"]
                    stages_info["stages"].append(stage_out_list)
        for br in pj.branches.list(all=True):
            for yaml_stage in stages_info["stages"]:
                if br.name not in out:
                    out[br.name] = {}
                    out[br.name]["commit_message"] = br.commit["message"]
                    out[br.name]["commit_time"] = br.commit["created_at"]
                    if "testing_tools" not in out[br.name]:
                        out[br.name]["testing_tools"] = []
                soft_key_and_status = {"key": yaml_stage["key"], "name": yaml_stage["name"], "enable": False}
                if "branches" in yaml_stage and br.name in yaml_stage["branches"]:
                    soft_key_and_status["enable"] = True
                out[br.name]["testing_tools"].append(soft_key_and_status)
    shutil.rmtree(f"pj_edit_pipe_yaml/{pj.path}_{create_time}", ignore_errors=True)
    return out


def tm_put_pipeline_branches(repository_id, data):
    pj = gl.projects.get(repository_id)
    if __check_git_project_is_empty(pj):
        return
    for br in pj.branches.list(all=True):
        create_time = datetime.now().strftime("%y%m%d_%H%M%S")
        __tm_git_clone_file(pj, "pj_edit_pipe_yaml", create_time, br.name)
        pipe_yaml_file_name = __tm_get_pipe_yamlfile_name(pj)
        if pipe_yaml_file_name == None:
            return
        with open(f'pj_edit_pipe_yaml/{pj.path}_{create_time}/{pipe_yaml_file_name}') as file:
            pipe_json = yaml.safe_load(file)
            for stage in pipe_json["stages"]:
                catalogTemplate_value =stage.get("steps")[0].get("applyAppConfig", {}).get("catalogTemplate")
                if catalogTemplate_value is not None:
                    catalogTemplate_value = catalogTemplate_value.split(":")[1].replace("iii-dev-charts3-","")
                for input_branch, input_softwares in data.items():
                    for input_soft_enable in input_softwares:
                        if catalogTemplate_value is not None and input_soft_enable["key"] == catalogTemplate_value:
                            if "when" not in stage:
                                stage["when"] = {"branch": {"include": []}}
                            stage_when = stage.get("when", {}).get("branch", {}).get("include", {})
                            if input_soft_enable["enable"] and input_branch not in stage_when:
                                stage_when.append(input_branch)
                            elif input_soft_enable["enable"] is False and input_branch in stage_when:
                                stage_when.remove(input_branch)
                            if len(stage_when) == 0:
                                stage_when.append("skip")
        with open(f'pj_edit_pipe_yaml/{pj.path}_{create_time}/{pipe_yaml_file_name}', 'w') as file:
            documents = yaml.dump(pipe_json, file)
        __set_git_username_config(f'pj_edit_pipe_yaml/{pj.path}_{create_time}')
        subprocess.call(['git', 'commit', '-m', '"編輯 .rancher-pipeline.yaml 啟用停用分支"', f'{pipe_yaml_file_name}'], cwd=f"pj_edit_pipe_yaml/{pj.path}_{create_time}")
        subprocess.call(['git', 'push', '-u', 'origin', f'{br.name}'], cwd=f"pj_edit_pipe_yaml/{pj.path}_{create_time}")
        shutil.rmtree(f"pj_edit_pipe_yaml/{pj.path}_{create_time}", ignore_errors=True)



def tm_get_pipeline_default_branch(repository_id):
    pj = gl.projects.get(repository_id)
    if __check_git_project_is_empty(pj):
        return {}
    create_time = datetime.now().strftime("%y%m%d_%H%M%S")
    __tm_git_clone_file(pj, "pj_edit_pipe_yaml", create_time)
    pipe_yaml_file_name = __tm_get_pipe_yamlfile_name(pj)
    if pipe_yaml_file_name == None:
        return {}
    with open(f'pj_edit_pipe_yaml/{pj.path}_{create_time}/{pipe_yaml_file_name}') as file:
        stage_list = yaml.safe_load(file)["stages"]
        stages_info = {}
        stages_info["default_branch"] = pj.default_branch
        stages_info["stages"] = []
        for stage in stage_list:
            stage_out_list={}
            stage_out_list["has_default_branch"] = False
            catalogTemplate_value =stage.get("steps")[0].get("applyAppConfig", {}).get("catalogTemplate")
            if catalogTemplate_value is not None:
                catalogTemplate_value = catalogTemplate_value.split(":")[1].replace("iii-dev-charts3-","")
            for software in  support_software:
                if catalogTemplate_value is not None and software["key"] == catalogTemplate_value:
                    stage_out_list["name"] = software["display"]
                    stage_out_list["key"] = software["key"]
                    if "when" in stage:
                        stage_when = pipeline_yaml_OO.RancherPipelineWhen(stage["when"]["branch"])
                        if pj.default_branch in stage_when.branch.include:
                            stage_out_list["has_default_branch"] = True
                    stages_info["stages"].append(stage_out_list)
    shutil.rmtree(f"pj_edit_pipe_yaml/{pj.path}_{create_time}", ignore_errors=True)
    return stages_info

def tm_put_pipeline_default_branch(repository_id, data):
    pj = gl.projects.get(repository_id)
    if __check_git_project_is_empty(pj):
        return
    for br in pj.branches.list(all=True):
        create_time = datetime.now().strftime("%y%m%d_%H%M%S")
        __tm_git_clone_file(pj, "pj_edit_pipe_yaml", create_time, br.name)
        pipe_yaml_file_name = __tm_get_pipe_yamlfile_name(pj)
        if pipe_yaml_file_name == None:
            return
        with open(f'pj_edit_pipe_yaml/{pj.path}_{create_time}/{pipe_yaml_file_name}') as file:
            pipe_json = yaml.safe_load(file)
            for stage in pipe_json["stages"]:
                catalogTemplate_value =stage.get("steps")[0].get("applyAppConfig", {}).get("catalogTemplate")
                if catalogTemplate_value is not None:
                    catalogTemplate_value = catalogTemplate_value.split(":")[1].replace("iii-dev-charts3-","")
                for put_pipe_soft in data["stages"]:
                    if catalogTemplate_value is not None and put_pipe_soft["key"] == catalogTemplate_value:
                        if "when" not in stage:
                            stage["when"] = {"branch": {"include": []}}
                        stage_when = stage.get("when", {}).get("branch", {}).get("include", {})
                        if put_pipe_soft["has_default_branch"] and pj.default_branch not in stage_when:
                            stage_when.append(pj.default_branch)
                        elif put_pipe_soft["has_default_branch"] is False and pj.default_branch in stage_when:
                            stage_when.remove(pj.default_branch)
                        if len(stage_when) == 0:
                            stage_when.append("skip")
        with open(f'pj_edit_pipe_yaml/{pj.path}_{create_time}/{pipe_yaml_file_name}', 'w') as file:
            documents = yaml.dump(pipe_json, file)
        __set_git_username_config(f'pj_edit_pipe_yaml/{pj.path}_{create_time}')
        subprocess.call(['git', 'commit', '-m', '"UI 編輯 .rancher-pipeline.yaml commit"', f'{pipe_yaml_file_name}'], cwd=f"pj_edit_pipe_yaml/{pj.path}_{create_time}")
        subprocess.call(['git', 'push', '-u', 'origin', f'{br.name}'], cwd=f"pj_edit_pipe_yaml/{pj.path}_{create_time}")
        shutil.rmtree(f"pj_edit_pipe_yaml/{pj.path}_{create_time}", ignore_errors=True)



class TemplateList(Resource):
    @jwt_required
    def get(self):
        role.require_pm("Error while getting template list.")
        parser = reqparse.RequestParser()
        parser.add_argument('force_update', type=int)
        args = parser.parse_args()
        return util.success(tm_get_template_list(args["force_update"]))


class SingleTemplate(Resource):
    @jwt_required
    def get(self, repository_id):
        role.require_pm("Error while getting template list.")
        parser = reqparse.RequestParser()
        parser.add_argument('tag_name', type=str)
        args = parser.parse_args()
        return util.success(tm_get_template(repository_id, args["tag_name"]))
    
class ProjectPipelineBranches(Resource):
    @jwt_required
    def get(self, repository_id):
        return util.success(tm_get_pipeline_branches(repository_id))
    
    @jwt_required
    def put(self, repository_id):
        parser = reqparse.RequestParser()
        parser.add_argument('detail', type=dict)
        args = parser.parse_args()
        tm_put_pipeline_branches(repository_id, args["detail"])
        return util.success()

class ProjectPipelineDefaultBranch(Resource):
    @jwt_required
    def get(self, repository_id):
        return util.success(tm_get_pipeline_default_branch(repository_id))

    @jwt_required
    def put(self, repository_id):
        parser = reqparse.RequestParser()
        parser.add_argument('detail', type=dict)
        args = parser.parse_args()
        tm_put_pipeline_default_branch(repository_id, args["detail"])
        return util.success()