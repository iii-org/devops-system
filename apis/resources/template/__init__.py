import json
import shutil
import subprocess
import sys
from datetime import datetime
from pathlib import Path

import nexus
from model import Project
import config
import dateutil.parser
import resources.apiError as apiError
import resources.pipeline as pipeline
import resources.role as role
from resources.gitlab import gitlab as rs_gitlab
import resources.yaml_OO as pipeline_yaml_OO
from resources import logger
import util
import yaml
from flask_jwt_extended import jwt_required
from flask_restful import Resource, reqparse
from gitlab import Gitlab
from model import PluginSoftware, TemplateListCache, db

template_replace_dict = {
    "registry": config.get("HARBOR_EXTERNAL_BASE_URL").replace("https://", ""),
    "PLUGIN_MIRROR": config.get("HARBOR_EXTERNAL_BASE_URL"),
    "harbor.host":
    config.get("HARBOR_EXTERNAL_BASE_URL").replace("https://", ""),
    "git.host": config.get("GITLAB_BASE_URL").replace("http://", ""),
    'kube.ingress.base_domain': config.get("INGRESS_EXTERNAL_BASE")
}

support_software = [{
    "template_key": "scan-sonarqube",
    "plugin_key": "sonarqube",
    "display": "SonarQube"
}, {
    "template_key": "scan-checkmarx",
    "plugin_key": "checkmarx",
    "display": "Checkmarx"
}, {
    "template_key": "test-postman",
    "plugin_key": "postman",
    "display": "Postman"
}, {
    "template_key": "test-sideex",
    "plugin_key": "sideex",
    "display": "SideeX"
}, {
    "template_key": "test-webinspect",
    "plugin_key": "webinspect",
    "display": "WebInspect"
}, {
    "template_key": "test-zap",
    "plugin_key": "zap",
    "display": "ZAP"
}, {
    "template_key": "db",
    "display": "Database"
}, {
    "template_key": "web",
    "display": "Web"
}]

gitlab_private_token = config.get("GITLAB_PRIVATE_TOKEN")
gl = Gitlab(config.get("GITLAB_BASE_URL"), private_token=gitlab_private_token, ssl_verify=False)
support_software_json = util.read_json_file("apis/resources/template/supported_software.json")

def __tm_get_tag_info(pj, tag_name):
    tag_info_dict = {
        "tag_name": None,
        "commit_time": sys.float_info.max,
        "commit_id": None
    }
    tags = pj.tags.list()
    if len(tags) != 0:
        if tag_name is None:
            # Get the last tag
            for tag in tags:
                seconds = (datetime.now() - dateutil.parser.parse(
                    tag.commit["committed_date"]).replace(tzinfo=None)
                ).total_seconds()
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
        tag_info_dict = {
            "tag_name": pj.default_branch,
            "commit_time": sys.float_info.max,
            "commit_id": pj.default_branch
        }
    return tag_info_dict


def __tm_get_pipe_yamlfile_name(pj, tag_name=None, branch_name=None):
    pipe_yaml_file_name = None
    if tag_name is None and branch_name is None:
        ref = pj.default_branch
    elif tag_name is not None:
        tag_info_dict = __tm_get_tag_info(pj, tag_name)
        ref = tag_info_dict["commit_id"]
    elif branch_name is not None:
        ref = branch_name
    for item in pj.repository_tree(ref=ref):
        if item["path"] == ".rancher-pipeline.yml":
            pipe_yaml_file_name = ".rancher-pipeline.yml"
        elif item["path"] == ".rancher-pipeline.yaml":
            pipe_yaml_file_name = ".rancher-pipeline.yaml"
    return pipe_yaml_file_name


def __tm_get_git_pipline_json(pj, tag_name=None):
    if tag_name is None:
        pipe_yaml_file_name = __tm_get_pipe_yamlfile_name(pj)
        ref = pj.default_branch
    else:
        pipe_yaml_file_name = __tm_get_pipe_yamlfile_name(pj,
                                                          tag_name=tag_name)
        tag_info_dict = __tm_get_tag_info(pj, tag_name)
        ref = tag_info_dict["commit_id"]

    f_raw = pj.files.raw(file_path=pipe_yaml_file_name, ref=ref)
    pipe_json = yaml.safe_load(f_raw.decode())
    return pipe_json


def __tm_read_pipe_set_json(pj, tag_name=None):
    pip_set_json = {}
    try:
        if pj.empty_repo:
            return {"description": "", "name": pj.name}
        if tag_name is None:
            iiidevops_folder = pj.repository_tree(path="iiidevops")
        else:
            tag_info_dict = __tm_get_tag_info(pj, tag_name)
            iiidevops_folder = pj.repository_tree(
                path="iiidevops", ref=tag_info_dict["commit_id"])
        for file in iiidevops_folder:
            if file["name"] == "pipeline_settings.json":
                f_raw = pj.files.raw(
                    file_path="iiidevops/pipeline_settings.json",
                    ref=pj.default_branch)
                pip_set_json = json.loads(f_raw.decode())
        return pip_set_json
    except apiError.TemplateError:
        return {"description": "", "name": pj.name}


def __tm_git_clone_file(pj,
                        dest_folder_name,
                        create_time=None,
                        branch_name=None):
    temp_http_url = pj.http_url_to_repo
    protocol = 'https' if temp_http_url[:5] == "https" else 'http'
    if protocol == "https":
        secret_temp_http_url = temp_http_url[:8] + f"root:{gitlab_private_token}@" + temp_http_url[8:]
    else:
        secret_temp_http_url = temp_http_url[:7] + f"root:{gitlab_private_token}@" + temp_http_url[7:]
    Path(f"{dest_folder_name}").mkdir(exist_ok=True)
    if create_time is not None:
        pj_name = f"{pj.path}_{create_time}"
    else:
        pj_name = f"{pj.path}"
    if branch_name is None:
        branch_name = pj.default_branch
    subprocess.call([
        'git', 'clone', '-b', branch_name, secret_temp_http_url,
        f"{dest_folder_name}/{pj_name}"
    ])


def __set_git_username_config(path):
    git_user_email_proc = subprocess.Popen(['git', 'config', 'user.email'],
                                           stdout=subprocess.PIPE,
                                           shell=False)
    git_user_name_proc = subprocess.Popen(['git', 'config', 'user.name'],
                                          stdout=subprocess.PIPE,
                                          shell=False)
    git_user_email = git_user_email_proc.stdout.read().decode("utf-8")
    git_user_name = git_user_name_proc.stdout.read().decode("utf-8")
    if git_user_email == "":
        subprocess.call([
            'git', 'config', '--global', 'user.email', '"system@iiidevops.org"'
        ],
            cwd=path)
    if git_user_name == "":
        subprocess.call(['git', 'config', '--global', 'user.name', '"system"'],
                        cwd=path)


def __check_git_project_is_empty(pj):
    if pj.default_branch is None or pj.repository_tree() is None:
        return True


def __add_plugin_soft_status():
    db_plugins = PluginSoftware.query.all()
    for software in support_software:
        for db_plugin in db_plugins:
            if software.get('plugin_key') == db_plugin.name:
                software['plugin_disabled'] = db_plugin.disabled


def __add_plugin_soft_status_json():
    db_plugins = PluginSoftware.query.all()
    for software in support_software_json:
        for db_plugin in db_plugins:
            if software.get('plugin_key') == db_plugin.name:
                software['plugin_disabled'] = db_plugin.disabled


def __compare_tag_version(tag_version, start_version, end_version=None):
    def version_parser(version_string):
        return version_string.replace('v', '').split('.')

    def ver_hight_greater_ver_low(ver_low, ver_hight):
        i = 0
        while i < 3:
            if int(ver_hight[i]) > int(ver_low[i]):
                return True
            elif int(ver_hight[i]) < int(ver_low[i]):
                return False
            elif i == 2:
                return True
            else:
                i += 1
    # has end
    tag_version_list = version_parser(tag_version)
    tag_version_list = tag_version_list + [0] * (3 - len(tag_version_list))
    start_version_list = version_parser(start_version)
    start_version_list = start_version_list + [0] * (3 - len(start_version_list))
    if end_version == "":
        return ver_hight_greater_ver_low(start_version_list, tag_version_list)
    else:
        # has end version
        end_version_list = version_parser(end_version)
        end_version_list = end_version_list + [0] * (3 - len(end_version_list))
        over_start_ver = ver_hight_greater_ver_low(start_version_list, tag_version_list)
        low_end_ver = ver_hight_greater_ver_low(tag_version_list, end_version_list)
        if over_start_ver and low_end_ver:
            return True
        else:
            return False


def __force_update_template_cache_table():
    template_support_version = None
    TemplateListCache.query.delete()
    db.session.commit()

    output = [{
        "source": "Public Templates",
        "options": []
    }, {
        "source": "Local Templates",
        "options": []
    }]
    template_group_dict = {
        "iiidevops-templates": "Public Templates",
        "local-templates": "Local Templates"
    }
    with open('apis/resources/template/template_support_version.json') as file:
        template_support_version = json.load(file)
    for group in gl.groups.list(all=True):
        if group.name in template_group_dict:
            for group_project in group.projects.list(all=True):
                pj = gl.projects.get(group_project.id)
                # get all tags
                tag_list = []
                for tag in pj.tags.list(all=True):
                    if group.name == "iiidevops-templates" and \
                            template_support_version is not None:
                        for temp_name, temp_value in template_support_version.items():
                            if temp_name == pj.name:
                                status = __compare_tag_version(
                                    tag.name, temp_value.get('start_version'),
                                    temp_value.get('end_version'))
                                if status:
                                    tag_list.append({
                                        "name": tag.name,
                                        "commit_id": tag.commit["id"],
                                        "commit_time": tag.commit["committed_date"]
                                    })
                                break
                    else:
                        tag_list.append({
                            "name": tag.name,
                            "commit_id": tag.commit["id"],
                            "commit_time": tag.commit["committed_date"]
                        })
                pip_set_json = __tm_read_pipe_set_json(pj)
                template_data = {
                    "id":
                        pj.id,
                        "name":
                        pj.name,
                        "path":
                        pj.path,
                        "display":
                        pip_set_json["name"],
                        "description":
                        pip_set_json["description"],
                        "version":
                        tag_list
                }
                if group.name == "iiidevops-templates" and template_support_version is None:
                    output[0]['options'].append(template_data)
                elif group.name == "iiidevops-templates" and template_support_version is not None \
                        and pj.name in template_support_version:
                    output[0]['options'].append(template_data)
                elif group.name == "local-templates":
                    output[1]['options'].append(template_data)
                cache_temp = TemplateListCache(
                    temp_repo_id=pj.id,
                    name=pj.name,
                    path=pj.path,
                    display=pip_set_json["name"],
                    description=pip_set_json["description"],
                    version=tag_list,
                    update_at=datetime.now(),
                    group_name=template_group_dict.get(group.name))
                db.session.add(cache_temp)
                db.session.commit()
    return output


def __update_stage_when_plugin_disable(stage):
    catalogTemplate_value = ""
    if ("steps" in stage) and ("applyAppConfig" in stage['steps'][0]) \
            and 'catalogTemplate' in stage['steps'][0]['applyAppConfig']:
        catalogTemplate_value = stage['steps'][0]['applyAppConfig']['catalogTemplate'].split(
            ":")[1].replace("iii-dev-charts3-", "")
    if catalogTemplate_value != '':
        for software in support_software:
            if software.get('template_key') == catalogTemplate_value and software.get(
                    'plugin_disabled') is True:
                if "when" not in stage:
                    stage["when"] = {"branch": {"include": []}}
                stage_when = stage.get("when", {}).get(
                    "branch", {}).get("include", {})
                stage_when.clear()
                stage_when.append("skip")
    return stage


def tm_get_template_list(force_update=0):
    one_day_ago = datetime.fromtimestamp(datetime.utcnow().timestamp() - 86400)
    total_data = TemplateListCache.query.all()
    one_day_ago_data = TemplateListCache.query.filter(
        TemplateListCache.update_at < one_day_ago).first()
    if force_update == 1:
        return __force_update_template_cache_table()
    elif len(total_data) == 0 or one_day_ago_data:
        return __force_update_template_cache_table()
    else:
        output = [{
            "source": "Public Templates",
            "options": []
        }, {
            "source": "Local Templates",
            "options": []
        }]
        for data in total_data:
            if data.group_name == "Public Templates":
                output[0]["options"].append({
                    "id": data.temp_repo_id,
                    "name": data.name,
                    "path": data.path,
                    "display": data.display,
                    "description": data.description,
                    "version": data.version
                })
            else:
                output[1]["options"].append({
                    "id": data.temp_repo_id,
                    "name": data.name,
                    "path": data.path,
                    "display": data.display,
                    "description": data.description,
                    "version": data.version
                })
        return output


def tm_get_template(repository_id, tag_name):
    pj = gl.projects.get(repository_id)
    tag_info_dict = __tm_get_tag_info(pj, tag_name)
    pip_set_json = __tm_read_pipe_set_json(pj, tag_name)
    output = {"id": int(repository_id), "tag_name": tag_info_dict["tag_name"]}
    if "arguments" in pip_set_json:
        output["arguments"] = pip_set_json["arguments"]
    return output


def tm_use_template_push_into_pj(template_repository_id, user_repository_id,
                                 tag_name, arguments):
    __add_plugin_soft_status()
    template_pj = gl.projects.get(template_repository_id)
    temp_http_url = template_pj.http_url_to_repo
    protocol = 'https' if temp_http_url[:5] == "https" else 'http'
    if protocol == "https":
        secret_temp_http_url = temp_http_url[:
                                             8] + f"root:{gitlab_private_token}@" + temp_http_url[
            8:]
    else:
        secret_temp_http_url = temp_http_url[:
                                             7] + f"root:{gitlab_private_token}@" + temp_http_url[
            7:]
    pipe_json = __tm_get_git_pipline_json(template_pj, tag_name=tag_name)
    tag_info_dict = __tm_get_tag_info(template_pj, tag_name)
    pipe_yaml_file_name = __tm_get_pipe_yamlfile_name(template_pj,
                                                      tag_name=tag_name)
    pip_set_json = __tm_read_pipe_set_json(template_pj, tag_name)

    pj = gl.projects.get(user_repository_id)
    pj_http_url = pj.http_url_to_repo
    protocol = 'https' if pj_http_url[:5] == "https" else 'http'
    if protocol == "https":
        secret_pj_http_url = pj_http_url[:
                                         8] + f"root:{gitlab_private_token}@" + pj_http_url[
            8:]
    else:
        secret_pj_http_url = pj_http_url[:
                                         7] + f"root:{gitlab_private_token}@" + pj_http_url[
            7:]
    Path("pj_push_template").mkdir(exist_ok=True)
    subprocess.call([
        'git', 'clone', '--branch', tag_info_dict["tag_name"],
        secret_temp_http_url, f"pj_push_template/{pj.path}"
    ])
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
                                    fun_value["answers"][
                                        ans_key] = template_replace_dict[
                                            ans_key]
                                # Replace by pipeline_settings.json default value
                                if "arguments" in pip_set_json:
                                    for argument in pip_set_json["arguments"]:
                                        if "default_value" in argument and argument[
                                                "key"] == ans_key:
                                            fun_value["answers"][
                                                ans_key] = argument[
                                                    "default_value"]
                                # Replace by user input parameter.
                                if arguments is not None and ans_key in arguments:
                                    for arg_key, arg_value in arguments.items(
                                    ):
                                        if arg_key is not None and ans_key == arg_key:
                                            fun_value["answers"][
                                                ans_key] = arg_value
                        elif fun_key == "envFrom":
                            pass
                        else:
                            for parm_key in fun_value.keys():
                                if parm_key in template_replace_dict:
                                    fun_value[
                                        parm_key] = template_replace_dict[
                                            parm_key]
            stage = __update_stage_when_plugin_disable(stage)
    with open(f'pj_push_template/{pj.path}/{pipe_yaml_file_name}',
              'w') as file:
        yaml.dump(pipe_json, file, sort_keys=False)
    __set_git_username_config(f"pj_push_template/{pj.path}")
    subprocess.call(['git', 'branch'], cwd=f"pj_push_template/{pj.path}")
    # Too lazy to handle file deleting issue on Windows, just keep the garbage there
    try:
        shutil.rmtree(f'pj_push_template/{pj.path}/.git')
    except PermissionError:
        pass
    subprocess.call(['git', 'init'], cwd=f"pj_push_template/{pj.path}")
    subprocess.call(['git', 'remote', 'add', 'origin', secret_pj_http_url],
                    cwd=f"pj_push_template/{pj.path}")
    subprocess.call(['git', 'add', '.'], cwd=f"pj_push_template/{pj.path}")
    subprocess.call(['git', 'commit', '-m', '"範本 commit"'],
                    cwd=f"pj_push_template/{pj.path}")
    subprocess.call(['git', 'push', '-u', 'origin', 'master'],
                    cwd=f"pj_push_template/{pj.path}")
    # Too lazy to handle file deleting issue on Windows, just keep the garbage there
    try:
        shutil.rmtree(f"pj_push_template/{pj.path}", ignore_errors=True)
    except PermissionError:
        pass


def tm_get_pipeline_branches(repository_id):
    out = {}
    pj = gl.projects.get(repository_id)
    stages_info = tm_get_pipeline_default_branch(repository_id, is_default_branch=False)

    for br in pj.branches.list(all=True):
        for yaml_stage in stages_info["stages"]:
            if br.name not in out:
                out[br.name] = {
                    "commit_message": br.commit["message"],
                    "commit_time": br.commit["created_at"],
                }
                if "testing_tools" not in out[br.name]:
                    out[br.name]["testing_tools"] = []
            soft_key_and_status = {
                "key": yaml_stage["key"],
                "name": yaml_stage["name"],
                "enable": "branches" in yaml_stage and br.name in yaml_stage["branches"]
            }
            out[br.name]["testing_tools"].append(soft_key_and_status)

    return out


def tm_put_pipeline_branches(repository_id, data):
    pj = gl.projects.get(repository_id)
    if __check_git_project_is_empty(pj):
        return
    for br in pj.branches.list(all=True):
        create_time = datetime.now().strftime("%y%m%d_%H%M%S")
        __tm_git_clone_file(pj, "pj_edit_pipe_yaml", create_time, br.name)
        pipe_yaml_file_name = __tm_get_pipe_yamlfile_name(pj)
        if pipe_yaml_file_name is None:
            return
        with open(
                f'pj_edit_pipe_yaml/{pj.path}_{create_time}/{pipe_yaml_file_name}'
        ) as file:
            pipe_json = yaml.safe_load(file)
            for stage in pipe_json["stages"]:
                catalogTemplate_value = stage.get("steps")[0].get(
                    "applyAppConfig", {}).get("catalogTemplate")
                if catalogTemplate_value is not None:
                    catalogTemplate_value = catalogTemplate_value.split(
                        ":")[1].replace("iii-dev-charts3-", "")
                for input_branch, multi_software in data.items():
                    for input_soft_enable in multi_software:
                        if catalogTemplate_value is not None and input_soft_enable[
                                "key"] == catalogTemplate_value:
                            if "when" not in stage:
                                stage["when"] = {"branch": {"include": []}}
                            stage_when = stage.get("when", {}).get(
                                "branch", {}).get("include", {})
                            if input_soft_enable[
                                    "enable"] and input_branch not in stage_when:
                                stage_when.append(input_branch)
                            elif input_soft_enable[
                                    "enable"] is False and input_branch in stage_when:
                                stage_when.remove(input_branch)
                            if len(stage_when) == 0:
                                stage_when.append("skip")
        with open(
                f'pj_edit_pipe_yaml/{pj.path}_{create_time}/{pipe_yaml_file_name}',
                'w') as file:
            yaml.dump(pipe_json, file, sort_keys=False)
        __set_git_username_config(f'pj_edit_pipe_yaml/{pj.path}_{create_time}')
        subprocess.call([
            'git', 'commit', '-m', '"編輯 .rancher-pipeline.yaml 啟用停用分支"',
            f'{pipe_yaml_file_name}'
        ],
            cwd=f"pj_edit_pipe_yaml/{pj.path}_{create_time}")
        next_run = pipeline.get_pipeline_next_run(repository_id)
        subprocess.call(['git', 'push', '-u', 'origin', f'{br.name}'],
                        cwd=f"pj_edit_pipe_yaml/{pj.path}_{create_time}")
        shutil.rmtree(f"pj_edit_pipe_yaml/{pj.path}_{create_time}",
                      ignore_errors=True)
        pipeline.stop_and_delete_pipeline(repository_id, next_run)


def tm_get_pipeline_default_branch(repository_id, is_default_branch=True):
    pj = gl.projects.get(repository_id)
    if __check_git_project_is_empty(pj):
        return {}
    default_branch = pj.default_branch
    pipe_yaml_name = __tm_get_pipe_yamlfile_name(pj, branch_name=default_branch)
    f = rs_gitlab.gl_get_file_from_lib(repository_id, pipe_yaml_name, branch_name=default_branch)
    pipe_dict = yaml.safe_load(f.decode())
    stages_info = {"default_branch": default_branch, "stages": []}
    for stage in pipe_dict["stages"]:
        tool = None
        stage_out_list = {"has_default_branch": False}
        if stage.get("iiidevops") is not None:
            __add_plugin_soft_status_json()
            tool = stage["iiidevops"]
            for software in support_software_json:
                if software["template_key"] == tool and (software.get("plugin_disabled") is False or tool == "deployed-environments"):
                    stage_out_list["name"] = software["display"]
                    stage_out_list["key"] = software["template_key"]
                    if "when" in stage:
                        stage_when = pipeline_yaml_OO.RancherPipelineWhen(stage["when"]["branch"])
                        if is_default_branch:
                            stage_out_list["has_default_branch"] = pj.default_branch in stage_when.branch.include
                        else:
                            stage_out_list["branches"] = stage_when.branch.include
                    if stage_out_list not in stages_info["stages"]:
                        stages_info["stages"].append(stage_out_list)
                    break
        else:
            __add_plugin_soft_status()
            catalogTemplate_value = stage.get("steps")[0].get(
                "applyAppConfig", {}).get("catalogTemplate")
            if catalogTemplate_value is not None:
                catalogTemplate_value = catalogTemplate_value.split(
                    ":")[1].replace("iii-dev-charts3-", "")
                for software in support_software:
                    if software["template_key"] == catalogTemplate_value and \
                            (catalogTemplate_value in ('web', 'db') or software.get("plugin_disabled") is False):
                        stage_out_list["name"] = software["display"]
                        stage_out_list["key"] = software["template_key"]
                        if "when" in stage:
                            stage_when = pipeline_yaml_OO.RancherPipelineWhen(stage["when"]["branch"])  
                            if is_default_branch:
                                stage_out_list["has_default_branch"] = pj.default_branch in stage_when.branch.include
                            else:
                                stage_out_list["branches"] = stage_when.branch.include
                        stages_info["stages"].append(stage_out_list)
                        break
    return stages_info


def tm_put_pipeline_default_branch(repository_id, data):
    pj = gl.projects.get(repository_id)
    if __check_git_project_is_empty(pj):
        return
    for br in pj.branches.list(all=True):
        pipe_yaml_file_name = __tm_get_pipe_yamlfile_name(pj)
        if pipe_yaml_file_name is None:
            return
        f = rs_gitlab.gl_get_file_from_lib(repository_id, pipe_yaml_file_name, branch_name=br.name)
        pipe_json = yaml.safe_load(f.decode())
        for stage in pipe_json["stages"]:
            if stage.get("iiidevops") is not None:
                catalogTemplate_value = stage["iiidevops"]
            else:
                catalogTemplate_value = stage.get("steps")[0].get("applyAppConfig", {}).get("catalogTemplate")
                if catalogTemplate_value is not None:
                    catalogTemplate_value = catalogTemplate_value.split(":")[1].replace("iii-dev-charts3-", "")
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
                    else:
                        if "skip" in stage_when:
                            stage_when.remove("skip")

        next_run = pipeline.get_pipeline_next_run(repository_id)
        f.content = yaml.dump(pipe_json, sort_keys=False)
        f.save(branch=br.name,
               commit_message='UI 編輯 .rancher-pipeline.yaml commit')
        pipeline.stop_and_delete_pipeline(repository_id, next_run)


def disable_soft_branch_at_project(repository_id, soft_name):
    template_key = None
    for software in support_software:
        if software.get('plugin_key') == soft_name:
            template_key = software.get('template_key')
    if template_key is None:
        return
    pj = gl.projects.get(repository_id)
    if pj.empty_repo:
        return
    for br in pj.branches.list(all=True):
        pipe_yaml_name = __tm_get_pipe_yamlfile_name(pj, branch_name=br.name)
        if pipe_yaml_name is None:
            continue
        f = rs_gitlab.gl_get_file_from_lib(repository_id, pipe_yaml_name, branch_name=br.name)
        pipe_dict = yaml.safe_load(f.decode())
        stages = pipe_dict.get("stages")
        stage_index = __get_step_index_from_pipe(stages, template_key)
        if stage_index is None:
            continue
        if "when" not in stages[stage_index]:
            stages[stage_index]["when"] = {"branch": {"include": []}}
        stage_when = stages[stage_index].get("when",
                                             {}).get("branch",
                                                     {}).get("include", {})
        if len(stage_when) == 1 and 'skip' in stage_when:
            continue
        stage_when.clear()
        stage_when.append("skip")
        '''
        next_run = pipeline.get_pipeline_next_run(repository_id)
        f.content = yaml.dump(pipe_dict)
        f.save(branch=br.name,
               commit_message=f'Update branch {br.name} .rancher-pipeline.yml, remove stage {soft_name} enable branch')
        pipeline.stop_and_delete_pipeline(repository_id, next_run)
        '''


def __get_step_index_from_pipe(stages, soft_key):
    if stages is None:
        return
    for index, stage in enumerate(stages):
        catalogTemplate_value = stage.get("steps")[0].get(
            "applyAppConfig", {}).get("catalogTemplate")
        if catalogTemplate_value is not None:
            catalogTemplate_value = catalogTemplate_value.split(
                ":")[1].replace("iii-dev-charts3-", "")
            if catalogTemplate_value == soft_key:
                return index


def update_project_rancher_pipline():
    projects = Project.query.all()
    project_id_list = [pj.id for pj in projects]
    project_id_list.remove(-1)
    for pj_id in project_id_list:
        logger.logger.info(f'project_id : {pj_id}')
        repository_id = nexus.nx_get_repository_id(pj_id)
        pj = gl.projects.get(repository_id)
        if pj.empty_repo:
            continue
        for br in pj.branches.list(all=True):
            try:
                pipe_yaml_name = __tm_get_pipe_yamlfile_name(pj, branch_name=br.name)
                f = rs_gitlab.gl_get_file_from_lib(repository_id, pipe_yaml_name, branch_name=br.name)
                pipe_dict = yaml.safe_load(f.decode())
                temp_list = []
                for info in pipe_dict["stages"]:
                    info_name = info["name"] 
                    logger.logger.info(f'name : {info_name}')
                    if info.get("iiidevops") is None:
                        temp_dict = {"name": info.pop("name")}
                        if info_name.startswith("Test--SonarQube for Java"):
                            temp_dict["iiidevops"] = "sonarqube"
                            temp_dict.update(info)
                            info = temp_dict
                        else:    
                            catalog_template_value = info["steps"][0].get("applyAppConfig", {}).get("catalogTemplate")
                            if catalog_template_value is not None:
                                catalog_template_value = catalog_template_value.split(
                                    ":")[1].replace("iii-dev-charts3-", "")
                                if catalog_template_value == "web":
                                    catalog_template_value = "deployed-environments"  
                                else:
                                    for prefix in ["test-", "scan-"]:
                                        if catalog_template_value.startswith(prefix):
                                            catalog_template_value = catalog_template_value.replace(prefix, "")
                                            break
                            else:
                                catalog_template_value = "deployed-environments"
                            temp_dict["iiidevops"] = catalog_template_value
                            temp_dict.update(info)
                            info = temp_dict

                    temp_list.append(info)
                pipe_dict["stages"] = temp_list
            except Exception as e:
                logger.logger.info(str(e))
                continue

            next_run = pipeline.get_pipeline_next_run(repository_id)
            f.content = yaml.dump(pipe_dict, sort_keys=False)
            f.save(branch=br.name,
                   commit_message=f'Add "iiidevops" in branch {br.name} .rancher-pipeline.yml.')
            logger.logger.info(f'{pj_id} update completely')
            pipeline.stop_and_delete_pipeline(repository_id, next_run)


# --------------------- Resources ---------------------
class TemplateList(Resource):
    @jwt_required
    def get(self):
        role.require_pm("Error while getting template list.")
        parser = reqparse.RequestParser()
        parser.add_argument('force_update', type=int)
        args = parser.parse_args()
        return util.success(tm_get_template_list(args["force_update"]))


class TemplateListForCronJob(Resource):

    def get(self):
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
