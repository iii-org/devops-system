import json
import os
import subprocess
import time
from datetime import datetime
from pathlib import Path

from nexus import nx_get_project_plugin_relation, nx_get_user_plugin_relation
from flask_jwt_extended import get_jwt_identity
from resources import role
from model import TemplateProject, db

from . import (gl, set_git_username_config, tm_get_secret_url,
               tm_git_commit_push)

TEMPLATE_FOLDER_NAME = "template_from_pj"


def template_from_project_list():
    all_templates = get_tm_filter_by_tm_member()
    print(all_templates)


def create_template_from_project(from_project_id, name, description):
    '''
    *. compare name and description, if it was been edit, edit old project.
    1. Create a empty project in local-template group\
    2. Add old project user join to this template project
    3. Git clone old project in to local folder
    4. Edit pipeline_settings.json, replace name and description.
    5. Commit and push all file to template project
    6. Update template_project table.
    '''

    old_project = gl.projects.get(nx_get_project_plugin_relation(
        nexus_project_id=from_project_id).git_repository_id)
    tm_update_pipe_set_json_from_api(old_project, name, description)

    '''
    # for test
    local_template_group = gl.groups.list(search='local-templates')[0]
    del_pjs = local_template_group.projects.list(search=old_project.path)
    if len(del_pjs) > 0:
        gl.projects.get(del_pjs[0].id).delete()
        time.sleep(2)
    '''

    local_template_group_id = gl.groups.list(search='local-templates')[0].id
    template_project = gl.projects.create({'name': f'{old_project.path}', 'namespace_id': local_template_group_id})

    members = old_project.members.list(all=True)
    for member in members:
        if 'project_bot' in member.username or 'root' in member.username:
            continue
        template_project.members.create({'user_id': member.id, 'access_level': member.access_level})

    old_secret_http_url = tm_get_secret_url(old_project)
    temp_pj_secret_http_url = tm_get_secret_url(template_project)
    Path(TEMPLATE_FOLDER_NAME).mkdir(exist_ok=True)
    subprocess.call(['git', 'clone', old_secret_http_url, f"{TEMPLATE_FOLDER_NAME}/{old_project.path}"])
    set_git_username_config(f'{TEMPLATE_FOLDER_NAME}/{template_project.path}')
    tm_git_commit_push(template_project.path, temp_pj_secret_http_url,
                       TEMPLATE_FOLDER_NAME, f"專案 {old_project.path} 轉範本commit")
    tm = TemplateProject(template_repository_id=template_project.id, from_project_id=old_project.id,
                         from_project_name=old_project.name, creator_id=get_jwt_identity()["user_id"],
                         created_at=datetime.utcnow(), updated_at=datetime.utcnow())
    db.session.add(tm)
    db.session.commit()
    return {"template_id": template_project.id}


'''
def tm_update_pipe_set_json_from_local(pj_path, name, description):
    Path(f'{TEMPLATE_FOLDER_NAME}/{pj_path}/iiidevops').mkdir(exist_ok=True)
    pipeline_settings_json = None
    if os.path.exists(f'{TEMPLATE_FOLDER_NAME}/{pj_path}/iiidevops/pipeline_settings.json'):
        with open(f'{TEMPLATE_FOLDER_NAME}/{pj_path}/iiidevops/pipeline_settings.json', encoding="utf-8") as f:
            pipeline_settings_json = json.loads(f.read())
            if name is not None:
                pipeline_settings_json['name'] = name
            if name is not None:
                pipeline_settings_json['description'] = description
        with open(f'{TEMPLATE_FOLDER_NAME}/{pj_path}/iiidevops/pipeline_settings.json', 'w') as f:
            json.dump(pipeline_settings_json, f)
'''


def tm_update_pipe_set_json_from_api(pj, name, description):
    if pj.empty_repo:
        return
    f = pj.files.get(file_path="iiidevops/pipeline_settings.json", ref=pj.default_branch)
    pip_set_json = json.loads(f.decode())
    if pip_set_json['name'] != name or pip_set_json['description'] != description:
        pip_set_json['name'] = name
        pip_set_json['description'] = description
        f.content = json.dumps(pip_set_json)
        f.save(
            branch=pj.default_branch,
            author_email='system@iiidevops.org.tw',
            author_name='iiidevops',
            commit_message=f"{get_jwt_identity()['user_account']} 編輯 {pj.default_branch} 分支 \
                iiidevops/pipeline_settings.json")


def get_tm_filter_by_tm_member():
    if get_jwt_identity()['role_id'] != role.ADMIN.id:
        belong_to_me_pj_ids = []
        git_user_id = nx_get_user_plugin_relation(user_id=get_jwt_identity()['user_id']).repository_user_id
        user = gl.users.get(git_user_id)
        memberships = user.memberships.list(type='Project')
        for membership in memberships:
            pj = gl.projects.get(membership.source_id)
            if pj.namespace['path'] == "local-templates":
                belong_to_me_pj_ids.append(pj.id)
        all_templates = TemplateProject.query.filter(
            TemplateProject.template_repository_id.in_(belong_to_me_pj_ids)).all()
    else:
        all_templates = TemplateProject.query.all()
    return all_templates
