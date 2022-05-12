import json
import os
import subprocess
import time
from datetime import datetime
from pathlib import Path

import nexus
from flask_jwt_extended import get_jwt_identity
from model import TemplateProject, db

from . import (gl, set_git_username_config, tm_get_secret_url,
               tm_git_commit_push)

TEMPLATE_FOLDER_NAME = "template_from_pj"


def create_template_from_project(from_project_id, name, description):
    '''
    1. Create a empty project in local-template group\
    2. Add old project user join to this template project
    3. Git clone old project in to local folder
    4. Edit pipeline_settings.json, replace name and description.
    5. Commit and push all file to template project
    6. Update template_project table.
    '''

    old_project = gl.projects.get(nexus.nx_get_project_plugin_relation(
        nexus_project_id=from_project_id).git_repository_id)
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
    if name is not None or description is not None:
        tm_update_pipe_set_json_from_local(template_project.path, name, description)
    set_git_username_config(f'{TEMPLATE_FOLDER_NAME}/{template_project.path}')
    tm_git_commit_push(template_project.path, temp_pj_secret_http_url,
                       TEMPLATE_FOLDER_NAME, f"專案 {old_project.path} 轉範本commit")
    tm = TemplateProject(template_repository_id=template_project.id, from_project_id=old_project.id,
                         creator_id=get_jwt_identity()["user_id"], created_at=datetime.utcnow(),
                         updated_at=datetime.utcnow())
    db.session.add(tm)
    db.session.commit()


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
