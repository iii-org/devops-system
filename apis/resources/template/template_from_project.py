import json
import subprocess
import time
from datetime import datetime
from pathlib import Path

from flask_jwt_extended import get_jwt_identity
from model import Project, TemplateProject, db
from nexus import (nx_get_project_plugin_relation, nx_get_user,
                   nx_get_user_plugin_relation, nx_get_project)
from resources import apiError, role

from . import (gl, set_git_username_config, tm_get_secret_url,
               tm_git_commit_push)

TEMPLATE_FOLDER_NAME = "template_from_pj"


def verify_user_in_template_project(id):
    repo_id = TemplateProject.query.filter_by(id=id).first().template_repository_id
    repo_user_id = nx_get_user_plugin_relation(user_id=get_jwt_identity()['user_id']).repository_user_id
    repo = gl.projects.get(repo_id)
    for member in repo.members.list(all=True):
        if member.id == repo_user_id:
            return True
    raise apiError.DevOpsError(401, "User not in this template gitlab repository",
                               error=apiError.template_user_not_in_template_gitlab_repo(repo_id,
                                                                                        get_jwt_identity()['user_id']))


def template_from_project_list():
    all_templates = get_tm_filter_by_tm_member()
    out_list = []
    for template in all_templates:
        template = json.loads(str(template))
        gl_template = gl.projects.get(template['template_repository_id'])
        template['template_repository_url'] = gl_template.http_url_to_repo
        if template['creator_id'] is not None:
            template['creator_name'] = nx_get_user(id=template['creator_id']).name
        template['times_cited'] = Project.query.filter_by(base_example=gl_template.path).count()
        try:
            gl_from_pj = gl.projects.get(nx_get_project_plugin_relation(
                nexus_project_id=template['from_project_id']).git_repository_id)
            template['the_last_update_time'] = gl_from_pj.commits.list()[0].created_at
            template['from_project_repo_url'] = gl_from_pj.http_url_to_repo
        except apiError.DevOpsError:
            template['the_last_update_time'] = None
        out_list.append(template)
    return out_list


def update_template(id, name, description):
    '''
    *. delete old template
    *. create a new one template
    *. update table
    '''
    row = TemplateProject.query.filter_by(id=id).one()
    try:
        gl.projects.delete(row.template_repository_id)
        time.sleep(2)
    except:
        pass
    new_template_project, old_project, pipe_json_temp_name = update_pipe_set_and_push_to_new_project(
        row.from_project_id, name, description)
    row.template_repository_id = new_template_project.id
    row.template_repository_name = pipe_json_temp_name
    row.creator_id = get_jwt_identity()['user_id']
    row.updated_at = datetime.utcnow()
    row.from_project_name = nx_get_project(id=row.from_project_id).display
    db.session.commit()


def update_pipe_set_and_push_to_new_project(from_project_id, name, description):
    '''
    *. compare name and description, if it was been edit, edit old project.
    1. Create a empty project in local-template group\
    2. Add old project user join to this template project
    3. Git clone old project in to local folder
    4. Edit pipeline_settings.json, replace name and description.
    5. Commit and push all file to template project
    '''
    old_project = gl.projects.get(nx_get_project_plugin_relation(
        nexus_project_id=from_project_id).git_repository_id)
    pipe_json_temp_name = tm_update_pipe_set_json_from_api(old_project, name, description)

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
    return template_project, old_project, pipe_json_temp_name


def create_template_from_project(from_project_id, name, description):
    # if template already exist, call update template function
    row = TemplateProject.query.filter_by(from_project_id=from_project_id).first()
    if row:
        update_template(row.id, name, description)
        return {"id": row.id}

    # 6. Update template_project table.
    template_project, old_project, pipe_json_temp_name = update_pipe_set_and_push_to_new_project(
        from_project_id, name, description)
    tm = TemplateProject(template_repository_id=template_project.id, template_repository_name=pipe_json_temp_name,
                         from_project_id=from_project_id, from_project_name=nx_get_project(id=from_project_id).display,
                         creator_id=get_jwt_identity()["user_id"],
                         created_at=datetime.utcnow(), updated_at=datetime.utcnow())
    db.session.add(tm)
    db.session.commit()
    return {"id": tm.id}


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


def delete_template(id):
    row = TemplateProject.query.filter_by(id=id).one()
    gl.projects.delete(row.template_repository_id)
    db.session.delete(row)
    db.session.commit()
    time.sleep(1)


def tm_update_pipe_set_json_from_api(pj, name, description):
    if pj.empty_repo:
        return
    f = pj.files.get(file_path="iiidevops/pipeline_settings.json", ref=pj.default_branch)
    pip_set_json = json.loads(f.decode())
    if (name is not None or description is not None) and (
            pip_set_json.get('name') != name or pip_set_json.get('description') != description):
        if name is not None and pip_set_json.get('name') != name:
            pip_set_json['name'] = name
        if description is not None and pip_set_json.get('description') != description:
            pip_set_json['description'] = description
        f.content = json.dumps(pip_set_json)
        f.save(
            branch=pj.default_branch,
            author_email='system@iiidevops.org.tw',
            author_name='iiidevops',
            commit_message=f"{get_jwt_identity()['user_account']} 編輯 {pj.default_branch} 分支 \
                    iiidevops/pipeline_settings.json")
    return pip_set_json['name']


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
