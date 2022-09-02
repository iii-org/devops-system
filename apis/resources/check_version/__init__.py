from model import Project, db, ProjectPluginRelation, PipelineUpdateVersion
from resources.template import gl
from resources import logger
from resources.gitlab import gitlab 
from resources import pipeline
import yaml
import os
from pathlib import Path
from time import sleep
import json
from resources.project import get_pj_id_by_name
import importlib
from datetime import datetime


# Black and white project list default format
DEFAULT_FORMAT = {
    "white_list": [],
    "black_list": []
}

# Latest version
LATEST_VERSION = 3


def get_project_pipeline_version(pj_id):
    version = 1
    pj_pipe_version = PipelineUpdateVersion.query.filter_by(project_id=pj_id).first()
    if pj_pipe_version is None:
        row = PipelineUpdateVersion(
            project_id=pj_id,
            version=version
        )
        db.session.add(row)
        db.session.commit()
        return {"status": None, "version": version}
    return {"status": pj_pipe_version.status, "version": pj_pipe_version.version}


def update_project_pipeline_version(pj_id, version=None, status=None, message=None):
    row = PipelineUpdateVersion.query.filter_by(project_id=pj_id).first()
    if version is not None:
        row.version = version
    if status is not None:
        row.status = status
    if message is not None:
        row.message = message
    row.updated_at = datetime.utcnow()
    db.session.commit()


def check_project_list_file_exist():
    '''
    ret = {"white_list": [{repo_name}, {repo_name}], "black_list": []}
    '''
    path = "devops-data/config/black_white_projects.json"
    if not os.path.isfile(path):
        Path("devops-data/config").mkdir(parents=True, exist_ok=True)
        with open(path, 'w') as w:
            w.write(json.dumps(DEFAULT_FORMAT))
        ret = DEFAULT_FORMAT
    else:
        with open(path, 'r') as r:
            ret = json.loads(r.read())
    return ret


def get_default_file_path(pj):
    file_path = None
    for item in pj.repository_tree(ref=pj.default_branch):
        if item["path"] == ".rancher-pipeline.yml":
            file_path = ".rancher-pipeline.yml"
        elif item["path"] == ".rancher-pipeline.yaml":
            file_path = ".rancher-pipeline.yaml"
    return file_path



def update_pipeline():
    project_repo_names = check_project_list_file_exist().get("white_list", [])
    if project_repo_names == []:
        project_rows = db.session.query(Project, PipelineUpdateVersion).join(
                PipelineUpdateVersion, Project.id==PipelineUpdateVersion.project_id).all()
        pj_id_version_mapping = {project_row.Project.id: project_row.PipelineUpdateVersion.version for project_row in project_rows}
    else:
        pj_ids = list(map(lambda x: get_pj_id_by_name(x)["id"], project_repo_names))
        pj_id_version_mapping = {pj_id: get_project_pipeline_version(pj_id)["version"] for pj_id in pj_ids}

    for pj_id, pj_pipe_version in pj_id_version_mapping.items():
        update_pipeline_execute(pj_id, pj_pipe_version)


def update_pipeline_execute(pj_id, pj_pipe_version):
    update_pipieline_file(pj_id, pj_pipe_version)
    if get_project_pipeline_version(pj_id)["status"] == "Failure":
        return 

    if pj_pipe_version < LATEST_VERSION:
        pj_pipe_version += 1
        update_project_pipeline_version(pj_id, version=pj_pipe_version, status="Success")
        update_pipeline_execute(pj_id, pj_pipe_version)
    elif pj_pipe_version == LATEST_VERSION:
        update_project_pipeline_version(pj_id, status="Success")
        return 


def update_pipieline_file(pj_id, version):
    gl_pj_id = ProjectPluginRelation.query.filter_by(project_id=pj_id).one().git_repository_id
    version_pk = importlib.import_module(f"resources.check_version.{version}")
    runner_version_mapping = version_pk.RUNNER_VERSION_MAPPING
    image_version_mapping = version_pk.IMAGE_VERSION_MAPPING
    api_version = version_pk.API_VERSION
    extra_func = version_pk.extra_func if hasattr(version_pk, "extra_func") else None

    update_project_pipeline_version(pj_id, status="Running")

    pj = gl.projects.get(gl_pj_id)
    if pj.empty_repo:
        logger.logger.info(f"{gl_pj_id} is empty project.")
        return 

    file_path = get_default_file_path(pj)
    if file_path is None:
        logger.logger.info(f"{gl_pj_id} does not have pipeline.yml file.")
        return 

    logger.logger.info(f"Start updating version: {version}.")  
    default_branch = pj.default_branch
    for br in pj.branches.list(all=True):
        try:
            branch = br.name
            change = False

            f = gitlab.gl_get_file_from_lib(gl_pj_id, file_path, branch_name=branch)
            pipe_dict = yaml.safe_load(f.decode())
            pipe_stages = pipe_dict.get("stages")
            if pipe_stages is None:
                logger.logger.info(f"{gl_pj_id} pipeline.yml format is unexpected.")
                continue
            
            logger.logger.info(f"Start updating {gl_pj_id} tool and image version in branch({branch}).")
            # Run extra_func
            if extra_func is not None:
                pipe_stages, change = extra_func(pipe_stages, change)

            for pipe_stage in pipe_stages:
                pipe_stage_step = pipe_stage["steps"][0]
                
                # Update runner version mapping
                iii_stage = runner_version_mapping.get(pipe_stage.get("iiidevops"))
                if iii_stage is not None:
                    pipe_stage_app_config = pipe_stage_step.get("applyAppConfig")

                    if pipe_stage_app_config is not None and pipe_stage_app_config["version"] != iii_stage["version"]:
                        pipe_stage_app_config["answers"] = iii_stage["answer"] | pipe_stage_app_config.get("answers", {})
                        pipe_stage_app_config["version"] = iii_stage["version"]
                        change = True

                # Update image version mapping 
                pipe_stage_script_config = pipe_stage_step.get("runScriptConfig")
                if pipe_stage_script_config is not None:
                    temp = pipe_stage_script_config.get("image", "").split(":")
                    image_repo, image_tag = temp[0], temp[-1]
                    replace_image_tag = image_version_mapping.get(image_repo.split("/")[-1])
                    if replace_image_tag is not None and replace_image_tag != image_tag:
                        pipe_stage_script_config["image"] = f"{image_repo}:{replace_image_tag}"
                        change = True

            if change:
                next_run = pipeline.get_pipeline_next_run(gl_pj_id)
                pipe_dict["stages"] = pipe_stages
                f.content = yaml.dump(pipe_dict, sort_keys=False)
                f.save(
                    branch=branch,
                    author_email='system@iiidevops.org.tw',
                    author_name='iiidevops',
                    commit_message=f"Upgrade rancher-pipeline.yml's tools and images(API Version: {api_version}).")
                pipeline.stop_and_delete_pipeline(gl_pj_id, next_run, branch=branch) 
                sleep(30)

            logger.logger.info(f"Change: {change}")
            logger.logger.info(f"Updating {gl_pj_id} tool version in branch({branch}) done.")
        except Exception as e:
            error_msg = f"Gitlab project id: {gl_pj_id} in branch({branch}) has exception message ({str(e)})"
            logger.logger.exception(error_msg)

            if branch == default_branch:
                update_project_pipeline_version(pj_id, message=error_msg, status="Failure")
                return 
            else:
                update_project_pipeline_version(pj_id, message=error_msg)
                continue
