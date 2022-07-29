from model import Project, db, ProjectPluginRelation
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


# Runner answer & version
COMMON_RUNNER_ANSWERS = {
    "git.branch": "${CICD_GIT_BRANCH}",
    "git.commitID": "${CICD_GIT_COMMIT}",
    "git.repoName": "${CICD_GIT_REPO_NAME}",
    "git.url": "${CICD_GIT_URL}",
    "pipeline.sequence": "${CICD_EXECUTION_SEQUENCE}"
}

RUNNER_WEB_ANSWERS = {
    "web.deployName": "${CICD_GIT_REPO_NAME}-${CICD_GIT_BRANCH}-serv",
    "web.port": 80
}


RUNNER_VERSION_MAPPING = {
    "checkmarx": {
       "answer": COMMON_RUNNER_ANSWERS,
       "version": "0.2.2"
    },
    "zap": {
        "answer": COMMON_RUNNER_ANSWERS | RUNNER_WEB_ANSWERS, 
        "version": "0.2.3"
    },
    "sideex": {
        "answer": COMMON_RUNNER_ANSWERS | RUNNER_WEB_ANSWERS,
        "version": "0.3.2"
    },
    "postman": {
        "answer": COMMON_RUNNER_ANSWERS | RUNNER_WEB_ANSWERS,
        "version": "0.3.3"
    }
}

# Image version
IMAGE_VERSION_MAPPING = {
    "rancher-cli": "1.0.1" 
}


# Stages
INITIAL_PIPELINE = [{
    "name": "Integration--initial pipeline",
    "iiidevops": "initial-pipeline",
    "steps": [
        {
            "envFrom": [
                {
                    "sourceKey": "api-origin",
                    "sourceName": "nexus",
                    "targetKey": "api_origin"
                }
            ],
            "runScriptConfig": {
                "image": "iiiorg/rancher-cli:1.0.1",
                "shellScript": "curl --location -s --request POST ${api_origin}/rancher/delete_app --form project_name=${CICD_GIT_REPO_NAME} --form branch_name=${CICD_GIT_BRANCH} && curl --location -s --request POST ${api_origin}/project/issues_commit_by_name --form project_name=${CICD_GIT_REPO_NAME} && count-src.pl"
            }
        }
    ]
}]

# Black and white project list default format
DEFAULT_FORMAT = {
    "white_list": [],
    "black_list": []
}


def check_project_list_file_exist():
    '''
    ret = {"white_list": [{repo_name}, {repo_name}], "black_list": []}
    '''
    path = "devops-data/config/B&W.json"
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


def update_pipieline_file(runner_version_mapping=None, image_version_mapping=None):
    '''
    runner_version_mapping => {"{server}": {"answer": {pipeline_answer}, "version": "0,2,2"}}
    '''
    runner_version_mapping = RUNNER_VERSION_MAPPING or runner_version_mapping
    image_version_mapping = IMAGE_VERSION_MAPPING or image_version_mapping

    project_repo_names = check_project_list_file_exist().get("white_list", [])
    if project_repo_names == []:
        project_rows = db.session.query(Project, ProjectPluginRelation).join(
                ProjectPluginRelation, Project.id==ProjectPluginRelation.project_id).all()
        gl_pj_ids = [project_row.ProjectPluginRelation.git_repository_id for project_row in project_rows]
    else:
        gl_pj_ids = list(map(lambda x: get_pj_id_by_name(x)["repo_id"], project_repo_names))

    logger.logger.info(f"Updating runner_version_mapping {runner_version_mapping}, image_version_mapping {image_version_mapping}")
    for gl_pj_id in gl_pj_ids:
        pj = gl.projects.get(gl_pj_id)
        if pj.empty_repo:
            logger.logger.info(f"{gl_pj_id} is empty project.")
            continue

        file_path = get_default_file_path(pj)
        if file_path is None:
            logger.logger.info(f"{gl_pj_id} does not have pipeline.yml file.")
            continue
        
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
                # Update stage 
                if pipe_stages[0].get("iiidevops") != "initial-pipeline":
                    pipe_stages = INITIAL_PIPELINE + pipe_stages
                    change = True
                elif pipe_stages[0].get("iiidevops") == "initial-pipeline" and pipe_stages[0] != INITIAL_PIPELINE[0]:
                    pipe_stages = INITIAL_PIPELINE + pipe_stages[1:]
                    change = True

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
                        commit_message="Ugrade rancher-pipeline.yml's tools and images version.")
                    pipeline.stop_and_delete_pipeline(gl_pj_id, next_run, branch=branch) 
                    sleep(30)

                logger.logger.info(f"Change: {change}")
                logger.logger.info(f"Updating {gl_pj_id} tool version in branch({branch}) done.")
            except Exception as e:
                logger.logger.exception(f"Gitlab project id: {gl_pj_id} in branch({branch}) has exception message ({str(e)})")
                continue



