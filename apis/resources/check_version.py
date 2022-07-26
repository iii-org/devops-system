from model import Project, db, ProjectPluginRelation
from resources.template import gl
from resources import logger
from resources.gitlab import gitlab 
from resources import pipeline
import yaml
from time import sleep



COMMON_ANSWERS = {
    "git.branch": "${CICD_GIT_BRANCH}",
    "git.commitID": "${CICD_GIT_COMMIT}",
    "git.repoName": "${CICD_GIT_REPO_NAME}",
    "git.url": "${CICD_GIT_URL}",
    "pipeline.sequence": "${CICD_EXECUTION_SEQUENCE}"
}

WEB_ANSWERS = {
    "web.deployName": "${CICD_GIT_REPO_NAME}-${CICD_GIT_BRANCH}-serv",
    "web.port": 80
}


VERSION_MAPPING = {
    "checkmarx": {
       "answer": COMMON_ANSWERS,
       "version": "0.2.2"
    },
    "zap": {
        "answer": COMMON_ANSWERS | WEB_ANSWERS, 
        "version": "0.2.3"
    },
    "sideex": {
        "answer": COMMON_ANSWERS | WEB_ANSWERS,
        "version": "0.3.2"
    },
    "postman": {
        "answer": COMMON_ANSWERS | WEB_ANSWERS,
        "version": "0.3.3"
    }
}

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
                "image": "iiiorg/rancher-cli:v2.4.6",
                "shellScript": "curl --location -s --request POST ${api_origin}/rancher/delete_app --form project_name=${CICD_GIT_REPO_NAME} --form branch_name=${CICD_GIT_BRANCH} && curl --location -s --request POST ${api_origin}/project/issues_commit_by_name --form project_name=${CICD_GIT_REPO_NAME}"
            }
        }
    ]
}]


def get_default_file_path(pj):
    for item in pj.repository_tree(ref=pj.default_branch):
        if item["path"] == ".rancher-pipeline.yml":
            file_path = ".rancher-pipeline.yml"
        elif item["path"] == ".rancher-pipeline.yaml":
            file_path = ".rancher-pipeline.yaml"
    return file_path


def update_pipieline_file(version_mapping=None):
    '''
    version_mapping => {"{server}": {"answer": {pipeline_answer}, "version": "0,2,2"}}
    '''
    if version_mapping is None:
        version_mapping = VERSION_MAPPING
    project_rows = db.session.query(Project, ProjectPluginRelation).join(
            ProjectPluginRelation, Project.id==ProjectPluginRelation.project_id).all()
    gl_pj_ids = [
        project_row.ProjectPluginRelation.git_repository_id for project_row in project_rows] 

    logger.logger.info(f"Updating version_mapping {version_mapping}")
    for gl_pj_id in gl_pj_ids:
        try:
            pj = gl.projects.get(gl_pj_id)
            if pj.empty_repo:
                continue
            default_branch = pj.default_branch
            file_path = get_default_file_path(pj)

            f = gitlab.gl_get_file_from_lib(gl_pj_id, file_path)
            pipe_dict = yaml.safe_load(f.decode())
            pipe_stages = pipe_dict.get("stages")
            if pipe_stages is None:
                continue
            
            change = False
            logger.logger.info(f"Start updating {gl_pj_id} tool version in branch({default_branch}).")
            if pipe_stages[0].get("iiidevops") != "initial-pipeline":
                pipe_stages = INITIAL_PIPELINE + pipe_stages
                change = True

            for pipe_stage in pipe_stages:
                iii_stage = version_mapping.get(pipe_stage.get("iiidevops"))
                if iii_stage is not None:
                    pipe_stage_step = pipe_stage["steps"][0]
                    pipe_stage_step_config = pipe_stage_step.get("applyAppConfig", {})

                    if pipe_stage_step_config["version"] == iii_stage["version"]:
                        continue
                    pipe_stage_step_config["answers"] = iii_stage["answer"] | pipe_stage_step_config.get("answers", {})
                    pipe_stage_step_config["version"] = iii_stage["version"]
                    change = True

            if change:
                next_run = pipeline.get_pipeline_next_run(gl_pj_id)
                pipe_dict["stages"] = pipe_stages
                f.content = yaml.dump(pipe_dict, sort_keys=False)
                f.save(
                    branch=default_branch,
                    author_email='system@iiidevops.org.tw',
                    author_name='iiidevops',
                    commit_message="Testing tool runner version update.")
                pipeline.stop_and_delete_pipeline(gl_pj_id, next_run, branch=default_branch)
                sleep(30)

            logger.logger.info(f"Change: {change}")
            logger.logger.info(f"Updating {gl_pj_id} tool version in branch({default_branch}) done.")
        except Exception as e:
            logger.logger.exception(f"Gitlab project id: {gl_pj_id} has exception message ({str(e)})")
            continue
    



