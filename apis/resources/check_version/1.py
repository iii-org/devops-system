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

API_VERSION = "1.19"

def extra_func(pipe_stages, change):
    if pipe_stages[0].get("iiidevops") != "initial-pipeline":
        pipe_stages = INITIAL_PIPELINE + pipe_stages
        change = True
    elif pipe_stages[0].get("iiidevops") == "initial-pipeline" and pipe_stages[0] != INITIAL_PIPELINE[0]:
        pipe_stages = INITIAL_PIPELINE + pipe_stages[1:]
        change = True
    return pipe_stages, change