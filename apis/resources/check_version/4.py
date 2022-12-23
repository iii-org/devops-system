import config
# Runner answer & version
RUNNER_VERSION_MAPPING = {"checkmarx": {
        "version": "0.2.2"
    }}

# Image version
IMAGE_VERSION_MAPPING = {}

# Stages
SCAN_DOCKER_IMAGE = [{
    "name": "Test--Anchore SBOM",
    "iiidevops": "anchore",
    "steps": [
      {
        "applyAppConfig": {
          "answers": {
            "git.branch": "${CICD_GIT_BRANCH}",
            "git.commitID": "${CICD_GIT_COMMIT}",
            "git.repoName": "${CICD_GIT_REPO_NAME}",
            "git.url": "${CICD_GIT_URL}",
            "harbor.host": config.get("HARBOR_EXTERNAL_BASE_URL").split("://")[1],
            "pipeline.sequence": "${CICD_EXECUTION_SEQUENCE}",
            "anchore.image": "${CICD_GIT_REPO_NAME}/${CICD_GIT_BRANCH}:${CICD_GIT_COMMIT}"
          },
          "catalogTemplate": "cattle-global-data:iii-dev-charts3-scan-anchore",
          "name": "${CICD_GIT_REPO_NAME}-${CICD_GIT_BRANCH}-sbom",
          "targetNamespace": "${CICD_GIT_REPO_NAME}",
          "version": "0.0.1"
        }
      }
    ],
    "when": {
      "branch": {
        "include": [
          "master"
        ]
      }
    }
  }
]

API_VERSION = "1.24.0"


def extra_func(pipe_stages, change):
    from copy import deepcopy
    pipe_stages_copy = deepcopy(pipe_stages)

    for pipe_stage in pipe_stages_copy:
        if pipe_stage.get("iiidevops") == "deployed-environments":
            index = pipe_stages.index(pipe_stage)
            if pipe_stages[index + 1].get("iiidevops") != "deployed-environments":
                pipe_stages.insert(index + 1, SCAN_DOCKER_IMAGE[0])
                change = True
                break
    return pipe_stages, change
