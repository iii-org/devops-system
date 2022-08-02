
# Runner answer & version
RUNNER_VERSION_MAPPING = {}

# Image version
IMAGE_VERSION_MAPPING = {}

# Stages
SCAN_DOCKER_IMAGE = [{
    "name": "Build--Scan docker image",
    "iiidevops": "deployed-environments",
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
          "shellScript": "curl --location -s --request POST ${api_origin}/v2/harbor/${CICD_GIT_REPO_NAME}/scan --form branch=${CICD_GIT_BRANCH} --form commit_id=${CICD_GIT_COMMIT}"
        }
      }
    ]
}]

API_VERSION = "1.19.1"

def extra_func(pipe_stages, change):
    from copy import deepcopy
    pipe_stages_copy = deepcopy(pipe_stages)
    
    for pipe_stage in pipe_stages_copy:
        if pipe_stage.get("iiidevops") == "deployed-environments" and pipe_stage.get("name") == "Build--Build and push docker image":
            when = pipe_stage.get("when", {"branch": {"include": ["-skip"]}})
            index = pipe_stages.index(pipe_stage)
            if pipe_stages[index + 1].get("name") != "Build--Scan docker image":
              SCAN_DOCKER_IMAGE[0]["when"] = when
              pipe_stages.insert(index + 1, SCAN_DOCKER_IMAGE[0])
              change = True
    return pipe_stages, change