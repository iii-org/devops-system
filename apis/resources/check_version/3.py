
# Runner answer & version
RUNNER_VERSION_MAPPING = {}

# Image version
IMAGE_VERSION_MAPPING = {
  "iiiorg/deployment-waiter": "0.0.5"
}

# Stages
'''
only need to change part of 'steps -> runScriptConfig -> shellScript'
'''
DEPLOYMENT_ENVIRONMENTS_steps_runScriptConfig =  {
  "image": "iiiorg/deployment-waiter:0.0.5",
  "shellScript": "rancher login ${rancher_url} -t ${rancher_api_token} --skip-verify; perl /app/run.sh"
}


API_VERSION = "1.20.0"

def extra_func(pipe_stages, change):
    for pipe_stage in pipe_stages:
        if pipe_stage.get("iiidevops") == "deployed-environments" and pipe_stage.get("name") == "Deploy--Wait Web deployment":
            pipe_stage["steps"][0]["runScriptConfig"] = DEPLOYMENT_ENVIRONMENTS_steps_runScriptConfig
            change = True
    return pipe_stages, change