import config

# Runner answer & version
RUNNER_VERSION_MAPPING = {}

# Image version
IMAGE_VERSION_MAPPING = {}

# Stages
'''
only need to change part of 'steps -> runScriptConfig -> shellScript'
'''
DEPLOYMENT_ENVIRONMENTS_steps_runScriptConfig =  {
  "image": "iiiorg/iiidevops-cli:0.0.1",
  "shellScript": "rancher login ${rancher_url} -t ${rancher_api_token} --skip-verify; deploy-wait.pl"
}

# Image Replace
'''
only this version has this requirement
'''
IMAGE_REPLACE_MAPPING = {
  "iiiorg/deployment-waiter": "iiiorg/iiidevops-cli:0.0.1",
  "iiiorg/rancher-cli": "iiiorg/iiidevops-cli:0.0.1"
}


API_VERSION = "1.20.0"

def extra_func(pipe_stages, change):
    harbor_domain = config.get("HARBOR_EXTERNAL_BASE_URL").split("/")[-1]

    for pipe_stage in pipe_stages:
        # Updated deployment environuments stage
        if pipe_stage.get("iiidevops") == "deployed-environments" and pipe_stage.get("name") == "Deploy--Wait Web deployment":
          if pipe_stage["steps"][0]["runScriptConfig"] != DEPLOYMENT_ENVIRONMENTS_steps_runScriptConfig:
            pipe_stage["steps"][0]["runScriptConfig"] = DEPLOYMENT_ENVIRONMENTS_steps_runScriptConfig
            change = True

        steps = pipe_stage.get("steps", [])
        if len(steps) > 0:
          # Image replace 
          split_image_list = steps[0].get("runScriptConfig", {}).get("image", "").split(":")
          if len(split_image_list) >= 2:
            for before_image, after_image in IMAGE_REPLACE_MAPPING.items():
              if split_image_list[-2].endswith(before_image):
                pipe_stage["steps"][0]["runScriptConfig"]["image"] = after_image
                change = True

          # Add harbor.host: {harbor_domain}
          answers = steps[0].get("applyAppConfig", {}).get("answers")
          if answers is not None and 'harbor.host' not in answers:
            pipe_stage["steps"][0]["applyAppConfig"]["answers"]["harbor.host"] = harbor_domain
            change = True
          
    return pipe_stages, change