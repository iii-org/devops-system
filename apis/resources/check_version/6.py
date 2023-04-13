import config

# Runner answer & version
RUNNER_VERSION_MAPPING = {}

# Image version
IMAGE_VERSION_MAPPING = {"iiidevops-cli": "0.0.4"}

API_VERSION = "1.28.0"


def extra_func(pipe_stages, change):
    for pipe_stage in pipe_stages:
        # if pipe_stage.get("iiidevops") == "sonarqube":
            steps = pipe_stage.get("steps", [])
            shellScript = steps[0].get("runScriptConfig", {}).get("shellScript")
            if shellScript is not None:
                if "perl iiidevops/bin/chk-app-env.pl" in shellScript:
                    shellScript = shellScript.replace("perl iiidevops/bin/chk-app-env.pl", "chk-app-env.pl")
                    pipe_stage["steps"][0]["runScriptConfig"]["shellScript"] = shellScript
                    change = True
    return pipe_stages, change
