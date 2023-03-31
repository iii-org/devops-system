import config

# Runner answer & version
RUNNER_VERSION_MAPPING = {"sonarqube": {"version": "0.3.1"}, "checkmarx": {"version": "0.3.1"}}

# Image version
IMAGE_VERSION_MAPPING = {}

API_VERSION = "1.27.0"


def extra_func(pipe_stages, change):
    for pipe_stage in pipe_stages:
        if pipe_stage.get("iiidevops") == "sonarqube":
            steps = pipe_stage.get("steps", [])
            answers = steps[0].get("applyAppConfig", {}).get("answers")
            if answers is not None:
                if "asp_dot_net.image" in answers or "gradle.image" in answers or "maven.image" in answers:
                    break
                if "asp_dot_net.enabled" in answers:
                    if answers.get("asp_dot_net.enabled"):
                        pipe_stage["steps"][0]["applyAppConfig"]["answers"]["type"] = "asp_dot_net"
                    del pipe_stage["steps"][0]["applyAppConfig"]["answers"]["asp_dot_net.enabled"]
                    change = True
                elif "gradle.enabled" in answers:
                    if answers.get("gradle.enabled"):
                        pipe_stage["steps"][0]["applyAppConfig"]["answers"]["type"] = "gradle"
                    del pipe_stage["steps"][0]["applyAppConfig"]["answers"]["gradle.enabled"]
                    change = True
                elif "maven.enabled" in answers:
                    if answers.get("maven.enabled"):
                        pipe_stage["steps"][0]["applyAppConfig"]["answers"]["type"] = "maven"
                    del pipe_stage["steps"][0]["applyAppConfig"]["answers"]["maven.enabled"]
                    change = True
    return pipe_stages, change
