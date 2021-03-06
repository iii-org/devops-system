import json
import os

FIXED = {
    # API versions
    'GITLAB_API_VERSION': 'v4',
    'RANCHER_API_VERSION': 'v3',
    'LOGGER_NAME': 'devops.api',
    'DEBUG': True
}

in_file = {}
if os.path.isfile('environments.json'):
    env_file = open('environments.json', 'r')
    in_file = json.load(env_file)


def get(key):
    env = os.getenv(key)
    if env is not None:
        return env
    if key in in_file and in_file[key] is not None:
        return in_file[key]
    elif key in FIXED:
        return FIXED[key]
    else:
        return None
