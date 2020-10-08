import os, json

FIXED = {
    # API versions
    'GITLAB_API_VERSION': 'v4',
    'RANCHER_API_VERSION': 'v3',
}

in_file = {}
if os.path.isfile('environments.json'):
    env_file = open('environments.json', 'r')
    in_file = json.load(env_file)


def get(key):
    env = os.getenv(key)
    if env is not None:
        return env
    if key in in_file:
        return in_file[key]
    else:
        return FIXED[key]
