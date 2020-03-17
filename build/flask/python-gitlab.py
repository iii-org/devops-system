import gitlab
import requests
import json


gitlab_url = 'http://10.50.0.20'
project_name = 'iii-DevOps-testing-on-Kubernetes'

jenkinks_url = 'http://10.50.1.68:8080'
jenkins_secret_token = '0ad85e846fe7c8b481fad51830cd5d30'


# get private token
parameter= {
    "login": "yuweichou",
    "password": 'a0918101553'
}
headers = {'Content-Type': 'application/json'}
callapi = requests.post("{0}/api/v3/session".format(gitlab_url), data=json.dumps(parameter), headers=headers)
gitlab_pri_token = callapi.json()["private_token"]

gl = gitlab.Gitlab(gitlab_url, private_token=gitlab_pri_token)
# Get project
projects = gl.projects.list(search=project_name)
if len(projects) == 1:
    project  = projects[0]
    hooks = project.hooks.list()
    #print (hooks[0])
    hook_exist = False
    for hook in hooks:
        print (hook.url)
        if "{0}/project/{1}".format(jenkinks_url, project_name) in hook.url:
            print ('hook already exist!')
            hook_exist = True
            print(hook)
    if hook_exist == False:
        print ('hook is not exist, add it.')
        hook = project.hooks.create({
            'url': "{0}/project/{1}".format(jenkinks_url, project_name),\
                'push_events': 1, 'token': jenkins_secret_token})
        print(hook)