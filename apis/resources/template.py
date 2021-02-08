from flask_jwt_extended import jwt_required, get_jwt_identity
from flask_restful import Resource, reqparse
import config
from . import role
from .logger import logger

from gitlab import Gitlab

def tm_get_template():
    output = []
    gl = Gitlab(config.get("GITLAB_BASE_URL"), private_token=config.get("GITLAB_PRIVATE_TOKEN"))
    group = gl.groups.get("iii-org-app", all=True)
    for group_project in group.projects.list():
        pj = gl.projects.get(group_project.id)
        # get default branch name
        default_branch = "master"
        for branch in pj.branches.list():
            if branch.default == True:
                default_branch = branch.name
        # get all tag
        tag_list = []
        for tag in pj.tags.list():
            tag_list.append({"name": tag.name, "commit_id": tag.commit["id"], 
                             "commit_time":tag.commit["committed_date"]})
        f_raw = pj.files.raw(file_path="README.md", ref = default_branch)
        summary = {"h1": [], "h2": []}
        for line in f_raw.decode().split('\n'):
            if line.count("#", 0, 5) == 2:
                summary["h2"].append(line[2:])
            elif line.count("#", 0, 5) == 1:
                summary["h1"].append(line[1:])
        output.append({"name": pj.name, 
                       "path": pj.path_with_namespace, 
                       "version": tag_list,
                       "summary": summary})
    return output

class SingleTemplate(Resource):
    @jwt_required
    def get(self):
        role.require_pm("Error while getting template list.")
        return tm_get_template()