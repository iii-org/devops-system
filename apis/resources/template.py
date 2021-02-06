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
    for project in group.projects.list():
        pj = gl.projects.get(project.id)
        f_raw = pj.files.raw(file_path="README.md", ref = 'main')
        summary = {"h1": [], "h2": []}
        for line in f_raw.decode().split('\n'):
            if line.count("#", 0, 5) == 2:
                summary["h2"].append(line[2:])
            elif line.count("#", 0, 5) == 1:
                summary["h1"].append(line[1:])
        output.append({"name": project.name, 
                       "path": project.path_with_namespace, 
                       "version": project.tag_list,
                       "summary": summary})
    return output

class SingleTemplate(Resource):
    @jwt_required
    def get(self):
        role.require_pm("Error while getting template list.")
        return tm_get_template()