from datetime import datetime
import dateutil.parser
import sys
import yaml

from flask_jwt_extended import jwt_required, get_jwt_identity
from flask_restful import Resource, reqparse
import config
from . import role
from .logger import logger

from gitlab import Gitlab

def tm_get_template_list():
    output = []
    gl = Gitlab(config.get("GITLAB_BASE_URL"), private_token=config.get("GITLAB_PRIVATE_TOKEN"))
    group = gl.groups.get("iii-org-app", all=True)
    for group_project in group.projects.list():
        pj = gl.projects.get(group_project.id)
        # get all tags
        tag_list = []
        for tag in pj.tags.list():
            tag_list.append({"name": tag.name, "commit_id": tag.commit["id"], 
                             "commit_time":tag.commit["committed_date"]})
        f_raw = pj.files.raw(file_path="README.md", ref = pj.default_branch)
        summary = {"h1": [], "h2": []}
        for line in f_raw.decode().split('\n'):
            if line.count("#", 0, 5) == 2:
                summary["h2"].append(line[2:])
            elif line.count("#", 0, 5) == 1:
                summary["h1"].append(line[1:])
        output.append({"id": pj.id,
                       "name": pj.name, 
                       "path": pj.path, 
                       "version": tag_list,
                       "summary": summary})
    return output


def tm_get_template(repository_id, args):
    gl = Gitlab(config.get("GITLAB_BASE_URL"), private_token=config.get("GITLAB_PRIVATE_TOKEN"))
    pj = gl.projects.get(repository_id)
    pipeline_yaml = ".rancher-pipeline.yaml"
    for item in  pj.repository_tree():
        if item["path"] == ".rancher-pipeline.yml":
            pipeline_yaml = ".rancher-pipeline.yml"
    the_last_tag = {"tag_name": None, "commit_time": sys.float_info.max, "commit_id": None}
    if args["tag_name"] is None:
        # Get the last tag
        for tag in pj.tags.list():
            seconds = (datetime.now() - dateutil.parser.parse(tag.commit["committed_date"])
                       .replace(tzinfo=None)).total_seconds()
            if seconds < the_last_tag["commit_time"]:
                the_last_tag["tag_name"] = tag.name
                the_last_tag["commit_time"] = seconds
                the_last_tag["commit_id"] = tag.commit["id"]
    else:
        for tag in pj.tags.list():
            if args["tag_name"] == tag.name:
                the_last_tag["tag_name"] = tag.name
                the_last_tag["commit_id"] = tag.commit["id"]
    f_raw = pj.files.raw(file_path = pipeline_yaml, ref = the_last_tag["commit_id"])
    print(yaml.safe_load(f_raw.decode()))


class TemplateList(Resource):
    @jwt_required
    def get(self):
        role.require_pm("Error while getting template list.")
        return tm_get_template_list()


class SingleTemplate(Resource):
    @jwt_required
    def get(self, repository_id):
        role.require_pm("Error while getting template list.")
        parser = reqparse.RequestParser()
        parser.add_argument('tag_name', type=str)
        args = parser.parse_args()
        return tm_get_template(repository_id, args)