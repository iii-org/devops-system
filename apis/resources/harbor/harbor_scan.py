import json
from datetime import datetime

import resources.yaml_OO as pipeline_yaml_OO
from model import HarborScan, Project, db
from nexus import nx_get_project_plugin_relation
from resources.template import gl, tm_get_git_pipeline_json


def create_harbor_scan(project_name, branch, commit_id):
    row = Project.query.filter_by(name=project_name).first()
    if row:
        # check this branch has build image or not
        git_repository_id = nx_get_project_plugin_relation(nexus_project_id=row.id).git_repository_id
        pj = gl.projects.get(git_repository_id)
        pipe_dicts = tm_get_git_pipeline_json(pj, commit_id=commit_id)
        for pipe_dict in pipe_dicts.get('stages'):
            if pipe_dict.get('iiidevops') == "deployed-environments" and \
                    'publishImageConfig' in pipe_dict.get('steps')[0]:
                stage_when = pipeline_yaml_OO.RancherPipelineWhen(pipe_dict.get("when").get("branch"))
                if branch in stage_when.branch.include:
                    scan = HarborScan(project_id=row.id, branch=branch, commit=commit_id,
                                      created_at=datetime.utcnow(), finished=False)
                    db.session.add(scan)
                    db.session.commit()


def harbor_scan_list(project_id):
    rows = HarborScan.query.filter_by(project_id=project_id).all()
    return [json.loads(str(row)) for row in rows]
