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


def harbor_scan_list(project_id, kwargs):
    page_dict = {}
    query = HarborScan.query.filter_by(project_id=project_id).order_by(HarborScan.id.desc())
    if 'per_page' in kwargs:
        per_page = kwargs['per_page']
    if 'page' in kwargs:
        paginate_query = query.paginate(
            page=kwargs['page'],
            per_page=per_page,
            error_out=False
        )
        page_dict = {
            'current': paginate_query.page,
            'prev': paginate_query.prev_num,
            'next': paginate_query.next_num,
            'pages': paginate_query.pages,
            'per_page': paginate_query.per_page,
            'total': paginate_query.total
        }
        rows = paginate_query.items
    else:
        rows = query.all()
    out_dict = {"scan_list": [json.loads(str(row)) for row in rows], "page": page_dict}
    if page_dict:
        out_dict['page'] = page_dict
    return out_dict
