import json
from datetime import datetime

import resources.yaml_OO as pipeline_yaml_OO
from model import HarborScan, Project, db
from nexus import nx_get_project_plugin_relation, nx_get_project
from resources.template import gl, tm_get_git_pipeline_json
from resources.gitlab import commit_id_to_url
from . import hb_get_artifact_scan_overview, hb_get_artifact_scan_vulnerabilities_detail


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


def get_harbor_scan_report(project_name, branch, commit_id):
    row = Project.query.filter_by(name=project_name).first()
    if row:
        out = hb_get_artifact_scan_vulnerabilities_detail(row.name, branch, commit_id)
        if out:
            return out.get('vulnerabilities')


def harbor_scan_list(project_id, kwargs):
    scan_list = []
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
    for row in rows:
        setattr(row, 'scan_status', 'Not Scanned')
        if row.finished is False:
            scan_report_dict = hb_get_artifact_scan_overview(nx_get_project(id=project_id).name, row.branch, row.commit)
            if scan_report_dict is not None:
                scan_report_dict |= scan_report_dict.get('summary').get('summary')
                del scan_report_dict.get('summary')['summary']
                scan_report_dict |= scan_report_dict.get('summary')
                del scan_report_dict['summary']
                if scan_report_dict.get('complete_percent') == 100:
                    row.finished_at = datetime.utcnow()
                    row.finished = True
                row.updated_at = datetime.utcnow()
                row.scan_overview = scan_report_dict
                db.session.commit()
        if row.scan_overview is not None:
            for k, v in row.scan_overview.items():
                setattr(row, k, v)
        setattr(row, 'commit_url', commit_id_to_url(project_id, row.commit))
        row_dict = json.loads(str(row))
        del row_dict['scan_overview']
        scan_list.append(row_dict)

    out_dict = {"scan_list": scan_list, "page": page_dict}
    if page_dict:
        out_dict['page'] = page_dict
    return out_dict
