import json
from datetime import datetime

import resources.yaml_OO as pipeline_yaml_OO
from model import HarborScan, Project, db
from nexus import nx_get_project_plugin_relation, nx_get_project
from resources.template import gl, tm_get_git_pipeline_json
from resources.gitlab import commit_id_to_url
from . import hb_get_artifact_scan_overview, hb_get_artifact_scan_vulnerabilities_detail
from sqlalchemy import or_

harbor_scan_list_keys = ["Critical", "High", "Low", "Medium", "fixable"]
harbor_scan_report_keys = ["Critical", "High", "Low", "Medium", "Negligible", "Unknown"]


def create_harbor_scan(project_name, branch, commit_id):
    row = Project.query.filter_by(name=project_name).first()
    if row:
        # check this branch has build image or not
        git_repository_id = nx_get_project_plugin_relation(nexus_project_id=row.id).git_repository_id
        pj = gl.projects.get(git_repository_id)
        pipe_dicts = tm_get_git_pipeline_json(pj, commit_id=commit_id)
        for pipe_dict in pipe_dicts.get("stages"):
            if (
                pipe_dict.get("iiidevops") == "deployed-environments"
                and "publishImageConfig" in pipe_dict.get("steps")[0]
            ):
                stage_when = pipeline_yaml_OO.RancherPipelineWhen(pipe_dict.get("when").get("branch"))
                if branch in stage_when.branch.include:
                    scan = HarborScan(
                        project_id=row.id,
                        branch=branch,
                        commit=commit_id,
                        created_at=datetime.utcnow(),
                        finished=False,
                    )
                    db.session.add(scan)
                    db.session.commit()


def get_harbor_scan_report(project_name, branch, commit_id):
    pj_row = Project.query.filter_by(name=project_name).first()
    if pj_row:
        out = hb_get_artifact_scan_vulnerabilities_detail(pj_row.name, branch, commit_id)
        if out:
            hs_row = (
                HarborScan.query.filter_by(project_id=pj_row.id, branch=branch, commit=commit_id)
                .order_by(HarborScan.id.desc())
                .first()
            )
            out["overview"] = hs_row.scan_overview
            for scan_key in harbor_scan_report_keys:
                if out["overview"].get(scan_key) is None:
                    out["overview"][scan_key] = 0
            return out


def harbor_get_scan_by_commit(project_id, commit_id):
    row = HarborScan.query.filter_by(project_id=project_id, commit=commit_id).first()
    if row is not None:
        if row.finished is False:
            update_harbor_scan_status(row, project_id)
            row = HarborScan.query.filter_by(project_id=project_id, commit=commit_id).first()
        ret = json.loads(str(row))
        ret["run_at"] = ret.pop("created_at")
        scan_overview = ret.pop("scan_overview", {}) or {}
        for k, v in scan_overview.items():
            ret[k] = v
        status = ret.pop("scan_status", None)
        if status == "Success" and ret.get("finished"):
            ret["status"] = "Finished"
        elif (status == "Success" and not ret.get("finished")) or status in [
            "Queued",
            "Scanning",
            "Complete",
        ]:
            ret["status"] = "scanning"
        else:
            ret["status"] = "failed"
    else:
        ret = {}
    return ret


def harbor_scan_list(project_id, kwargs):
    scan_list = []
    page_dict = {}
    query = HarborScan.query.filter_by(project_id=project_id).order_by(HarborScan.id.desc())
    if kwargs.get("search"):
        query = query.filter(
            or_(
                HarborScan.branch.like(f"%{kwargs['search']}%"),
                HarborScan.commit.like(f"%{kwargs['search']}%"),
            )
        )
    if "per_page" in kwargs:
        per_page = kwargs["per_page"]
    if "page" in kwargs:
        paginate_query = query.paginate(page=kwargs["page"], per_page=per_page, error_out=False)
        page_dict = {
            "current": paginate_query.page,
            "prev": paginate_query.prev_num,
            "next": paginate_query.next_num,
            "pages": paginate_query.pages,
            "per_page": paginate_query.per_page,
            "total": paginate_query.total,
        }
        rows = paginate_query.items
    else:
        rows = query.all()
    for row in rows:
        setattr(row, "scan_status", "Not Scanned")
        if row.finished is False:
            update_harbor_scan_status(row, project_id)
        if row.scan_overview is not None:
            for k, v in row.scan_overview.items():
                setattr(row, k, v)
        setattr(row, "commit_url", commit_id_to_url(project_id, row.commit))
        for scan_key in harbor_scan_list_keys:
            if hasattr(row, scan_key) is False:
                setattr(row, scan_key, 0)
        row_dict = json.loads(str(row))
        del row_dict["scan_overview"]
        scan_list.append(row_dict)

    out_dict = {"scan_list": scan_list, "page": page_dict}
    if page_dict:
        out_dict["page"] = page_dict
    return out_dict


def update_harbor_scan_status(row: HarborScan, project_id: int) -> None:
    scan_report_dict = hb_get_artifact_scan_overview(nx_get_project(id=project_id).name, row.branch, row.commit)
    if scan_report_dict is not None:
        if scan_report_dict.get("summary", {}).get("summary") is not None:
            scan_report_dict |= scan_report_dict.pop("summary")
            scan_report_dict |= scan_report_dict.pop("summary")
        if scan_report_dict.get("complete_percent") == 100:
            row.finished_at = datetime.utcnow()
            row.finished = True
        row.updated_at = datetime.utcnow()
        row.scan_overview = scan_report_dict
        db.session.commit()
