import json
from datetime import datetime

from model import HarborScan, Project, db


def create_harbor_scan(project_name, branch, commit_id):
    row = Project.query.filter_by(name=project_name).first()
    if row:
        scan = HarborScan(project_id=row.id, branch=branch, commit=commit_id,
                          created_at=datetime.utcnow(), finished=False)
        db.session.add(scan)
        db.session.commit()


def harbor_scan_list(project_id):
    rows = HarborScan.query.filter_by(project_id=project_id).all()
    for row in rows:
        row = json.loads(str(row))
    return row
