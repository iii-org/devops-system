from model import db, Project, HarborScan
from datetime import datetime


def create_harbor_scan(project_name, branch, commit_id):
    row = Project.query.filter_by(name=project_name).first()
    if row:
        scan = HarborScan(project_id=row.id, branch=branch, commit=commit_id,
                          created_at=datetime.utcnow(), finished=False)
        db.session.add(scan)
        db.session.commit()
