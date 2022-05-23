from model import db, HarborScan
from datetime import datetime


def create_harbor_scan(project_id, branch, commit_id):
    scan = HarborScan(project_id=project_id, branch=branch, commit=commit_id,
                      created_at=datetime.utcnow(), finished=False)
    db.session.add(scan)
    db.session.commit()
