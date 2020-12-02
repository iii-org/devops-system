"""
Steps to modify the ORM model:
1. Change python codes in this file.
2. In command line: $ alembic revision --autogenerate -m <message>
3. A file named <some hash>_<message>.py will appear at apis/alembic/versions
4. Check if the migration can work: $ alembic upgrade head
5. If no error, rollback: $ alembic downgrade -1
6. If with error, modify the file generated in step 3 then repeat step 4.
7. Add an API server version in migrate.py's VERSION array.
8. Add an alembic_upgrade() statement for that version.
9. Commit all files includes the file generated in step 3 to git.
10. Done.

If you don't have the alembic.ini, copy _alembic.ini and replace the postgres uri by yourself.
"""

from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import Column, Integer, String, Boolean, DateTime, ForeignKey, Date

db = SQLAlchemy()


class AlembicVersion(db.Model):
    version_num = Column(String(32), primary_key=True)


class User(db.Model):
    id = Column(Integer, primary_key=True)
    name = Column(String(45))
    email = Column(String(45))
    phone = Column(String(40))
    login = Column(String(45))
    password = Column(String(100))
    create_at = Column(DateTime)
    update_at = Column(DateTime)
    disabled = Column(Boolean)


class Project(db.Model):
    __tablename__ = 'projects'

    id = Column(Integer, primary_key=True)
    name = Column(String)
    description = Column(String)
    ssh_url = Column(String)
    http_url = Column(String)
    start_date = Column(Date)
    due_date = Column(Date)
    create_at = Column(DateTime)
    update_at = Column(DateTime)
    disabled = Column(Boolean)
    display = Column(String)


class ProjectPluginRelation(db.Model):
    id = Column(Integer, primary_key=True)
    project_id = Column(Integer, ForeignKey(Project.id, ondelete='CASCADE'))
    plan_project_id = Column(Integer, unique=True)
    git_repository_id = Column(Integer, unique=True)
    ci_project_id = Column(String)
    ci_pipeline_id = Column(String)
    harbor_project_id = Column(Integer)


class PipelinePhase(db.Model):
    id = Column(Integer, primary_key=True)
    name = Column(String)
    description = Column(String)
    parent_phase_Id = Column(Integer)
    is_closed = Column(Boolean)


class PipelineSoftware(db.Model):
    id = Column(Integer, primary_key=True)
    name = Column(String)
    phase_id = Column(Integer)
    is_closed = Column(Boolean)
    description = Column(String)


class PipelineSoftwareConfig(db.Model):
    id = Column(Integer, primary_key=True)
    software_id = Column(Integer, ForeignKey(PipelineSoftware.id, ondelete='CASCADE'),
                         nullable=False)
    project_id = Column(Integer, ForeignKey(Project.id, ondelete='CASCADE'))
    detail = Column(String)
    sample = Column(Boolean)


class ProjectUserRole(db.Model):
    project_id = Column(Integer, ForeignKey(Project.id, ondelete='CASCADE'), primary_key=True)
    user_id = Column(Integer, ForeignKey(User.id, ondelete='CASCADE'), primary_key=True)
    role_id = Column(Integer, primary_key=True)


class Requirements(db.Model):
    id = Column(Integer, primary_key=True)
    project_id = Column(Integer, ForeignKey(Project.id, ondelete='CASCADE'))
    issue_id = Column(Integer)
    flow_info = Column(String)
    create_at = Column(DateTime)
    update_at = Column(DateTime)
    disabled = Column(Boolean)


class TestCases(db.Model):
    id = Column(Integer, primary_key=True)
    name = Column(String(255))
    description = Column(String(255))
    issue_id = Column(Integer)
    project_id = Column(Integer, ForeignKey(Project.id, ondelete='CASCADE'))
    create_at = Column(DateTime)
    update_at = Column(DateTime)
    disabled = Column(Boolean)
    # JSON string like
    # {
    #  "type": "API",
    #  "url": "/user/forgot",
    #  "method": "POST",
    #  "method_id": "2"
    # }
    data = Column(String)
    type_id = Column(Integer)


class TestItems(db.Model):
    id = Column(Integer, primary_key=True)
    test_case_id = Column(Integer, ForeignKey(TestCases.id, ondelete='CASCADE'))
    project_id = Column(Integer, ForeignKey(Project.id, ondelete='CASCADE'))
    issue_id = Column(Integer)
    name = Column(String(255))
    is_passed = Column(Boolean)
    create_at = Column(DateTime)
    update_at = Column(DateTime)
    disabled = Column(Boolean)


class TestResults(db.Model):
    id = Column(Integer, primary_key=True)
    project_id = Column(Integer, ForeignKey(Project.id, ondelete='CASCADE'))
    branch = Column(String(50))
    report = Column(String)
    total = Column(Integer)
    fail = Column(Integer)
    run_at = Column(DateTime)


class TestValues(db.Model):
    id = Column(Integer, primary_key=True)
    type_id = Column(Integer)  # Request = 1, response = 2
    key = Column(String(255))
    value = Column(String)
    location_id = Column(Integer)  # Header = 1, Body = 2
    test_item_id = Column(Integer, ForeignKey(TestItems.id, ondelete='CASCADE'))
    test_case_id = Column(Integer, ForeignKey(TestCases.id, ondelete='CASCADE'))
    issue_id = Column(Integer)
    project_id = Column(Integer, ForeignKey(Project.id, ondelete='CASCADE'))
    create_at = Column(DateTime)
    update_at = Column(DateTime)
    disabled = Column(Boolean)


class UserPluginRelation(db.Model):
    user_id = Column(Integer, ForeignKey(User.id, ondelete='CASCADE'), primary_key=True)
    plan_user_id = Column(Integer)
    repository_user_id = Column(Integer)
    harbor_user_id = Column(Integer)
    kubernetes_sa_name = Column(String)


class Checkmarx(db.Model):
    cm_project_id = Column(Integer, primary_key=True)
    repo_id = Column(Integer, ForeignKey(ProjectPluginRelation.git_repository_id, ondelete='CASCADE'))
    scan_id = Column(Integer)
    # -1 if report is not registered yet
    report_id = Column(Integer, default=-1)
    # The time scan registered
    run_at = Column(DateTime)
    finished_at = Column(DateTime)
    finished = Column(Boolean)


class Flows(db.Model):
    id = Column(Integer, primary_key=True)
    project_id = Column(Integer, ForeignKey(Project.id, ondelete='CASCADE'))
    issue_id = Column(Integer)
    requirement_id = Column(Integer, ForeignKey(Requirements.id, ondelete='CASCADE'))
    type_id = Column(Integer)
    name = Column(String)
    description = Column(String)
    serial_id = Column(Integer)
    create_at = Column(DateTime)
    update_at = Column(DateTime)
    disabled = Column(Boolean)


class Parameters(db.Model):
    id = Column(Integer, primary_key=True)
    issue_id = Column(Integer)
    project_id = Column(Integer, ForeignKey(Project.id, ondelete='CASCADE'))
    parameter_type_id = Column(Integer)
    name = Column(String(50))
    description = Column(String(100))
    limitation = Column(String(50))
    length = Column(Integer)
    create_at = Column(DateTime)
    update_at = Column(DateTime)
    disabled = Column(Boolean)
