from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import Column, Integer, String, Boolean, DateTime

db = SQLAlchemy()


class CheckMarx(db.Model):
    cm_project_id = Column(Integer, primary_key=True)
    repo_id = Column(Integer)
    scan_id = Column(Integer)
    # -1 if report is not registered yet
    report_id = Column(Integer, default=-1)
    # The time scan registered
    run_at = Column(DateTime)
    finished_at = Column(DateTime)
    finished = Column(Boolean)


class DbVersion(db.Model):
    version = Column(Integer, primary_key=True)


class Flows(db.Model):
    id = Column(Integer, primary_key=True)
    project_id = Column(Integer)
    issue_id = Column(Integer)
    requirement_id = Column(Integer)
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
    project_id = Column(Integer)
    parameter_type_id = Column(Integer)
    name = Column(String(50))
    description = Column(String(100))
    limitation = Column(String(50))
    length = Column(Integer)
    create_at = Column(DateTime)
    update_at = Column(DateTime)
    disabled = Column(Boolean)


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
    software_id = Column(Integer, nullable=False)
    project_id = Column(Integer)
    detail = Column(String)
    sample = Column(Boolean)


class ProjectPluginRelation(db.Model):
    project_id = Column(Integer, primary_key=True)
    plan_project_id = Column(Integer)
    git_repository_id = Column(Integer)
    ci_project_id = Column(String)
    ci_pipeline_id = Column(String)


class ProjectUserRole(db.Model):
    project_id = Column(Integer, primary_key=True)
    user_id = Column(Integer, primary_key=True)
    role_id = Column(Integer, primary_key=True)


class Project(db.Model):
    __tablename__ = 'projects'

    id = Column(Integer, primary_key=True)
    name = Column(String)
    display = Column(String)


class Requirements(db.Model):
    id = Column(Integer, primary_key=True)
    project_id = Column(Integer)
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
    project_id = Column(Integer)
    create_at = Column(DateTime)
    update_at = Column(DateTime)
    disabled = Column(Boolean)
    # Stringified JSON like
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
    test_case_id = Column(Integer)
    project_id = Column(Integer)
    issue_id = Column(Integer)
    name = Column(String(255))
    is_passed = Column(Boolean)
    create_at = Column(DateTime)
    update_at = Column(DateTime)
    disabled = Column(Boolean)


class TestResults(db.Model):
    id = Column(Integer, primary_key=True)
    project_id = Column(Integer)
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
    test_item_id = Column(Integer)
    test_case_id = Column(Integer)
    issue_id = Column(Integer)
    project_id = Column(Integer)
    create_at = Column(DateTime)
    update_at = Column(DateTime)
    disabled = Column(Boolean)


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


class UserPluginRelation(db.Model):
    user_id = Column(Integer, primary_key=True)
    plan_user_id = Column(Integer)
    repository_user_id = Column(Integer)

