"""
Steps to modify the ORM model:
1. Change python codes in this file.
2. In command line: $ alembic revision --autogenerate -m <message>
3. A file named <some hash>_<message>.py will appear at apis/alembic/versions
4. Check if the migration can work: $ alembic upgrade head
5. If no error, rollback: $ alembic downgrade -1
6. If with error, modify the file generated in step 3 then repeat step 4.
7. Add an API server version in migrate.py's VERSION array.
8. Add an alembic_upgrade() statement for that version, or add it in the ONLY_UPDATE_DB_MODELS array.
9. Commit all files includes the file generated in step 3 to git.
10. Restart the API server, then you're done.

If you don't have the alembic.ini, copy _alembic.ini and replace the postgres uri by yourself.
"""
import json

from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import Column, Integer, String, Boolean, DateTime, ForeignKey, Date, Enum, JSON, Float
from sqlalchemy.orm import relationship

import util
from enums.action_type import ActionType

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
    from_ad = Column(Boolean, default=False)
    title = Column(String(45))
    department = Column(String(300))
    plugin_relation = relationship('UserPluginRelation', uselist=False)
    project_role = relationship('ProjectUserRole', back_populates='user')

    def __repr__(self):
        fields = {}
        for field in [x for x in dir(self) if
                      not x.startswith('query') and not x.startswith('_') and x != 'metadata']:
            if field in ['starred_project', 'plugin_relation', 'project_role']:
                continue
            data = self.__getattribute__(field)
            try:
                json.dumps(data)  # this will fail on unencodable values, like other classes
                if field == 'password':
                    continue
                elif field == 'disabled':
                    if data:
                        fields['status'] = 'disable'
                    else:
                        fields['status'] = 'enable'
                else:
                    fields[field] = data
            except TypeError:
                fields[field] = util.date_to_str(data)
        return json.dumps(fields)


class Project(db.Model):
    __tablename__ = 'projects'

    id = Column(Integer, primary_key=True)
    name = Column(String, unique=True)
    description = Column(String)
    ssh_url = Column(String)
    http_url = Column(String)
    start_date = Column(Date)
    due_date = Column(Date)
    create_at = Column(DateTime)
    update_at = Column(DateTime)
    disabled = Column(Boolean)
    display = Column(String)
    owner_id = Column(Integer, ForeignKey(User.id, ondelete='SET NULL'), nullable=True)
    creator_id = Column(Integer, ForeignKey(User.id, ondelete='SET NULL'), nullable=True)
    starred_by = relationship(User, secondary='starred_project', backref='starred_project')
    plugin_relation = relationship('ProjectPluginRelation', uselist=False)
    user_role = relationship('ProjectUserRole', back_populates='project')

    def __repr__(self):
        fields = {}
        for field in [x for x in dir(self) if
                      not x.startswith('query') and not x.startswith('_') and x != 'metadata']:
            if field in ['starred_by', 'plugin_relation', 'user_role']:
                continue
            data = self.__getattribute__(field)
            try:
                json.dumps(data)  # this will fail on unencodable values, like other classes
                fields[field] = data
            except TypeError:
                fields[field] = str(data)
        return json.dumps(fields)


class Release(db.Model):
    id = Column(Integer, primary_key=True)
    project_id = Column(Integer, ForeignKey(Project.id, ondelete='CASCADE'))
    version_id = Column(Integer)
    versions = Column(String)
    issues = Column(String)
    branch = Column(String)
    commit = Column(String)
    tag_name = Column(String)
    note = Column(String)
    creator_id = Column(Integer, ForeignKey(User.id, ondelete='SET NULL'), nullable=True)
    create_at = Column(DateTime)
    update_at = Column(DateTime)


class PluginSoftware(db.Model):
    id = Column(Integer, primary_key=True)
    name = Column(String)
    parameter = Column(String)
    disabled = Column(Boolean)
    create_at = Column(DateTime)
    update_at = Column(DateTime)


class ProjectPluginRelation(db.Model):
    id = Column(Integer, primary_key=True)
    project_id = Column(Integer, ForeignKey(Project.id, ondelete='CASCADE'))
    plan_project_id = Column(Integer, unique=True)
    git_repository_id = Column(Integer, unique=True)
    ci_project_id = Column(String)
    ci_pipeline_id = Column(String)
    harbor_project_id = Column(Integer)


class PipelineLogsCache(db.Model):
    id = Column(Integer, primary_key=True)
    project_id = Column(Integer, ForeignKey(Project.id, ondelete='CASCADE'))
    ci_pipeline_id = Column(String)
    run = Column(Integer)
    logs = Column(JSON)


class TemplateListCache(db.Model):
    temp_repo_id = Column(Integer, primary_key=True)
    name = Column(String)
    path = Column(String)
    display = Column(String)
    description = Column(String)
    version = Column(JSON)
    update_at = Column(DateTime)
    group_name = Column(String)


class ProjectUserRole(db.Model):
    project_id = Column(Integer, ForeignKey(Project.id, ondelete='CASCADE'), primary_key=True)
    user_id = Column(Integer, ForeignKey(User.id, ondelete='CASCADE'), primary_key=True)
    role_id = Column(Integer, primary_key=True)
    user = relationship('User', back_populates='project_role')
    project = relationship('Project', back_populates='user_role')


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
    commit_id = Column(String)
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
    scan_id = Column(Integer, primary_key=True)
    cm_project_id = Column(Integer)
    repo_id = Column(Integer, ForeignKey(ProjectPluginRelation.git_repository_id, ondelete='CASCADE'))
    branch = Column(String)
    commit_id = Column(String)
    # -1 if report is not registered yet
    report_id = Column(Integer, default=-1)
    # The time scan registered
    run_at = Column(DateTime)
    # Store if a final status (Finished, Failed, Cancelled) is checked
    # Null if scan is in non-final status
    scan_final_status = Column(String, nullable=True)
    stats = Column(String)
    # The time report is generated
    finished_at = Column(DateTime)
    # True only if report is available
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


class WebInspect(db.Model):
    scan_id = Column(String, primary_key=True)
    project_name = Column(String, ForeignKey(Project.name, ondelete='CASCADE'))
    branch = Column(String)
    commit_id = Column(String)
    stats = Column(String)
    # The time scan registered
    run_at = Column(DateTime)
    finished = Column(Boolean, default=False)

    def __repr__(self):
        fields = {}
        for field in [x for x in dir(self) if
                      not x.startswith('query') and not x.startswith('_') and x != 'metadata']:
            data = self.__getattribute__(field)
            try:
                json.dumps(data)  # this will fail on unencodable values, like other classes
                if field == 'stats':
                    fields[field] = json.loads(data)
                else:
                    fields[field] = data
            except TypeError:
                fields[field] = str(data)
        return json.dumps(fields)


class Activity(db.Model):
    id = Column(Integer, primary_key=True)
    action_type = Column(Enum(ActionType), nullable=False)
    action_parts = Column(String)
    operator_id = Column(Integer, ForeignKey(User.id, ondelete='SET NULL'), nullable=True)
    operator_name = Column(String)
    object_id = Column(String)
    act_at = Column(DateTime)

    def __repr__(self):
        return f'<{self.id}:{self.action_type.name}>' \
               f' {self.operator_name}({self.operator_id})' \
               f' on {self.action_parts} at {str(self.act_at)}.'


class NexusVersion(db.Model):
    id = Column(Integer, primary_key=True)
    api_version = Column(String)
    deploy_version = Column(String)
    deployment_uuid = Column(String)


class Sonarqube(db.Model):
    id = Column(Integer, primary_key=True)
    project_name = Column(String, ForeignKey(Project.name, ondelete='CASCADE'))
    date = Column(DateTime, nullable=False)
    measures = Column(String)


class Zap(db.Model):
    id = Column(Integer, primary_key=True)
    project_name = Column(String, ForeignKey(Project.name, ondelete='CASCADE'))
    branch = Column(String)
    commit_id = Column(String)
    status = Column(String)
    result = Column(String)
    full_log = Column(String)
    # The time scan registered
    run_at = Column(DateTime)
    finished_at = Column(DateTime)

    def __repr__(self):
        fields = {}
        for field in [x for x in dir(self) if
                      not x.startswith('query') and not x.startswith('_') and x != 'metadata']:
            data = self.__getattribute__(field)
            try:
                json.dumps(data)  # this will fail on unencodable values, like other classes
                if field == 'result':
                    fields[field] = json.loads(data)
                else:
                    fields[field] = data
            except TypeError:
                fields[field] = str(data)
        return json.dumps(fields)


class Sideex(db.Model):
    id = Column(Integer, primary_key=True)
    project_name = Column(String, ForeignKey(Project.name, ondelete='CASCADE'))
    branch = Column(String)
    commit_id = Column(String)
    status = Column(String)
    result = Column(String)
    report = Column(String)
    # The time scan registered
    run_at = Column(DateTime)
    finished_at = Column(DateTime)

    def __repr__(self):
        fields = {}
        for field in [x for x in dir(self) if
                      not x.startswith('query') and not x.startswith('_') and x != 'metadata']:
            data = self.__getattribute__(field)
            try:
                json.dumps(data)  # this will fail on unencodable values, like other classes
                if field == 'result':
                    fields[field] = json.loads(data)
                elif field == 'report':
                    fields['has_report'] = (data is not None)
                else:
                    fields[field] = data
            except TypeError:
                fields[field] = str(data)
        return json.dumps(fields)


class RedmineIssue(db.Model):
    issue_id = Column(Integer, primary_key=True)
    project_id = Column(Integer)
    project_name = Column(String)
    assigned_to = Column(String)
    assigned_to_id = Column(Integer)
    assigned_to_login = Column(String)
    issue_type = Column(String)
    issue_name = Column(String)
    status_id = Column(Integer)
    status = Column(String)
    is_closed = Column(Boolean)
    start_date = Column(DateTime)
    sync_date = Column(DateTime)


class RedmineProject(db.Model):
    id = Column(Integer, primary_key=True)
    project_id = Column(Integer)
    project_name = Column(String)
    owner_id = Column(Integer)
    owner_login = Column(String)
    owner_name = Column(String)
    complete_percent = Column(Float)
    closed_issue_count = Column(Integer)
    unclosed_issue_count = Column(Integer)
    total_issue_count = Column(Integer)
    member_count = Column(Integer)
    expired_day = Column(Integer)
    start_date = Column(DateTime)
    end_date = Column(DateTime)
    sync_date = Column(DateTime)
    project_status = Column(String)


class ProjectMember(db.Model):
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer)
    user_name = Column(String)
    project_id = Column(Integer)
    project_name = Column(String)
    role_id = Column(Integer)
    role_name = Column(String)
    department = Column(String)
    title = Column(String)


class ProjectMemberCount(db.Model):
    project_id = Column(Integer, primary_key=True)
    project_name = Column(String)
    member_count = Column(Integer)


class GitCommitNumberEachDays(db.Model):
    id = Column(Integer, primary_key=True)
    repo_id = Column(Integer)
    repo_name = Column(String)
    date = Column(Date)
    commit_number = Column(Integer)
    created_at = Column(DateTime)


class Registries(db.Model):
    registries_id = Column(Integer, primary_key=True)
    name = Column(String)
    user_id = Column(Integer, ForeignKey(User.id, ondelete='CASCADE'))
    description = Column(String)
    access_key = Column(String)
    access_secret = Column(String)
    url = Column(String)
    type = Column(String)


class IssueCollectionRelation(db.Model):
    id = Column(Integer, primary_key=True)
    project_id = Column(Integer, ForeignKey(Project.id, ondelete='CASCADE'))
    issue_id = Column(Integer)
    software_name = Column(String)
    file_name = Column(String)
    plan_name = Column(String)
    items = Column(JSON)


class TestGeneratedIssue(db.Model):
    id = Column(Integer, primary_key=True)
    project_id = Column(Integer, ForeignKey(Project.id, ondelete='CASCADE'))
    issue_id = Column(Integer)
    software_name = Column(String)
    file_name = Column(String)
    branch = Column(String)
    commit_id = Column(String)
    result_table = Column(String, nullable=False)
    result_id = Column(Integer, nullable=False)


class StarredProject(db.Model):
    id = Column(Integer, primary_key=True)
    project_id = Column(Integer, ForeignKey(Project.id, ondelete='CASCADE'), nullable=False)
    user_id = Column(Integer, ForeignKey(User.id, ondelete='CASCADE'), nullable=False)
