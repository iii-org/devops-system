from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import Column, Integer, String, Boolean, DateTime

db = SQLAlchemy()


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

    def __repr__(self):
        return '<User (id={0}, name={1}, login={2})>'.format(self.id, self.name, self.login)


class UserPluginRelation(db.Model):
    user_id = Column(Integer, primary_key=True)
    plan_user_id = Column(Integer)
    repository_user_id = Column(Integer)


class ProjectPluginRelation():
    meta = db.MetaData()
    stru_project_plug_relation = db.Table(
        'project_plugin_relation', meta, Column('project_id', db.Integer),
        Column('plan_project_id', db.Integer),
        Column('git_repository_id', db.Integer),
        Column('ci_project_id', db.String),
        Column('ci_pipeline_id', db.String))


class GroupsHasUsers():
    meta = db.MetaData()
    stru_groups_has_users = db.Table(
        'groups_has_users', meta,
        Column('group_id', db.Integer, nullable=True),
        Column('user_id', db.Integer, nullable=True))


class TableGroup():
    meta = db.MetaData()
    stru_group = db.Table('group', meta,
                          Column('id', db.Integer, nullable=True),
                          Column('name', db.String, nullable=True))


class ProjectUserRole():
    meta = db.MetaData()
    stru_project_user_role = db.Table('project_user_role', meta,
                                      Column('project_id', db.Integer),
                                      Column('user_id', db.Integer),
                                      Column('role_id', db.Integer))


class TableProjects():
    meta = db.MetaData()
    stru_projects = db.Table('projects', meta,
                             Column('id', db.Integer),
                             Column('name', db.String),
                             Column('display', db.String))


class TableRequirement():
    meta = db.MetaData()
    stru_rqmt = db.Table('requirements', meta,
                         Column('id', db.Integer, primary_key=True),
                         Column('project_id', db.Integer),
                         Column('issue_id', db.Integer),
                         Column('flow_info', db.TEXT),
                         Column('create_at', db.DATETIME(255)),
                         Column('update_at', db.DATETIME(255)),
                         Column('disabled', db.Boolean))

class TableFlow():
    meta = db.MetaData()
    stru_flow = db.Table('flows', meta,
                         Column('id', db.Integer, primary_key=True),
                         Column('project_id', db.Integer),
                         Column('issue_id', db.Integer),
                         Column('requirement_id', db.Integer),
                         Column('type_id', db.Integer),
                         Column('name', db.String),
                         Column('description', db.String),
                         Column('serial_id',db.Integer),
                         Column('create_at', db.DATETIME(255)),
                         Column('update_at', db.DATETIME(255)),
                         Column('disabled', db.Boolean))


class TableTestCase():
    meta = db.MetaData()
    stru_testCase = db.Table(
        'test_cases',
        meta,
        Column('id', db.Integer, primary_key=True),
        Column('name', db.String(255)),
        Column('description', db.String(255)),
        # Column('url', db.String(255)),
        # Column('http_request_method_id', db.Integer),
        Column('issue_id', db.Integer),
        Column('project_id', db.Integer),
        Column('create_at', db.DATETIME(255)),
        Column('update_at', db.DATETIME(255)),
        Column('disabled', db.Boolean),
        # Stringified JSON like
        # {
        #  "type": "API",
        #  "url": "/user/forgot",
        #  "method": "POST",
        #  "method_id": "2"
        # }
        Column('data', db.TEXT),
        Column('type_id', db.Integer))


class TableCaseType():
    meta = db.MetaData()
    stru_tcType = db.Table('test_cases_type', meta,
                           Column('id', db.Integer, primary_key=True),
                           Column('name', db.String(50)))


class TableTestItem():
    meta = db.MetaData()
    stru_testItem = db.Table(
        'test_items',
        meta,
        Column('id', db.Integer, primary_key=True),
        Column('test_case_id', db.Integer),
        Column('project_id', db.Integer),
        Column('issue_id', db.Integer),
        Column('name', db.String(255)),
        Column('is_passed', db.Boolean),
        # Column('value_id', db.Integer),
        # Column('value_info', db.TEXT),
        Column('create_at', db.DATETIME(255)),
        Column('update_at', db.DATETIME(255)),
        Column('disabled', db.Boolean))


class TableTestValue():
    meta = db.MetaData()
    stru_testValue = db.Table('test_values', meta,
                              Column('id', db.Integer, primary_key=True),
                              Column('type_id', db.Integer), # Request = 1, response = 2
                              Column('key', db.String(255)),
                              Column('value', db.Text),
                              Column('location_id', db.Integer), # Header = 1, Body = 2
                              Column('test_item_id', db.Integer),
                              Column('test_case_id', db.Integer),
                              Column('issue_id', db.Integer),
                              Column('project_id', db.Integer),
                              Column('create_at', db.DATETIME(255)),
                              Column('update_at', db.DATETIME(255)),
                              Column('disabled', db.Boolean))


class TableTestResult:
    meta = db.MetaData()
    stru_testResult = db.Table('test_results', meta,
                              Column('id', db.Integer, primary_key=True),
                              Column('project_id', db.Integer),
                              Column('branch', db.String(50)),
                              Column('report', db.String),
                              Column('total', db.Integer),
                              Column('fail', db.Integer),
                              Column('run_at', db.DATETIME(255))
                               )


class TableParameter():
    meta = db.MetaData()
    stru_param = db.Table('parameters', meta,
                          Column('id', db.Integer, primary_key=True),
                          Column('issue_id', db.Integer),
                          Column('project_id', db.Integer),
                          Column('parameter_type_id', db.Integer),
                          Column('name', db.String(50)),
                          Column('description', db.String(100)),
                          Column('limitation', db.String(50)),
                          Column('length', db.Integer),
                          Column('create_at', db.DATETIME(255)),
                          Column('update_at', db.DATETIME(255)),
                          Column('disabled', db.Boolean))


class TableParameterType():
    meta = db.MetaData()
    stru_paramType = db.Table('parameter_types', meta,
                              Column('id', db.Integer, primary_key=True),
                              Column('type', db.String(50)))


class TableRolesPluginRelation():
    meta = db.MetaData()
    stru_rolerelation = db.Table('roles_plugin_relation', meta,
                                 Column('role_id', db.Integer),
                                 Column('plan_role_id', db.Integer))


class TableCheckMarx:
    meta = db.MetaData()
    stru_checkmarx = db.Table('checkmarx', meta,
                              Column('cm_project_id', db.Integer, primary_key=True),
                              Column('repo_id', db.Integer),
                              Column('scan_id', db.Integer),
                              # -1 if report is not registered yet
                              Column('report_id', db.Integer, default=-1),
                              # The time scan registered
                              Column('run_at', db.DATETIME(255)),
                              Column('finished_at', db.DATETIME(255)),
                              Column('finished', db.DATETIME(255)),
                              )
