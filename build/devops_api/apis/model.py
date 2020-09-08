from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()


class User():
    meta = db.MetaData()
    stru_user = db.Table(
        'user', meta,
        db.Column('id', db.Integer, primary_key=True, nullable=True),
        db.Column('name', db.String(255)), db.Column('email', db.String(255)),
        db.Column('phone', db.Integer), db.Column('login', db.String(255)),
        db.Column('password', db.String(255)),
        db.Column('create_at', db.DATETIME(255)),
        db.Column('update_at', db.DATETIME(255)),
        db.Column('disabled', db.Boolean))


class UserPluginRelation():
    meta = db.MetaData()
    stru_user_plug_relation = db.Table(
        'user_plugin_relation', meta, db.Column('user_id', db.Integer),
        db.Column('plan_user_id', db.Integer),
        db.Column('repository_user_id', db.Integer))


class ProjectPluginRelation():
    meta = db.MetaData()
    stru_project_plug_relation = db.Table(
        'project_plugin_relation', meta, db.Column('project_id', db.Integer),
        db.Column('plan_project_id', db.Integer),
        db.Column('git_repository_id', db.Integer),
        db.Column('ci_project_id', db.String),
        db.Column('ci_pipeline_id', db.String))


class GroupsHasUsers():
    meta = db.MetaData()
    stru_groups_has_users = db.Table(
        'groups_has_users', meta,
        db.Column('group_id', db.Integer, nullable=True),
        db.Column('user_id', db.Integer, nullable=True))


class TableGroup():
    meta = db.MetaData()
    stru_group = db.Table('group', meta,
                          db.Column('id', db.Integer, nullable=True),
                          db.Column('name', db.String, nullable=True))


class TableRole():
    meta = db.MetaData()
    stru_role = db.Table('roles', meta,
                         db.Column('id', db.Integer, nullable=True),
                         db.Column('name', db.String, nullable=True))


class ProjectUserRole():
    meta = db.MetaData()
    stru_project_user_role = db.Table('project_user_role', meta,
                                      db.Column('project_id', db.Integer),
                                      db.Column('user_id', db.Integer),
                                      db.Column('role_id', db.Integer))


class TableProjects():
    meta = db.MetaData()
    stru_projects = db.Table('projects', meta, db.Column('id', db.Integer),
                             db.Column('name', db.String))


class TableRequirement():
    meta = db.MetaData()
    stru_rqmt = db.Table('requirements', meta,
                         db.Column('id', db.Integer, primary_key=True),
                         db.Column('project_id', db.Integer),
                         db.Column('issue_id', db.Integer),
                         db.Column('flow_info', db.TEXT),
                         db.Column('create_at', db.DATETIME(255)),
                         db.Column('update_at', db.DATETIME(255)),
                         db.Column('disabled', db.Boolean))

class TableFlow():
    meta = db.MetaData()
    stru_flow = db.Table('flows', meta,
                         db.Column('id', db.Integer, primary_key=True),
                         db.Column('project_id', db.Integer),
                         db.Column('issue_id', db.Integer),
                         db.Column('requirement_id', db.Integer),
                         db.Column('type_id', db.Integer),
                         db.Column('name', db.String),
                         db.Column('description', db.String),
                         db.Column('serial_id',db.Integer),
                         db.Column('create_at', db.DATETIME(255)),
                         db.Column('update_at', db.DATETIME(255)),
                         db.Column('disabled', db.Boolean))


class TableTestCase():
    meta = db.MetaData()
    stru_testCase = db.Table(
        'test_cases',
        meta,
        db.Column('id', db.Integer, primary_key=True),
        db.Column('name', db.String(255)),
        db.Column('description', db.String(255)),
        # db.Column('url', db.String(255)),
        # db.Column('http_request_method_id', db.Integer),
        db.Column('issue_id', db.Integer),
        db.Column('project_id', db.Integer),
        db.Column('create_at', db.DATETIME(255)),
        db.Column('update_at', db.DATETIME(255)),
        db.Column('disabled', db.Boolean),
        # Stringified JSON like
        # {
        #  "type": "API",
        #  "url": "/user/forgot",
        #  "method": "POST",
        #  "method_id": "2"
        # }
        db.Column('data', db.TEXT),
        db.Column('type_id', db.Integer))


class TableHttpMethod():
    meta = db.MetaData()
    stru_httpMethod = db.Table('http_method', meta,
                               db.Column('id', db.Integer, primary_key=True),
                               db.Column('type', db.String(50)))


class TableCaseType():
    meta = db.MetaData()
    stru_tcType = db.Table('test_cases_type', meta,
                           db.Column('id', db.Integer, primary_key=True),
                           db.Column('name', db.String(50)))


class TableTestItem():
    meta = db.MetaData()
    stru_testItem = db.Table(
        'test_items',
        meta,
        db.Column('id', db.Integer, primary_key=True),
        db.Column('test_case_id', db.Integer),
        db.Column('project_id', db.Integer),
        db.Column('issue_id', db.Integer),
        db.Column('name', db.String(255)),
        db.Column('is_passed', db.Boolean),
        # db.Column('value_id', db.Integer),
        # db.Column('value_info', db.TEXT),
        db.Column('create_at', db.DATETIME(255)),
        db.Column('update_at', db.DATETIME(255)),
        db.Column('disabled', db.Boolean))


class TableTestValue():
    meta = db.MetaData()
    stru_testValue = db.Table('test_values', meta,
                              db.Column('id', db.Integer, primary_key=True),
                              db.Column('type_id', db.Integer), # Request = 1, response = 2
                              db.Column('key', db.String(255)),
                              db.Column('value', db.Text),
                              db.Column('location_id', db.Integer), # Header = 1, Body = 2
                              db.Column('test_item_id', db.Integer),
                              db.Column('test_case_id', db.Integer),
                              db.Column('issue_id', db.Integer),
                              db.Column('project_id', db.Integer),
                              db.Column('create_at', db.DATETIME(255)),
                              db.Column('update_at', db.DATETIME(255)),
                              db.Column('disabled', db.Boolean))


class TableTestResult:
    meta = db.MetaData()
    stru_testResult = db.Table('test_results', meta,
                              db.Column('id', db.Integer, primary_key=True),
                              db.Column('project_id', db.Integer),
                              db.Column('branch', db.String(50)),
                              db.Column('total', db.Integer),
                              db.Column('fail', db.Integer),
                              db.Column('run_at', db.DATETIME(255))
                               )

class TableParameter():
    meta = db.MetaData()
    stru_param = db.Table('parameters', meta,
                          db.Column('id', db.Integer, primary_key=True),
                          db.Column('issue_id', db.Integer),
                          db.Column('project_id', db.Integer),
                          db.Column('parameter_type_id', db.Integer),
                          db.Column('name', db.String(50)),
                          db.Column('description', db.String(100)),
                          db.Column('limitation', db.String(50)),
                          db.Column('length', db.Integer),
                          db.Column('create_at', db.DATETIME(255)),
                          db.Column('update_at', db.DATETIME(255)),
                          db.Column('disabled', db.Boolean))


class TableParameterType():
    meta = db.MetaData()
    stru_paramType = db.Table('parameter_types', meta,
                              db.Column('id', db.Integer, primary_key=True),
                              db.Column('type', db.String(50)))


class TableRolesPluginRelation():
    meta = db.MetaData()
    stru_rolerelation = db.Table('roles_plugin_relation', meta,
                              db.Column('role_id', db.Integer),
                              db.Column('plan_role_id', db.Integer))
