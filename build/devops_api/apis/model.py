from flask_sqlalchemy import SQLAlchemy 

db = SQLAlchemy()

class User():
    meta = db.MetaData()
    stru_user = db.Table('user', meta,
                            db.Column(
                                'id', db.Integer, primary_key=True, nullable=True),
                            db.Column(
                                'name', db.String(255)),
                            db.Column(
                                'username', db.String(255)),
                            db.Column(
                                'email', db.String(255)),
                            db.Column(
                                'phone', db.Integer),
                            db.Column(
                                'login', db.String(255)),
                            db.Column(
                                'password', db.String(255)),
                            db.Column(
                                'create_at', db.DATETIME(255)),
                            db.Column(
                                'update_at', db.DATETIME(255)),
                            db.Column(
                                'disable', db.Boolean)
                        )

class UserPluginRelation():
    meta = db.MetaData()
    stru_user_plug_relation = db.Table('user_plugin_relation', meta,
                            db.Column(
                                'user_id', db.Integer),
                            db.Column(
                                'plan_user_id', db.Integer),
                            db.Column(
                                'repository_user_id', db.Integer)
                        )

class ProjectPluginRelation():
    meta = db.MetaData()
    stru_project_plug_relation = db.Table('project_plugin_relation', meta,
                            db.Column(
                                'project_id', db.Integer),
                            db.Column(
                                'plan_project_id', db.Integer),
                            db.Column(
                                'git_repository_id', db.Integer),
                            db.Column(
                                'ci_project_id', db.String),
                            db.Column(
                                'ci_pipeline_id', db.String)
                        )

class GroupsHasUsers():
    meta = db.MetaData()
    stru_groups_has_users = db.Table('groups_has_users', meta,
                            db.Column(
                                'group_id', db.Integer, nullable=True),
                            db.Column(
                                'user_id', db.Integer, nullable=True)
                        )

class ProjectUserRole():
    meta = db.MetaData()
    stru_project_user_role = db.Table('project_user_role', meta,
                            db.Column(
                                'project_id', db.Integer),
                            db.Column(
                                'user_id', db.Integer),
                            db.Column(
                                'role_id', db.Integer)
                        )