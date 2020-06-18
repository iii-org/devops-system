from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

class Project_relationship(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    rm_project_id = db.Column(db.Integer)
    rm_project_name = db.Column(db.String)
    gl_project_id = db.Column(db.Integer)
    gl_project_name = db.Column(db.String)
    ran_project_id = db.Column(db.Integer)
    ran_project_name = db.Column(db.String)


class Note(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    body = db.Column(db.Text)