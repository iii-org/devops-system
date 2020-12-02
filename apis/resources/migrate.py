import os

import config
import model
from model import db, ProjectPluginRelation, Project, UserPluginRelation, User, ProjectUserRole
from resources import harbor
from resources.logger import logger

VERSION_FILE_NAME = '.api_version'
# Each time you add a migration, add a version code here.
VERSIONS = ['0.9.2']


def upgrade(version):
    if version == '0.9.2':
        cleanup_change_to_orm()
        alembic_upgrade()
        create_harbor_projects()
        create_harbor_users()


def create_harbor_projects():
    rows = db.session.query(ProjectPluginRelation, Project.name). \
        join(Project).all()
    for row in rows:
        if row.ProjectPluginRelation.harbor_project_id is None:
            harbor_project_id = harbor.hb_create_project(row.name)
            row.ProjectPluginRelation.harbor_project_id = harbor_project_id
            members = db.session.query(ProjectUserRole, UserPluginRelation). \
                join(UserPluginRelation, ProjectUserRole.user_id == UserPluginRelation.user_id). \
                filter(ProjectUserRole.project_id == row.ProjectPluginRelation.project_id
                       ).all()
            for m in members:
                harbor.hb_add_member(harbor_project_id,
                                     m.UserPluginRelation.harbor_user_id)
            db.session.commit()


def create_harbor_users():
    rows = db.session.query(UserPluginRelation, User). \
        join(User).all()
    for row in rows:
        if row.UserPluginRelation.harbor_user_id is None:
            args = {
                'login': row.User.login,
                'password': 'HarborFromIIIDevOps2020',
                'name': row.User.name,
                'email': row.User.email
            }
            hid = harbor.hb_create_user(args)
            row.UserPluginRelation.harbor_user_id = hid
            db.session.commit()


def cleanup_project_gone(rows):
    for row in rows:
        p_count = model.Project.query.filter_by(id=row.project_id).count()
        if p_count == 0:
            db.session.delete(row)
    db.session.commit()


def cleanup_change_to_orm():
    # Cleanup corrupted data violating foreign key constraints
    cleanup_project_gone(model.Flows.query.all())
    cleanup_project_gone(model.Parameters.query.all())
    cleanup_project_gone(model.Requirements.query.all())
    cleanup_project_gone(model.TestCases.query.all())
    # Insert dummy project
    p = model.Project.query.filter_by(id=-1).first()
    if p is None:
        new = model.Project(id=-1, name='dummy-project', disabled=False)
        db.session.add(new)
        db.session.commit()


def init():
    with (open(VERSION_FILE_NAME, 'w')) as f:
        f.write(VERSIONS[-1])
        f.close()


def needs_upgrade(current, target):
    r = current.split('.')
    c = target.split('.')
    for i in range(len(c)):
        if int(c[i]) > int(r[i]):
            return True
    return False


def alembic_upgrade():
    # Rewrite ini file
    with open('alembic.ini', 'w') as ini:
        with open('_alembic.ini', 'r') as template:
            for line in template:
                if line.startswith('sqlalchemy.url'):
                    ini.write('sqlalchemy.url = {0}\n'.format(
                        config.get('SQLALCHEMY_DATABASE_URI')))
                else:
                    ini.write(line)
    os.system('alembic upgrade head')


def run():
    current = '0.0.0'
    if os.path.exists(VERSION_FILE_NAME):
        with open(VERSION_FILE_NAME, 'r') as f:
            current = f.read()
    for version in VERSIONS:
        if needs_upgrade(current, version):
            logger.info('Upgrade to {0}'.format(version))
            upgrade(version)
            current = version
    with (open(VERSION_FILE_NAME, 'w')) as f:
        f.write(current)
