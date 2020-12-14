import os

import util
import config
import model
from model import db, ProjectPluginRelation, Project, UserPluginRelation, User, ProjectUserRole
from resources import harbor, role, kubernetesClient
import resources.rancher as rancher
from resources.logger import logger

from flask_restful import Resource

VERSION_FILE_NAME = '.api_version'
# Each time you add a migration, add a version code here.
VERSIONS = ['0.9.2', '0.9.2.1', '0.9.2.2', '0.9.2.3', '0.9.2.4']

ran = rancher.Rancher()

def upgrade(version):
    if version == '0.9.2':
        cleanup_change_to_orm()
        alembic_upgrade()
        create_harbor_users()
        create_harbor_projects()
    elif version in {'0.9.2.1', '0.9.2.2', '0.9.2.3'}:
        alembic_upgrade()
    elif version == '0.9.2.4':
        create_k8s_user()
        create_k8s_namespsace()
        

def create_k8s_user():
    # get db user list
    rows = db.session.query(User, UserPluginRelation)\
        .join(User).all()
    k8s_sa_list = kubernetesClient.list_service_account()
    for row in rows:
        user_sa_name = util.encode_k8s_sa(row.User.login)
        if user_sa_name not in k8s_sa_list:
            print("still not create sa user: {0}".format(row.UserPluginRelation.kubernetes_sa_name))
            kubernetesClient.create_service_account(user_sa_name)
            row.UserPluginRelation.kubernetes_sa_name = user_sa_name
        db.session.commit()


def create_k8s_namespsace():
    rows = db.session.query(ProjectPluginRelation, Project). \
        join(Project).all()
    namespace_list = kubernetesClient.list_namespace()
    for row in rows:
        if row.Project.name not in namespace_list:
            print("need create k8s namespace project: {0}".format(row.Project.name))
            kubernetesClient.create_namespace(row.Project.name)
            kubernetesClient.create_role_in_namespace(row.Project.name)
            members = db.session.query(ProjectUserRole, UserPluginRelation). \
                join(UserPluginRelation, ProjectUserRole.user_id == UserPluginRelation.user_id). \
                filter(ProjectUserRole.project_id == row.ProjectPluginRelation.project_id).all()
            for member in members:
                print("attach member {0} into k8snamespace {1}".format(member, row.Project.name))
                kubernetesClient.create_role_binding(row.Project.name,
                    member.UserPluginRelation.kubernetes_sa_name)
            ran.rc_add_namespace_into_rc_project(row.Project.name)
            

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
            u = model.ProjectUserRole.query.filter_by(user_id=row.user_id, project_id=-1).one()
            hid = harbor.hb_create_user(args, is_admin=u.role_id == role.ADMIN.id)
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
    if len(r) == 3:
        r.extend([0])
    if len(c) == 3:
        c.extend([0])
    for i in range(4):
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
    os_ret = os.system('alembic upgrade head')
    if os_ret != 0:
        raise RuntimeError('Alembic has error, process stop.')


def run():
    current = '0.0.0'
    if os.path.exists(VERSION_FILE_NAME):
        with open(VERSION_FILE_NAME, 'r') as f:
            current = f.read()
    try:
        for version in VERSIONS:
            if needs_upgrade(current, version):
                logger.info('Upgrade to {0}'.format(version))
                upgrade(version)
                current = version
    except Exception as e:
        raise e
    finally:
        with (open(VERSION_FILE_NAME, 'w')) as f:
            f.write(current)
