import os
import config
import model
from model import db
from resources.logger import logger
from migrate.upgrade_function.ui_route_upgrade import ui_route_first_version
from migrate.upgrade_function import v1_22_upgrade

# Each time you add a migration, add a version code here.

VERSIONS = []
ONLY_UPDATE_DB_MODELS = ['1.22.0.1', '1.22.0.2']


def upgrade(version):
    '''
    Upgraded function need to check it can handle multi calls situation,
    just in case multi pods will call it several times.
    ex. Insert data need to check data has already existed or not.
    '''
    if version in ONLY_UPDATE_DB_MODELS:
        alembic_upgrade()


def init():
    new = model.NexusVersion(api_version=VERSIONS[-1])
    db.session.add(new)
    db.session.commit()

    # For the new server, need to add some default value
    # 1.22
    v1_22_upgrade.insert_default_value_in_lock()
    v1_22_upgrade.insert_default_value_in_system_parameter()
    ui_route_first_version()




def needs_upgrade(current, target):
    r = current.split('.')
    c = target.split('.')
    for i in range(4):
        if int(c[i]) > int(r[i]):
            return True
        elif int(c[i]) < int(r[i]):
            return False
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


def current_version():
    if db.engine.has_table(model.NexusVersion.__table__.name):
        # Cannot write in ORM here since NexusVersion table itself may be modified
        result = db.engine.execute('SELECT api_version FROM nexus_version')
        row = result.fetchone()
        result.close()
        if row is not None:
            current = row['api_version']
        else:
            # This is a new server, so NexusVersion table scheme should match the ORM
            current = '1.22.9.9'
            new = model.NexusVersion(api_version=current)
            db.session.add(new)
            db.session.commit()
    else:
        # Backward compatibility
        if os.path.exists('.api_version'):
            with (open('.api_version', 'r')) as f:
                current = f.read()
        else:
            current = '1.22.9.9'
    return current


def run():
    current = current_version()
    try:
        for version in VERSIONS:
            if needs_upgrade(current, version):
                current = version
                row = model.NexusVersion.query.first()
                row.api_version = current
                db.session.commit()
                logger.info('Upgrade to {0}'.format(version))
                upgrade(version)
    except Exception as e:
        raise e
