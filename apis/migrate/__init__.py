import io
import logging
import os
from pathlib import Path

from alembic.command import current, upgrade
from alembic.config import Config
from alembic.script import ScriptDirectory

import config
import model
from migrate.upgrade_function import v1_22_upgrade
from migrate.upgrade_function.ui_route_upgrade import ui_route_first_version
from model import db, UIRouteData, PluginSoftware, SystemParameter
from resources.logger import logger
from resources.router import update_plugin_hidden

_config_file: Path = config.BASE_FOLDER / "alembic.ini"
_script_location: Path = config.BASE_FOLDER / "alembic"

_alembic_config: Path = config.BASE_FOLDER / "alembic.ini"
_alembic_config_template: Path = config.BASE_FOLDER / "_alembic.ini"

_buffer: io.StringIO = io.StringIO()
_logger: logging.Logger = logging.getLogger("alembic.runtime.migration")

# Rebuild init file since ini is not git tracked
if not os.path.isfile(_alembic_config):
    with open(_alembic_config, "w") as ini:
        with open(_alembic_config_template, "r") as template:
            for line in template:
                if line.startswith("sqlalchemy.url"):
                    ini.write(
                        f"sqlalchemy.url = {config.get('SQLALCHEMY_DATABASE_URI').replace('%', '%%')}\n"
                    )
                else:
                    ini.write(line)

# Each time you add a migration, add a version code here.

VERSIONS = [
    "1.22.0.1",
    "1.22.0.2",
    "1.22.0.3",
    "1.22.0.4",
    "1.22.0.5",
    "1.23.0.1",
    "1.23.0.2",
    "1.24.0.1",
    "1.24.0.2",
    "1.25.0.1",
    "1.25.0.3",
    "1.25.0.4",
    "1.25.0.5",
    "1.25.0.6",
    "1.25.0.7",
    "1.26.0.1",
    "1.26.0.2",
    "1.26.0.3",
    "1.26.0.4",
    "1.26.1.0",
    "1.27.0.1",
    "1.28.0.1",
    "1.28.0.2",
    "1.28.0.3",
    "1.28.0.4",
    "1.28.0.5",
    "1.28.0.6",
    "1.28.0.7",
]


def _upgrade(version):
    """
    Upgraded function need to check it can handle multi calls situation,
    just in case multi pods will call it several times.
    ex. Insert data need to check data has already existed or not.
    """
    # TODO: Rewrite this function since when someone didn't upgrade from a long time
    #  the model structure won't be the same obviously
    if version == "1.22.0.4":
        recreate_ui_route()
    elif version == "1.22.0.5":
        if SystemParameter.query.filter_by(name="upload_file_size").first() is None:
            row = SystemParameter(
                name="upload_file_size", value={"upload_file_size": 5}, active=True
            )
            db.session.add(row)
            db.session.commit()
    elif version == "1.23.0.1":
        recreate_ui_route()
    elif version == "1.25.0.1":
        model.NotificationMessage.query.filter_by(
            alert_service_id=303, close=False
        ).delete()
        db.session.commit()
    elif version == "1.26.0.2":
        recreate_ui_route()
    elif version == "1.27.0.1":
        pass
    elif version == "1.28.0.3":
        recreate_ui_route()
    elif version == "1.28.0.5":
        from resources.tag import order_pj_tags_by_id

        order_pj_tags_by_id()
    elif version == "1.28.0.6":
        model.WebInspect.query.delete()
        db.session.commit()


def recreate_ui_route():
    UIRouteData.query.delete()
    ui_route_first_version()

    for plugin_software in PluginSoftware.query.all():
        update_plugin_hidden(plugin_software.name, plugin_software.disabled)


def init():
    latest_api_version, deploy_version = VERSIONS[-1], config.get("DEPLOY_VERSION")
    logger.info(
        f"Creat NexusVersion, api_version={latest_api_version}, deploy_version={deploy_version}"
    )
    new = model.NexusVersion(
        api_version=latest_api_version, deploy_version=deploy_version
    )
    db.session.add(new)
    db.session.commit()

    # For the new server, need to add some default value
    # 1.22
    logger.info("Start insert default value in v1.22")
    v1_22_upgrade.insert_default_value_in_lock()
    logger.info("Insert default value in Lock done")
    v1_22_upgrade.insert_default_value_in_system_parameter()
    logger.info("Insert default value in SystemParameter done")
    ui_route_first_version()
    logger.info("Insert default value in UiRouteData done")


def needs_upgrade(current, target):
    r = current.split(".")
    c = target.split(".")
    for i in range(4):
        if int(c[i]) > int(r[i]):
            return True
        elif int(c[i]) < int(r[i]):
            return False
    return False


def alembic_get_config(to_stringio: bool = False) -> Config:
    """
    Get alembic config

    Args:
        to_stringio: If True, return config from stdout to StringIO

    Returns:
        Config: Alembic config
    """
    # Reset before use
    _buffer.seek(0)

    if not to_stringio:
        _config: Config = Config(f"{_config_file}")

    else:
        _config: Config = Config(f"{_config_file}", stdout=_buffer)

    _config.set_main_option("script_location", f"{_script_location}")

    return _config


def alembic_upgrade(version: str = "head") -> None:
    """
    Upgrade alembic

    Args:
        version: revision to upgrade

    Returns:
        None
    """
    upgrade(alembic_get_config(), version)


def alembic_need_upgrade() -> bool:
    """
    Check if alembic need upgrade

    Returns:
        bool: True if alembic need upgrade
    """
    if alembic_get_current() == alembic_get_head():
        return False
    return True


def alembic_get_current() -> str:
    """
    Get current alembic revision

    Returns:
        str: Current alembic revision
    """
    # https://stackoverflow.com/a/61770854
    _logger.disabled = True

    current(alembic_get_config(True))
    _out: str = _buffer.getvalue().strip()

    _logger.disabled = False
    return _out[:12]


def alembic_get_head() -> str:
    """
    Get alembic head revision

    Returns:
        str: Alembic head revision
    """
    _script: ScriptDirectory = ScriptDirectory.from_config(alembic_get_config())

    return _script.get_current_head()


def current_version():
    if db.engine.has_table(model.NexusVersion.__table__.name):
        # Cannot write in ORM here since NexusVersion table itself may be modified
        result = db.engine.execute("SELECT api_version FROM nexus_version")
        row = result.fetchone()
        result.close()
        if row is not None:
            current = row["api_version"]
        else:
            # This is a new server, so NexusVersion table scheme should match the ORM
            current = "1.22.9.9"
            new = model.NexusVersion(api_version=current)
            db.session.add(new)
            db.session.commit()
    else:
        # Backward compatibility
        if os.path.exists(".api_version"):
            with open(".api_version", "r") as f:
                current = f.read()
        else:
            current = "1.22.9.9"
    return current


def run():
    current = current_version()
    try:
        # Upgrade alembic no matter what, run only once before version upgrade
        alembic_upgrade()
        for version in VERSIONS:
            if needs_upgrade(current, version):
                current, deploy_version = version, config.get("DEPLOY_VERSION")
                row = model.NexusVersion.query.first()
                if row.deploy_version != deploy_version:
                    row.deploy_version = deploy_version
                row.api_version = current
                db.session.commit()
                logger.info("Upgrade to {0}".format(version))
                _upgrade(version)
    except Exception as e:
        logger.exception(str(e))
        raise e
