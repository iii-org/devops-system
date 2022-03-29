from model import Lock, db
import util

def get_lock_status(name):
    lock_info = Lock.query.filter_by(name=name).first()
    if lock_info is None:
        return {}
    return {
        "name": lock_info.name,
        "is_lock": lock_info.is_lock,
        "sync_date": lock_info.sync_date if lock_info.sync_date is not None else None,
    }

def update_lock_status(name, is_lock=False, sync_date=None):
    lock_redmine = Lock.query.filter_by(name=name).first()
    if lock_redmine is not None:
        lock_redmine.is_lock = is_lock
        if sync_date is not None:
            lock_redmine.sync_date = sync_date
    db.session.commit()


