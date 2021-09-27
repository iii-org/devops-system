from flask_restful import Resource, reqparse
from model import Lock
import util



def get_lock_status(name):
    lock_info = Lock.query.filter_by(name=name).first()
    if lock_info is None:
        return {}
    return {
        "name": lock_info.name,
        "is_lock": lock_info.is_lock,
        "sync_date": str(lock_info.sync_date),
    }

# --------------------- Resources ---------------------
class LockStatus(Resource):
    def get(self):
        parser = reqparse.RequestParser()
        parser.add_argument('name', type=str, required=True)
        args = parser.parse_args()

        return util.success(get_lock_status(args["name"]))
