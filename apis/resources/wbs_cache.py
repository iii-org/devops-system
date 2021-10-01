from flask_restful import Resource, reqparse
from flask_jwt_extended import jwt_required, get_jwt_identity
from model import WBSCache, db
import util


def create_wbs_cache(user_id, pj_id, display_field=[]):
    wbs_cache = WBSCache(
        user_id=user_id, project_id=pj_id, display_field=display_field)
    db.session.add(wbs_cache)
    db.session.commit()


def get_wbs_cache(user_id, pj_id):
    lock_info = WBSCache.query.filter_by(user_id=user_id, project_id=pj_id).first()
    if lock_info is None:
        create_wbs_cache(user_id, pj_id)
        return []

    return lock_info.display_field


def put_wbs_cache(user_id, pj_id, display_field):
    lock_info = WBSCache.query.filter_by(user_id=user_id, project_id=pj_id).first()
    if lock_info is None:
        create_wbs_cache(user_id, pj_id, display_field)
    else:
        lock_info.display_field = display_field
        db.session.commit()
    return display_field


# --------------------- Resources ---------------------
class WbsCache(Resource):
    @jwt_required
    def get(self):
        user_id = get_jwt_identity()['user_id']
        parser = reqparse.RequestParser()
        parser.add_argument('project_id', type=int, required=True)
        args = parser.parse_args()

        return util.success(get_wbs_cache(user_id, args["project_id"]))

    @jwt_required
    def put(self):
        user_id = get_jwt_identity()['user_id']
        parser = reqparse.RequestParser()
        parser.add_argument('project_id', type=int, required=True)
        parser.add_argument('display_fields', type=str, action='append', required=True)
        args = parser.parse_args()

        return util.success(put_wbs_cache(user_id, args["project_id"], args["display_fields"]))
