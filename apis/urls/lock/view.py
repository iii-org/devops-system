from flask_apispec import marshal_with, doc, use_kwargs
from flask_apispec.views import MethodResource
from flask_jwt_extended import jwt_required
from flask_restful import Resource, reqparse
from flask_jwt_extended import jwt_required, get_jwt_identity
import util
from threading import Thread
from urls.lock import router_model
from resources.lock import get_lock_status

import model
import util as util
from model import db
from resources import role
from sqlalchemy.orm.exc import NoResultFound


class LockStatus(Resource):
    @jwt_required()
    def get(self):
        parser = reqparse.RequestParser()
        parser.add_argument('name', type=str, required=True, location="query")
        args = parser.parse_args()

        ret = get_lock_status(args["name"])
        ret["sync_date"] = str(ret["sync_date"])
        return util.success(ret)


@doc(tags=['System'], description='Lock API')
class LockStatusV2(MethodResource):
    @use_kwargs(router_model.LockSchema, location="query")
    @marshal_with(router_model.LockResponse)
    @jwt_required()
    def get(self, **kwargs):
        ret = get_lock_status(kwargs["name"])
        ret["sync_date"] = str(ret["sync_date"])
        return util.success(ret)
