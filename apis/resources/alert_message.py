from flask_restful import Resource, reqparse

import model
import json
import util as util
from model import db, AlertMessage
from resources import apiError
from datetime import datetime


def create_alert_messages(args):
    row = AlertMessage(
        resource_type=args["resource_type"],
        alert_code=args["alert_code"],
        message=args["message"],
        detail=args.get("detail"),
        create_at=datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    )
    db.session.add(row)
    db.session.commit()

# --------------------- Resources ---------------------
class AlertMessages(Resource):
    def post(self):
        parser = reqparse.RequestParser()
        parser.add_argument('resource_type', type=str, required=True)
        parser.add_argument('alert_code', type=int, required=True)
        parser.add_argument('message', type=str, required=True)
        parser.add_argument('detail', type=str, location='json')
        args = parser.parse_args()
        args["detail"] = json.loads(args["detail"].replace("\'", "\""))

        return util.success(create_alert_messages(args))
