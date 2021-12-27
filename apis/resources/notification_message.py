from flask_restful import Resource, reqparse
from flask_jwt_extended import jwt_required, get_jwt_identity
import json
import util
import datetime
from model import db, NotificationMessage, NotificationMessageReplySlip
from resources import role


def create_notification_message(args):
    row = NotificationMessage(
        message=args['message'],
        type_id=args['type_id'],
        type_parameter=args['type_parameter'],
        no_deadline=args['no_deadline'],
        due_datetime=args['due_datetime'],
        creator_id=get_jwt_identity()['user_id'],
        created_at=datetime.datetime.utcnow(),
        updated_at=datetime.datetime.utcnow()
    )
    db.session.add(row)
    db.session.commit()


def get_notification_message(message_id):
    return NotificationMessage.query.filter_by(id=message_id).first()


def delete_notification_message(message_id):
    row = NotificationMessage.query.filter_by(id=message_id).first()
    db.session.delete(row)
    db.session.commit()


class Message(Resource):
    @ jwt_required
    def post(self):
        role.require_admin()
        parser = reqparse.RequestParser()
        parser.add_argument('message', type=str, required=True)
        parser.add_argument('type_id', type=int, required=True)
        parser.add_argument('type_parameter', type=str, location='json')
        parser.add_argument('no_deadline', type=bool, required=True)
        parser.add_argument('due_datetime', type=str)
        args = parser.parse_args()
        if args.get("type_parameter") is not None:
            args["type_parameter"] = json.loads(args["type_parameter"].replace("\'", "\""))

        return util.success(create_notification_message(args))

    @ jwt_required
    def get(self, message_id):
        return util.success(get_notification_message(message_id))

    @ jwt_required
    def patch(self, message_id):
        pass

    @ jwt_required
    def delete(self, message_id):
        return util.success(delete_notification_message(message_id))
