from flask_restful import Resource, reqparse
from flask_jwt_extended import jwt_required, get_jwt_identity
from flask_socketio import Namespace, emit, send, join_room, leave_room
import json
import util
import datetime
from model import db, NotificationMessage, NotificationMessageReplySlip
from resources import role


def get_notification_message_list():
    out = []
    for message in NotificationMessage.query.all():
        out.append(json.loads(str(message)))
    return out


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


def update_notification_message(message_id, args):
    message = NotificationMessage.query.filter_by(id=message_id).first()
    for k, v in args.items():
        setattr(message, k, v)
    db.session.commit()


def get_notification_message(message_id):
    return json.loads(str(NotificationMessage.query.filter_by(id=message_id).first()))


def delete_notification_message(message_id):
    row = NotificationMessage.query.filter_by(id=message_id).first()
    db.session.delete(row)
    db.session.commit()


def create_notification_message_reply_slip(user_id, args):
    row_list = []
    for message_id in args["message_ids"]:
        row = NotificationMessageReplySlip(
            message_id=message_id,
            user_id=user_id,
            created_at=datetime.datetime.utcnow(),
        )
        row_list.append(row)
    db.session.add_all(row_list)
    db.session.commit()


class NotificationRoom(object):

    def get_message(self, data):

        rows = NotificationMessage.query.order_by(NotificationMessage.id.desc()).all()
        for row in rows:
            print(str(row))
            emit("system_message", str(row), namespace="/get_notification_message", to=data["room"])


class GetNotificationMessage(Namespace):

    def on_connect(self):
        print('Connect')

    def on_disconnect(self):
        print('Client disconnected')

    def on_join_room(self, data):
        print('Join room')
        join_room(data['room'])

    def on_leave_room(self, data):
        print('Leave room')
        leave_room(data['room'])

    def on_get_message(self, data):
        notification_room.get_message(data)


class Message(Resource):
    @ jwt_required
    def post(self):
        role.require_admin()
        parser = reqparse.RequestParser()
        parser.add_argument('message', type=str, required=True)
        parser.add_argument('type_id', type=int, required=True)
        parser.add_argument('type_parameter', type=str)
        parser.add_argument('no_deadline', type=bool, required=True)
        parser.add_argument('due_datetime', type=str)
        args = parser.parse_args()
        if args.get("type_parameter") is not None:
            args["type_parameter"] = json.loads(args["type_parameter"].replace("\'", "\""))

        return util.success(create_notification_message(args))

    @ jwt_required
    def get(self, message_id):
        role.require_admin()
        return util.success(get_notification_message(message_id))

    @ jwt_required
    def patch(self, message_id):
        role.require_admin()
        parser = reqparse.RequestParser()
        parser.add_argument('message', type=str)
        parser.add_argument('type_id', type=int)
        parser.add_argument('type_parameter', type=str)
        parser.add_argument('no_deadline', type=bool)
        parser.add_argument('due_datetime', type=str)
        args = parser.parse_args()
        args = {k: v for k, v in args.items() if v is not None}
        if args.get("type_parameter") is not None:
            args["type_parameter"] = json.loads(args["type_parameter"].replace("\'", "\""))
        update_notification_message(message_id, args)
        return util.success()

    @ jwt_required
    def delete(self, message_id):
        role.require_admin()
        return util.success(delete_notification_message(message_id))


class MessageList(Resource):

    @ jwt_required
    def get(self):
        role.require_admin()
        return util.success(get_notification_message_list())


class MessageReply(Resource):
    @ jwt_required
    def post(self, user_id):
        role.require_user_himself(user_id, even_admin=True)
        parser = reqparse.RequestParser()
        parser.add_argument('message_ids', type=list, location='json', required=True)
        args = parser.parse_args()
        return util.success(create_notification_message_reply_slip(user_id, args))


notification_room = NotificationRoom()
