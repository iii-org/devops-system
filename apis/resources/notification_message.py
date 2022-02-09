from flask_restful import Resource, reqparse
from flask_jwt_extended import jwt_required, get_jwt_identity
from flask_socketio import Namespace, emit, join_room, leave_room
from sqlalchemy.sql import and_
import json
import util
import datetime
from model import db, NotificationMessage, NotificationMessageReplySlip, ProjectUserRole, User
from resources import role
from resources.apiError import DevOpsError, resource_not_found, not_enough_authorization, argument_error

'''
websocket parameters:
{"user_id"=234}

Notification type:
type_id=1(All):  {}
type_id=2(By project) {
    "project_id": 3
}
type_id=3(By user) {
    "user_id": 314
}
'''


def parameter_check(args):
    if args.get("alert_level") not in (1, 2, 3, 4):
        raise DevOpsError(400, 'Argument alert_level not in (1, 2, 3, 4).',
                          error=argument_error('alert_level'))
    elif args.get("type_id") not in (1, 2, 3):
        raise DevOpsError(400, 'Argument type_id not in (1,2,3).',
                          error=argument_error('type_id'))
    elif args.get("type_id") == 2 and 'project_id' not in json.loads(args["type_parameter"]):
        raise DevOpsError(400, 'Argument project_id not exist in type_parameter.',
                          error=argument_error('project_id'))
    elif args.get("type_id") == 3 and 'user_id' not in json.loads(args["type_parameter"]):
        raise DevOpsError(400, 'Argument user_id not exist in type_parameter.',
                          error=argument_error('user_id'))


def get_notification_message_list(args):
    out = []
    page_dict = None
    base_query = NotificationMessage.query
    if args['limit'] is not None or args['offset'] is not None:
        base_query, page_dict = util.orm_pagination(base_query, args['limit'], args['offset'])
    rows = base_query.all()

    if get_jwt_identity()["role_id"] == 5:
        for row in rows:
            out.append(json.loads(str(row)))
    else:
        projects = db.session.query(ProjectUserRole.project_id).filter(and_(
            ProjectUserRole.user_id == get_jwt_identity()["user_id"], ProjectUserRole.project_id != -1)).all()
        for row in rows:
            if row.type_id == 2 and (row.type_parameter['project_id'],) not in projects:
                continue
            elif row.type_id == 3 and row.type_parameter['user_id'] != get_jwt_identity()["user_id"]:
                continue
            else:
                out.append(json.loads(str(row)))
    out_dict = {'notification_message_list': out}
    if page_dict:
        out_dict['page'] = page_dict
    return out_dict


def create_notification_message(args):
    row = NotificationMessage(
        alert_level=args['alert_level'],
        message=args['message'],
        type_id=args['type_id'],
        type_parameter=args['type_parameter'],
        creator_id=get_jwt_identity()['user_id'],
        created_at=datetime.datetime.utcnow(),
        updated_at=datetime.datetime.utcnow()
    )
    db.session.add(row)
    db.session.commit()
    notification_room.send_message_to_all(row.id)


def update_notification_message(message_id, args):
    message = NotificationMessage.query.filter_by(id=message_id).first()
    for k, v in args.items():
        setattr(message, k, v)
    db.session.commit()


def get_notification_message(message_id):
    row = NotificationMessage.query.filter_by(id=message_id).first()
    if row:
        if get_jwt_identity()['role_id'] == 5 or row.type_id == 1 or \
                (row.type_id == 3 and row.type_parameter["user_id"] == get_jwt_identity()['user_id']):
            return json.loads(str(row))
        else:
            projects = db.session.query(ProjectUserRole.project_id).filter(and_(
                ProjectUserRole.user_id == get_jwt_identity()["user_id"], ProjectUserRole.project_id != -1)).all()
            if row.type_id == 2 and (row.type_parameter["project_id"],) in projects:
                return json.loads(str(row))
            else:
                return not_enough_authorization(message_id, get_jwt_identity()["user_id"])
    else:
        return resource_not_found()


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

    def send_message_to_all(self, message_id):
        message_row = NotificationMessage.query.filter_by(id=message_id).first()
        if message_row.type_id == 1:
            # Send message to all
            # Get all user list
            user_rows = User.query.all()
            # Send message
            for user_row in user_rows:
                emit("system_message", str(message_row), namespace="/get_notification_message",
                     to=f"user/{user_row.id}")
        elif message_row.type_id == 2:
            # Send message to user in project
            # Get all user list in projects
            user_rows = ProjectUserRole.query.filter_by(project_id=message_row.type_parameter['project_id']).all()
            # Send message
            for user_row in user_rows:
                emit("system_message", str(message_row), namespace="/get_notification_message",
                     to=f"user/{user_row.user_id}")
        elif message_row.type_id == 3:
            # Send message to the user
            emit("system_message", str(message_row), namespace="/get_notification_message",
                 to=f"user/{message_row.type_parameter['user_id']}")

    def get_message(self, data):
        rows = db.session.query(NotificationMessage).outerjoin(
            NotificationMessageReplySlip, and_(NotificationMessageReplySlip.user_id == data['user_id'],
                                               NotificationMessage.id == NotificationMessageReplySlip.message_id)
        ).filter(NotificationMessageReplySlip.id == None).all()

        projects = db.session.query(ProjectUserRole.project_id).filter(and_(
            ProjectUserRole.user_id == data['user_id'], ProjectUserRole.project_id != -1)).all()
        for row in rows:
            if row.type_id == 2 and (row.type_parameter['project_id'],) not in projects:
                continue
            if row.type_id == 3 and row.type_parameter['user_id'] != data['user_id']:
                continue
            emit("system_message", str(row), namespace="/get_notification_message", to=f"user/{data['user_id']}")


class GetNotificationMessage(Namespace):

    def on_connect(self):
        print('Connect')

    def on_disconnect(self):
        print('Client disconnected')

    def on_join_room(self, data):
        # verify jwt token
        # verify user_id
        if "user_id" not in data:
            return
        print('Join room')
        join_room(f"user/{data['user_id']}")

    def on_leave_room(self, data):
        print('Leave room')
        leave_room(f"user/{data['user_id']}")

    def on_get_message(self, data):
        notification_room.get_message(data)


class Message(Resource):
    @ jwt_required
    def post(self):
        role.require_admin()
        parser = reqparse.RequestParser()
        parser.add_argument('alert_level', type=int, required=True)
        parser.add_argument('message', type=str, required=True)
        parser.add_argument('type_id', type=int, required=True)
        parser.add_argument('type_parameter', type=str)
        args = parser.parse_args()
        parameter_check(args)
        if args.get("type_parameter") is not None:
            args["type_parameter"] = json.loads(args["type_parameter"].replace("\'", "\""))

        return util.success(create_notification_message(args))

    @ jwt_required
    def get(self, message_id):
        return util.success(get_notification_message(message_id))

    @ jwt_required
    def patch(self, message_id):
        role.require_admin()
        parser = reqparse.RequestParser()
        parser.add_argument('alert_level', type=int, required=True)
        parser.add_argument('message', type=str)
        parser.add_argument('type_id', type=int)
        parser.add_argument('type_parameter', type=str)
        args = parser.parse_args()
        args = {k: v for k, v in args.items() if v is not None}
        parameter_check(args)
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
        parser = reqparse.RequestParser()
        parser.add_argument('limit', type=int, default=10)
        parser.add_argument('offset', type=int, default=0)
        args = parser.parse_args()
        return util.success(get_notification_message_list(args))


class MessageReply(Resource):
    @ jwt_required
    def post(self, user_id):
        role.require_user_himself(user_id, even_admin=True)
        parser = reqparse.RequestParser()
        parser.add_argument('message_ids', type=list, location='json', required=True)
        args = parser.parse_args()
        return util.success(create_notification_message_reply_slip(user_id, args))


notification_room = NotificationRoom()
