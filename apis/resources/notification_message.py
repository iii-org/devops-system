from flask_restful import Resource, reqparse
from flask_jwt_extended import jwt_required, get_jwt_identity
from flask_socketio import Namespace, emit, join_room, leave_room
from sqlalchemy.sql import and_
from datetime import datetime
import json
import util
from model import db, NotificationMessage, NotificationMessageReply, NotificationMessageRecipient, \
    ProjectUserRole, User, SystemParameter
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


def clear_has_expired_notifications_message(name, value_key):
    month_number = int(SystemParameter.query.filter_by(name=name).one().value[value_key])

    NotificationMessage.query.filter(util.get_few_months_ago_utc_datetime(month_number)
                                     > NotificationMessage.created_at).delete()
    db.session.commit()


def parameter_check(args):
    if args.get("alert_level") not in (1, 2, 3, 4):
        raise DevOpsError(400, 'Argument alert_level not in (1, 2, 3, 4).',
                          error=argument_error('alert_level'))
    for type_id in args.get("type_ids"):
        if type_id not in (1, 2, 3):
            raise DevOpsError(400, 'Argument type_id not in (1,2,3).', error=argument_error('type_id'))
        if type_id in range(2, 4) and args["type_parameter"] is None:
            raise DevOpsError(400, 'Missing type_parameter', error=argument_error('type_parameter'))
        elif type_id == 2 and 'project_id' not in json.loads(args["type_parameter"]):
            raise DevOpsError(400, 'Argument project_id not exist in type_parameter.',
                              error=argument_error('project_id'))
        elif type_id == 3 and 'user_id' not in json.loads(args["type_parameter"]):
            raise DevOpsError(400, 'Argument user_id not exist in type_parameter.',
                              error=argument_error('user_id'))


def __check_read(row):
    message_dict = json.loads(str(row[0]))
    message_dict["read"] = False
    if row[1] is not None:
        message_dict["read"] = True
    return message_dict


def get_notification_message_list(args):
    out = []
    page_dict = None
    base_query = db.session.query(NotificationMessage, NotificationMessageReply).outerjoin(
        NotificationMessageReply, and_(NotificationMessageReply.user_id == get_jwt_identity()["user_id"],
                                       NotificationMessage.id == NotificationMessageReply.message_id))
    if args['limit'] is not None or args['offset'] is not None:
        base_query, page_dict = util.orm_pagination(base_query, args['limit'], args['offset'])
    rows = base_query.all()

    if get_jwt_identity()["role_id"] == 5:
        for row in rows:
            out.append(__check_read(row))
    else:
        projects = db.session.query(ProjectUserRole.project_id).filter(and_(
            ProjectUserRole.user_id == get_jwt_identity()["user_id"], ProjectUserRole.project_id != -1)).all()
        for row in rows:
            if row[0].type_id == 2 and (row[0].type_parameter['project_id'],) not in projects:
                continue
            elif row[0].type_id == 3 and row[0].type_parameter['user_id'] != get_jwt_identity()["user_id"]:
                continue
            else:
                out.append(__check_read(row))
    out_dict = {'notification_message_list': out}
    if page_dict:
        out_dict['page'] = page_dict
    return out_dict


def create_notification_message(args):
    row = NotificationMessage(
        alert_level=args['alert_level'],
        message=args['message'],
        creator_id=get_jwt_identity()['user_id'],
        created_at=datetime.utcnow(),
        updated_at=datetime.utcnow()
    )
    db.session.add(row)
    db.session.commit()
    for type_id in args['type_ids']:
        row_recipient = NotificationMessageRecipient(
            message_id=row.id,
            type_id=type_id,
            type_parameter=args['type_parameter'],
        )
        db.session.add(row_recipient)
        db.session.commit()
    notification_room.send_message_to_all(row.id)


def update_notification_message(message_id, args):
    message = NotificationMessage.query.filter_by(id=message_id).first()
    for k, v in args.items():
        setattr(message, k, v)
    db.session.commit()


def get_notification_message(message_id):
    row = db.session.query(NotificationMessage, NotificationMessageReply).outerjoin(
        NotificationMessageReply, and_(NotificationMessage.id == NotificationMessageReply.message_id,
                                       NotificationMessageReply.user_id == get_jwt_identity()["user_id"])).filter(NotificationMessage.id == message_id).first()
    if row[0]:
        if (get_jwt_identity()['role_id'] == 5 or
            row[0].type_id == 1 or
                (row[0].type_id == 3 and row[0].type_parameter["user_id"] == get_jwt_identity()['user_id'])):
            return __check_read(row)
        else:
            projects = db.session.query(ProjectUserRole.project_id).filter(and_(
                ProjectUserRole.user_id == get_jwt_identity()["user_id"], ProjectUserRole.project_id != -1)).all()
            if row[0].type_id == 2 and (row[0].type_parameter["project_id"],) in projects:
                return __check_read(row)
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
        row = NotificationMessageReply(
            message_id=message_id,
            user_id=user_id,
            created_at=datetime.utcnow(),
        )
        row_list.append(row)
    db.session.add_all(row_list)
    db.session.commit()


class NotificationRoom(object):

    def send_message_to_all(self, message_id):
        message_rows = db.session.query(NotificationMessage, NotificationMessageRecipient).join(
            NotificationMessageRecipient, and_(NotificationMessage.id == message_id,
                                               NotificationMessage.id == NotificationMessageRecipient.message_id
                                               )).all()
        for message_row in message_rows:
            if message_row[1].type_id == 1:
                # Send message to all
                # Get all user list
                user_rows = User.query.all()
                # Send message
                for user_row in user_rows:
                    emit("system_message", str(message_row[0]), namespace="/get_notification_message",
                         to=f"user/{user_row.id}")
            elif message_row[1].type_id == 2:
                # Send message to user in project
                # Get all user list in projects
                user_rows = ProjectUserRole.query.filter_by(
                    project_id=message_row[1].type_parameter['project_id']).all()
                # Send message
                for user_row in user_rows:
                    emit("system_message", str(message_row[0]), namespace="/get_notification_message",
                         to=f"user/{user_row.user_id}")
            elif message_row[1].type_id == 3:
                # Send message to the user
                emit("system_message", str(message_row[0]), namespace="/get_notification_message",
                     to=f"user/{message_row[1].type_parameter['user_id']}")

    def get_message(self, data):
        rows = db.session.query(NotificationMessage, NotificationMessageRecipient).outerjoin(
            NotificationMessageReply, and_(NotificationMessageReply.user_id == data['user_id'],
                                           NotificationMessage.id == NotificationMessageReply.message_id)).filter(
            NotificationMessageReply.message_id == None)

        rows = rows.outerjoin(NotificationMessageRecipient,
                              NotificationMessageRecipient.message_id == NotificationMessage.id).all()

        projects = db.session.query(ProjectUserRole.project_id).filter(and_(
            ProjectUserRole.user_id == data['user_id'], ProjectUserRole.project_id != -1)).all()
        out_dict = {}
        for row in rows:
            if row[1].type_id == 2 and (row[1].type_parameter['project_id'],) not in projects:
                continue
            if row[1].type_id == 3 and row[1].type_parameter['user_id'] != data['user_id']:
                continue
            if row[0].id not in out_dict:
                out_dict[row[0].id] = {**json.loads(str(row[0])), **{"types": [json.loads(str(row[1]))]}}
            else:
                out_dict[row[0].id]["types"].append(json.loads(str(row[1])))
        for message in list(out_dict.values()):
            emit("system_message", message, namespace="/get_notification_message", to=f"user/{data['user_id']}")


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
        parser.add_argument('type_ids', type=str, required=True)
        parser.add_argument('type_parameter', type=str)
        args = parser.parse_args()
        args["type_ids"] = json.loads(args["type_ids"].replace("\'", "\""))
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
        parser.add_argument('type_ids', type=int, action='append', required=True)
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
