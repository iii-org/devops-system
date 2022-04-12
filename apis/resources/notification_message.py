from flask_restful import Resource, reqparse
from flask_jwt_extended import jwt_required, get_jwt_identity
from flask_socketio import Namespace, emit, join_room, leave_room
from sqlalchemy.sql import and_
from sqlalchemy import desc
from datetime import datetime, timedelta
from time import strptime, mktime
import json
import util
from model import db, NotificationMessage, NotificationMessageReply, NotificationMessageRecipient, \
    ProjectUserRole, User, SystemParameter, Project
from resources import role
from resources.apiError import DevOpsError, resource_not_found, not_enough_authorization, argument_error

'''
websocket parameters:
{"user_id"=234}

https://github.com/iii-org/devops-system/wiki/Notification-Message
'''


class Alert_Level:
    def __init__(self, id_, name, users_can_read):
        self.id = id_
        self.name = name
        self.users_can_read = users_can_read


INF = Alert_Level(1, 'INFO', True)
WAR = Alert_Level(2, 'WARNING', True)
URG = Alert_Level(3, 'Urgent', True)

NEW = Alert_Level(101, 'New Version', False)
SAL = Alert_Level(102, 'System Alert', False)
SWA = Alert_Level(103, 'System Warming', True)

ALL_ALERTS = [INF, WAR, URG, NEW, SAL, SWA]


def get_alert_level(alert_id):
    for alert in ALL_ALERTS:
        if alert.id == alert_id:
            return {'id': alert.id, 'name': alert.name}
    return 'Unknown Alert'


def get_users_can_read(alert_id):
    for alert in ALL_ALERTS:
        if alert.id == alert_id:
            return alert.users_can_read


def check_message_exist(message_key, alert_level):
    count = NotificationMessage.query.filter(
        NotificationMessage.alert_level == alert_level).filter(
        NotificationMessage.message.like(f'%{message_key}%')).filter(
        NotificationMessage.title.like(f'%{message_key}%')).count()
    if count > 0:
        return True
    else:
        return False


def clear_has_expired_notifications_message(name, value_key):
    month_number = int(SystemParameter.query.filter_by(name=name).one().value[value_key])

    NotificationMessage.query.filter(util.get_few_months_ago_utc_datetime(month_number)
                                     > NotificationMessage.created_at).delete()
    db.session.commit()


def parameter_check(args):
    if args.get("alert_level") not in (1, 2, 3, 101, 102, 103):
        raise DevOpsError(400, 'Argument alert_level not in range.',
                          error=argument_error('alert_level'))
    for type_id in args.get("type_ids"):
        if type_id not in range(1, 6):
            raise DevOpsError(400, 'Argument type_id not in range.', error=argument_error('type_id'))
        if type_id in range(2, 6) and args.get("type_parameters") is None:
            raise DevOpsError(400, 'Missing type_parameters', error=argument_error('type_parameters'))
        elif type_id in [2, 5] and 'project_ids' not in json.loads(args["type_parameters"]):
            raise DevOpsError(400, 'Argument project_ids not exist in type_parameters.',
                              error=argument_error('project_ids'))
        elif type_id == 3 and 'user_ids' not in json.loads(args["type_parameters"]):
            raise DevOpsError(400, 'Argument user_id not exist in type_parameters.',
                              error=argument_error('user_ids'))
        elif type_id == 4 and 'role_ids' not in json.loads(args["type_parameters"]):
            raise DevOpsError(400, 'Argument role_ids not exist in type_parameters.',
                              error=argument_error('role_ids'))


def combine_message_and_recipient(rows):
    out_dict = {}
    for row in rows:
        if row[0].id not in out_dict:
            out_dict[row[0].id] = {**json.loads(str(row[0])), **{"types": [json.loads(str(row[1]))]}}
        else:
            out_dict[row[0].id]["types"].append(json.loads(str(row[1])))
        if row[0].alert_level:
            out_dict[row[0].id]["alert_level"] = get_alert_level(row[0].alert_level)
            out_dict[row[0].id]["users_can_read"] = get_users_can_read(row[0].alert_level)
        if row[0].creator_id:
            from resources.user import NexusUser
            out_dict[row[0].id]["creator"] = NexusUser().set_user_id(row[0].creator_id).to_json()
        out_dict[row[0].id].pop("creator_id", None)
        if len(row) > 2:
            if row[2] is not None:
                out_dict[row[0].id]["read"] = True
            else:
                out_dict[row[0].id]["read"] = False
    return list(out_dict.values())


def filter_by_user(rows, user_id, role_id=None):
    project_ids = db.session.query(ProjectUserRole.project_id).filter(and_(
        ProjectUserRole.user_id == user_id, ProjectUserRole.project_id != -1)).all()

    out_list = []
    for row in rows:
        if row[1].type_id == 1 and row not in out_list:
            out_list.append(row)
        if row[1].type_id == 2:
            for type_project_id in row[1].type_parameter['project_ids']:
                if (type_project_id,) in project_ids and row not in out_list:
                    out_list.append(row)
        if row[1].type_id == 3:
            for type_user_id in row[1].type_parameter['user_ids']:
                if type_user_id == user_id and row not in out_list:
                    out_list.append(row)
        if role_id and row[1].type_id == 4:
            for type_role_id in row[1].type_parameter['role_ids']:
                if type_role_id == role_id and row not in out_list:
                    out_list.append(row)
        if row[1].type_id == 5:
            for type_project_id in row[1].type_parameter['project_ids']:
                pj_row = Project.query.filter_by(id=type_project_id).first()
                if pj_row.owner_id == user_id:
                    out_list.append(row)
    return out_list


def get_notification_message_list(args, admin=False):
    out = []
    page_dict = None
    base_query = db.session.query(NotificationMessage, NotificationMessageRecipient, NotificationMessageReply).outerjoin(
        NotificationMessageReply, and_(NotificationMessageReply.user_id == get_jwt_identity()["user_id"],
                                       NotificationMessage.id == NotificationMessageReply.message_id))
    base_query = base_query.outerjoin(NotificationMessageRecipient,
                                      NotificationMessageRecipient.message_id == NotificationMessage.id)
    if args.get("search") is not None:
        base_query = base_query.filter(NotificationMessage.message.like(f'%{args.get("search")}%'))
    a_from_date = args['from_date']
    a_to_date = args['to_date']
    if a_from_date is not None:
        from_date = datetime.fromtimestamp(mktime(strptime(a_from_date, '%Y-%m-%d')))
        base_query = base_query.filter(NotificationMessage.created_at >= from_date)
    if a_to_date is not None:
        to_date = datetime.fromtimestamp(mktime(strptime(a_to_date, '%Y-%m-%d')))
        to_date += timedelta(days=1)
        base_query = base_query.filter(NotificationMessage.created_at < to_date)
    if args.get("alert_ids") is not None:
        base_query = base_query.filter(NotificationMessage.alert_level.in_(args.get("alert_ids")))
    if args.get("unread"):
        base_query = base_query.filter(NotificationMessageReply.user_id == None)
    if admin and args.get("include_system_message") is not True:
        base_query = base_query.filter(NotificationMessage.alert_level <= 100)
    rows = base_query.order_by(desc(NotificationMessage.id)).all()

    if admin is False:
        rows = filter_by_user(rows, get_jwt_identity()["user_id"], get_jwt_identity()["role_id"])
    out = combine_message_and_recipient(rows)
    out, page_dict = util.list_pagination(out, args['limit'], args['offset'])
    out_dict = {'notification_message_list': out}

    if page_dict:
        out_dict['page'] = page_dict
    return out_dict


def create_notification_message(args, user_id=None):
    if user_id is None:
        user_id = get_jwt_identity()['user_id']
    row = NotificationMessage(
        alert_level=args['alert_level'],
        title=args['title'],
        message=args['message'],
        creator_id=user_id,
        created_at=datetime.utcnow(),
        updated_at=datetime.utcnow()
    )
    db.session.add(row)
    db.session.commit()
    for type_id in args['type_ids']:
        row_recipient = NotificationMessageRecipient(
            message_id=row.id,
            type_id=type_id,
            type_parameter=args['type_parameters'],
        )
        db.session.add(row_recipient)
        db.session.commit()
    notification_room.send_message_to_all(row.id)


def close_notification_message(message_id):
    for user_id, v in choose_send_to_who(message_id, send_message_id=True).items():
        if NotificationMessageReply.query.filter_by(message_id=message_id, user_id=user_id).first() is None:
            args = {"message_ids": [message_id]}
            create_notification_message_reply_slip(user_id, args)


def delete_notification_message(message_id):
    out_dict = choose_send_to_who(message_id, send_message_id=True)
    for k, v in out_dict.items():
        emit("delete_message", v, namespace="/get_notification_message", to=f"user/{k}")

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
    for message_id in args["message_ids"]:
        emit("read_message", message_id, namespace="/get_notification_message", to=f"user/{user_id}")


def choose_send_to_who(message_id, send_message_id=None):
    # out_dict: {user_id: message}
    out_dict = {}
    message_rows = db.session.query(NotificationMessage, NotificationMessageRecipient).join(
        NotificationMessageRecipient, and_(NotificationMessage.id == message_id,
                                           NotificationMessage.id == NotificationMessageRecipient.message_id
                                           )).all()

    for message_row in message_rows:
        if message_row[1].type_id == 1:
            # Send message to all
            for user_row in User.query.all():
                if user_row not in out_dict:
                    if send_message_id:
                        out_dict[user_row.id] = message_id
                    else:
                        out_dict[user_row.id] = json.loads(str(message_row[0]))
        elif message_row[1].type_id == 2:
            for project_id in message_row[1].type_parameter['project_ids']:
                # Send message to user in project
                for user_row in ProjectUserRole.query.filter_by(project_id=project_id).all():
                    if user_row.user_id not in out_dict:
                        if send_message_id:
                            out_dict[user_row.user_id] = message_id
                        else:
                            out_dict[user_row.user_id] = json.loads(str(message_row[0]))
        elif message_row[1].type_id == 3:
            # Send message to the user
            for user_id in message_row[1].type_parameter['user_ids']:
                if user_id not in out_dict:
                    if send_message_id:
                        out_dict[user_id] = message_id
                    else:
                        out_dict[user_id] = json.loads(str(message_row[0]))
        elif message_row[1].type_id == 4:
            # Send message to same role account
            for role_id in message_row[1].type_parameter['role_ids']:
                for user_row in ProjectUserRole.query.filter_by(role_id=role_id, project_id=-1).all():
                    if user_row.user_id not in out_dict:
                        if send_message_id:
                            out_dict[user_row.user_id] = message_id
                        else:
                            out_dict[user_row.user_id] = json.loads(str(message_row[0]))
        elif message_row[1].type_id == 5:
            for project_id in message_row[1].type_parameter['project_ids']:
                # Send message to project onwer
                pj_row = Project.query.filter_by(id=project_id).first()
                if send_message_id:
                    out_dict[pj_row.owner_id] = message_id
                else:
                    out_dict[pj_row.owner_id] = json.loads(str(message_row[0]))
    return out_dict


class NotificationRoom(object):

    def send_message_to_all(self, message_id):
        out_dict = choose_send_to_who(message_id)
        for k, v in out_dict.items():
            v["alert_level"] = get_alert_level(v["alert_level"])
            if "creator_id" in v:
                from resources.user import NexusUser
                v["creator"] = NexusUser().set_user_id(v["creator_id"]).to_json()
            v.pop("creator_id", None)
            if k != get_jwt_identity()["user_id"]:
                emit("create_message", v, namespace="/get_notification_message", to=f"user/{k}")

    def get_message(self, data):
        rows = db.session.query(NotificationMessage, NotificationMessageRecipient).outerjoin(
            NotificationMessageReply, and_(NotificationMessageReply.user_id == data['user_id'],
                                           NotificationMessage.id == NotificationMessageReply.message_id)).filter(
            NotificationMessageReply.message_id == None)

        rows = rows.outerjoin(NotificationMessageRecipient,
                              NotificationMessageRecipient.message_id == NotificationMessage.id).all()
        pur_row = ProjectUserRole.query.filter_by(user_id=data['user_id']).first()
        rows = filter_by_user(rows, data['user_id'], pur_row.role_id)
        message_list = combine_message_and_recipient(rows)
        for message in message_list:
            emit("create_message", message, namespace="/get_notification_message", to=f"user/{data['user_id']}")


class GetNotificationMessage(Namespace):

    def on_connect(self):
        print('Connect')

    def on_disconnect(self):
        print('Client disconnected')

    def on_join(self, data):
        # verify jwt token
        # verify user_id
        if "user_id" not in data:
            return
        print('Join room')
        join_room(f"user/{data['user_id']}")

    def on_leave(self, data):
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
        parser.add_argument('title', type=str)
        parser.add_argument('message', type=str, required=True)
        parser.add_argument('type_ids', type=str, required=True)
        parser.add_argument('type_parameters', type=str)
        args = parser.parse_args()
        args["type_ids"] = json.loads(args["type_ids"].replace("\'", "\""))
        parameter_check(args)
        if args.get("type_parameters") is not None:
            args["type_parameters"] = json.loads(args["type_parameters"].replace("\'", "\""))

        return util.success(create_notification_message(args))

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
        parser.add_argument('from_date', type=str)
        parser.add_argument('to_date', type=str)
        parser.add_argument('search', type=str)
        parser.add_argument('alert_ids', type=str)
        parser.add_argument('unread', type=bool)
        args = parser.parse_args()
        if args["alert_ids"]:
            args["alert_ids"] = json.loads(args["alert_ids"].replace("\'", "\""))
        return util.success(get_notification_message_list(args))


class MessageListForAdmin(Resource):
    @ jwt_required
    def get(self):
        role.require_admin()
        parser = reqparse.RequestParser()
        parser.add_argument('limit', type=int, default=10)
        parser.add_argument('offset', type=int, default=0)
        parser.add_argument('from_date', type=str)
        parser.add_argument('to_date', type=str)
        parser.add_argument('search', type=str)
        parser.add_argument('alert_ids', type=str)
        parser.add_argument('include_system_message', type=bool)
        args = parser.parse_args()
        if args["alert_ids"]:
            args["alert_ids"] = json.loads(args["alert_ids"].replace("\'", "\""))
        return util.success(get_notification_message_list(args, admin=True))


class MessageReply(Resource):
    @ jwt_required
    def post(self, user_id):
        role.require_user_himself(user_id, even_admin=True)
        parser = reqparse.RequestParser()
        parser.add_argument('message_ids', type=list, location='json', required=True)
        args = parser.parse_args()
        return util.success(create_notification_message_reply_slip(user_id, args))


class MessageClose(Resource):
    @ jwt_required
    def post(self, message_id):
        role.require_admin()
        return util.success(close_notification_message(message_id))


notification_room = NotificationRoom()
