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

https://github.com/iii-org/devops-system/wiki/Notification-Message
'''


class Alert_Level:
    def __init__(self, id_, name):
        self.id = id_
        self.name = name


INF = Alert_Level(1, 'INFO')
WAR = Alert_Level(2, 'WARNING')
ERR = Alert_Level(3, 'ERROR')
CRI = Alert_Level(4, 'CRITICAL')

NEW = Alert_Level(101, 'New Version')

ALL_ALERTS = [INF, WAR, ERR, CRI, NEW]


def get_alert_level(alert_id):
    for alert in ALL_ALERTS:
        if alert.id == alert_id:
            return {'id': alert.id, 'name': alert.name}
    return 'Unknown Alert'


def clear_has_expired_notifications_message(name, value_key):
    month_number = int(SystemParameter.query.filter_by(name=name).one().value[value_key])

    NotificationMessage.query.filter(util.get_few_months_ago_utc_datetime(month_number)
                                     > NotificationMessage.created_at).delete()
    db.session.commit()


def parameter_check(args):
    if args.get("alert_level") not in (1, 2, 3, 4):
        raise DevOpsError(400, 'Argument alert_level not in range.',
                          error=argument_error('alert_level'))
    for type_id in args.get("type_ids"):
        if type_id not in range(1, 5):
            raise DevOpsError(400, 'Argument type_id not in range.', error=argument_error('type_id'))
        if type_id in range(2, 5) and args.get("type_parameters") is None:
            raise DevOpsError(400, 'Missing type_parameters', error=argument_error('type_parameters'))
        elif type_id == 2 and 'project_ids' not in json.loads(args["type_parameters"]):
            raise DevOpsError(400, 'Argument project_ids not exist in type_parameters.',
                              error=argument_error('project_ids'))
        elif type_id == 3 and 'user_ids' not in json.loads(args["type_parameters"]):
            raise DevOpsError(400, 'Argument user_id not exist in type_parameters.',
                              error=argument_error('user_ids'))
        elif type_id == 4 and 'role_ids' not in json.loads(args["type_parameters"]):
            raise DevOpsError(400, 'Argument role_ids not exist in type_parameters.',
                              error=argument_error('role_ids'))


'''
def __check_read(row):
    message_dict = json.loads(str(row[0]))
    message_dict["read"] = False
    if row[1] is not None:
        message_dict["read"] = True
    return message_dict
'''


def combine_message_and_recipient(rows):
    out_dict = {}
    for row in rows:
        if row[0].id not in out_dict:
            out_dict[row[0].id] = {**json.loads(str(row[0])), **{"types": [json.loads(str(row[1]))]}}
        else:
            out_dict[row[0].id]["types"].append(json.loads(str(row[1])))
        if row[0].alert_level:
            out_dict[row[0].id]["alert_level"] = get_alert_level(row[0].alert_level)
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
    return out_list


def get_notification_message_list(args):
    out = []
    page_dict = None
    base_query = db.session.query(NotificationMessage, NotificationMessageRecipient, NotificationMessageReply).outerjoin(
        NotificationMessageReply, and_(NotificationMessageReply.user_id == get_jwt_identity()["user_id"],
                                       NotificationMessage.id == NotificationMessageReply.message_id))
    base_query = base_query.outerjoin(NotificationMessageRecipient,
                                      NotificationMessageRecipient.message_id == NotificationMessage.id)
    if args['limit'] is not None or args['offset'] is not None:
        base_query, page_dict = util.orm_pagination(base_query, args['limit'], args['offset'])
    rows = base_query.all()

    if get_jwt_identity()["role_id"] != role.ADMIN.id:
        rows = filter_by_user(rows, get_jwt_identity()["user_id"], get_jwt_identity()["role_id"])
    out = combine_message_and_recipient(rows)
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
            type_parameter=args['type_parameters'],
        )
        db.session.add(row_recipient)
        db.session.commit()
    notification_room.send_message_to_all(row.id)


'''
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
'''


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
        out_dict = {}
        for message_row in message_rows:
            if message_row[1].type_id == 1:
                # Send message to all
                for user_row in User.query.all():
                    if user_row not in out_dict:
                        out_dict[user_row.id] = json.loads(str(message_row[0]))
            elif message_row[1].type_id == 2:
                for project_id in message_row[1].type_parameter['project_ids']:
                    # Send message to user in project
                    for user_row in ProjectUserRole.query.filter_by(project_id=project_id).all():
                        if user_row.user_id not in out_dict:
                            out_dict[user_row.user_id] = json.loads(str(message_row[0]))
            elif message_row[1].type_id == 3:
                # Send message to the user
                for user_id in message_row[1].type_parameter['user_ids']:
                    if user_id not in out_dict:
                        out_dict[user_id] = json.loads(str(message_row[0]))
            elif message_row[1].type_id == 4:
                # Send message to same role account
                for role_id in message_row[1].type_parameter['role_ids']:
                    for user_row in ProjectUserRole.query.filter_by(role_id=role_id, project_id=-1).all():
                        if user_row.user_id not in out_dict:
                            out_dict[user_row.user_id] = json.loads(str(message_row[0]))
        for k, v in out_dict.items():
            v["alert_level"] = get_alert_level(v["alert_level"])
            if "creator_id" in v:
                from resources.user import NexusUser
                v["creator"] = NexusUser().set_user_id(v["creator_id"]).to_json()
            v.pop("creator_id", None)
            emit("system_message", v, namespace="/get_notification_message",
                 to=f"user/{k}")

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
            emit("system_message", message, namespace="/get_notification_message", to=f"user/{data['user_id']}")


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
        parser.add_argument('message', type=str, required=True)
        parser.add_argument('type_ids', type=str, required=True)
        parser.add_argument('type_parameters', type=str)
        args = parser.parse_args()
        args["type_ids"] = json.loads(args["type_ids"].replace("\'", "\""))
        parameter_check(args)
        if args.get("type_parameters") is not None:
            args["type_parameters"] = json.loads(args["type_parameters"].replace("\'", "\""))

        return util.success(create_notification_message(args))
    '''
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
        parser.add_argument('type_parameters', type=str)
        args = parser.parse_args()
        args = {k: v for k, v in args.items() if v is not None}
        parameter_check(args)
        if args.get("type_parameters") is not None:
            args["type_parameters"] = json.loads(args["type_parameters"].replace("\'", "\""))
        update_notification_message(message_id, args)
        return util.success()
    '''

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
