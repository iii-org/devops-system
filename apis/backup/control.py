from model import User, UserMessageType
from util import row_to_dict, write_json_file, check_folder_exist, rows_to_list
from sqlalchemy import inspect, or_, not_
import os


def backup_user_to_json():
    output = []
    users = User.query.filter(not_(or_(User.login=='sysadmin', User.login.like('project_bot_%')))).order_by(User.id).all()
    for user in users:
        user_json = row_to_dict(user)
        umt = UserMessageType.query.filter_by(user_id=user.id).first()
        if umt:
            user_json["user_message_type"] = row_to_dict(umt)
        output.append(user_json)
    backup_path = os.path.join("devops-data", "backup")
    check_folder_exist(backup_path, True)
    write_json_file(os.path.join(backup_path, "backup_user.json"), output)

