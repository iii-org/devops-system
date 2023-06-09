# from model import User, UserMessageType
from util import row_to_dict, read_json_file, check_folder_exist, rows_to_list
from resources.user import (
    get_user_json_by_login,
    get_user_json_by_email,
    create_user,
    update_user,
    update_user_message_types,
)
import os


def restore_user_from_json():
    backup_path = os.path.join("devops-data", "backup")
    backup_file = os.path.join(backup_path, "backup_user.json")
    if os.path.exists(backup_path):
        users = read_json_file(backup_file)
        for user in  users:
            umt = user.get("user_message_type")
            del user["user_message_type"]
            if user.get("disabled") is not None:
                user["status"] = "disable" if user["disabled"] else "enable"
            user_id = get_user_json_by_email(user.get("email")).get("id")
            if user_id is None:
                user_id = get_user_json_by_login(user.get("login")).get("id")
            if user_id:
                del user["password"]
                update_user(user_id, user)
            else:
                user["password"] = "Default2Pswd"
                user_id = create_user(user).get("user_id")
            update_user_message_types(user_id, umt)
    else:
        print(f"{backup_file} is not exists")
