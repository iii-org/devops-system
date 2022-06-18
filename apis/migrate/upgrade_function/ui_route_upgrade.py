import os
import util
from model import db, UIRouteData
from datetime import datetime


UI_ROUTE_FOLDER_NAME = "apis/ui_routes"


def insert_into_ui_route_table(ui_route_dict, parent_name, old_brother_name):
    if 'meta' in ui_route_dict and 'roles' in ui_route_dict['meta']:
        role = ui_route_dict['meta']['roles'][0]
    else:
        role = ""
    parent_id = 0
    if parent_name != "":
        parent_row = UIRouteData.query.filter_by(name=parent_name, role=role).first()
        parent_id = parent_row.id if parent_row else 0
    old_brother_id = 0
    if parent_name != "":
        old_brother_row = UIRouteData.query.filter_by(name=old_brother_name, role=role).first()
        old_brother_id = old_brother_row.id if old_brother_row else 0
    num = UIRouteData.query.filter_by(name=ui_route_dict['name'], role=role).count()
    if num == 0:
        new_row = UIRouteData(name=ui_route_dict['name'],
                              role=role,
                              parent=parent_id,
                              old_brother=old_brother_id,
                              ui_route=ui_route_dict,
                              created_at=datetime.utcnow(),
                              updated_at=datetime.utcnow())
        db.session.add(new_row)
        db.session.commit()
        print(ui_route_dict['name'])
        print(role)
        print(parent_name)
        print(old_brother_name)
        print('-'*30)
    if 'children' in ui_route_dict:
        j = 0
        while j < len(ui_route_dict['children']):
            old_brother_name = "" if j == 0 else ui_route_dict['children'][j-1]['name']
            insert_into_ui_route_table(ui_route_dict['children'][j], ui_route_dict['name'], old_brother_name)
            j += 1


def ui_route_first_version():
    for ui_route_file_name in next(os.walk(UI_ROUTE_FOLDER_NAME))[2]:
        if ui_route_file_name[-5:] == ".json":
            ui_route_dicts = util.read_json_file(f"{UI_ROUTE_FOLDER_NAME}/{ui_route_file_name}")
            i = 0
            while i < len(ui_route_dicts):
                old_brother_name = "" if i == 0 else ui_route_dicts[i-1]['name']
                insert_into_ui_route_table(ui_route_dicts[i], "", old_brother_name)
                i += 1
            print("="*50)
