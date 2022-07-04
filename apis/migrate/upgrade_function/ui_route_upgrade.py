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


# get parent_id
def get_parent_or_old_brother_id(role, parent_or_old_brother_name):
    if parent_or_old_brother_name == '':
        return 0
    else:
        row = UIRouteData.query.filter_by(role=role, name=parent_or_old_brother_name).first()
        if row:
            return row.id
        else:
            print("could not find parent or old_brother")


def get_young_brother_id(role, parent_id, old_brother_id):
    row = UIRouteData.query.filter_by(role=role, parent=parent_id, old_brother=old_brother_id).first()
    if row:
        return row.id
    else:
        return 0


def create_ui_route_object(name, role, parent_name, old_brother_name, ui_route_json):
    # create a new route ob
    parent_id = get_parent_or_old_brother_id(role, parent_name)
    old_brother_id = get_parent_or_old_brother_id(role, old_brother_name)
    young_brother_id = get_young_brother_id(role, parent_id, old_brother_id)
    if old_brother_id == 0:
        original_first = UIRouteData.query.filter_by(role=role, parent=parent_id, old_brother=0).first()
        # insert into the first
        new = UIRouteData(name=name, role=role, parent=parent_id, old_brother=0, ui_route=ui_route_json,
                          created_at=datetime.utcnow(), updated_at=datetime.utcnow())
        db.session.add(new)
        original_first.old_brother = new.id
    elif young_brother_id == 0:
        # insert into the last
        new = UIRouteData(name=name, role=role, parent=parent_id, old_brother=old_brother_id, ui_route=ui_route_json,
                          created_at=datetime.utcnow(), updated_at=datetime.utcnow())
        db.session.add(new)
    else:
        # insert into the middle
        original_position = UIRouteData.query.filter_by(role=role, parent=parent_id, old_brother=old_brother_id).first()
        new = UIRouteData(name=name, role=role, parent=parent_id, old_brother=old_brother_id, ui_route=ui_route_json,
                          created_at=datetime.utcnow(), updated_at=datetime.utcnow())
        db.session.add(new)
        original_position.old_brother = new.id
    db.session.commit()


def put_ui_route_object(name, role, parent_name, old_brother_name, ui_route_json):
    # update the route object
    parent_id = get_parent_or_old_brother_id(role, parent_name)
    old_brother_id = get_parent_or_old_brother_id(role, old_brother_name)
    route_row = UIRouteData.query.filter_by(role=role, name=name).first()
    route_row.parent = parent_id
    route_row.old_brother = old_brother_id
    route_row.ui_route = ui_route_json
    route_row.updated_at = datetime.utcnow()
    db.session.commit()


# delete the old route object
def delete_ui_route_object(name, role):
    route_row = UIRouteData.query.filter_by(role=role, name=name).first()
    parent_id = route_row.parent
    old_brother_id = route_row.old_brother
    young_brother_id = get_young_brother_id(role, parent_id, old_brother_id)
    db.session.delete(route_row)
    if old_brother_id == 0:
        # on the first
        original_second = UIRouteData.query.filter_by(id=young_brother_id).first()
        original_second.old_brother = 0
    elif young_brother_id == 0:
        # on the last
        pass
    else:
        # insert into the middle
        original_second = UIRouteData.query.filter_by(id=young_brother_id).first()
        original_second.old_brother = old_brother_id
    db.session.commit()
