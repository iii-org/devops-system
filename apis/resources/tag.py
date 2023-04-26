from flask_jwt_extended import jwt_required, get_jwt_identity
from sqlalchemy import desc

import model
import util as util
from model import db
from resources import role
from typing import Union, Any

error_tag_name_is_exists = "Tag Name was Created"


def row_to_dict(row):
    ret = {}
    if row is None:
        return row
    for key in type(row).__table__.columns.keys():
        if key == "project_id":
            continue
        value = getattr(row, key)
        ret[key] = value
    return ret


def get_tags_for_dict(project_id=None):
    output = {}
    if project_id is None:
        tags = model.Tag.query.all()
    elif isinstance(project_id, int):
        tags = model.Tag.query.filter_by(project_id=project_id).all()
    elif isinstance(project_id, list):
        tags = model.Tag.query.filter(model.Tag.project_id.in_(project_id)).all()
    else:
        return output
    for tag in tags:
        output[int(tag.id)] = {"id": int(tag.id), "name": tag.name}
    return output


def get_tags(project_id=None, tag_name=None):
    output = []
    if project_id is None:
        role.require_admin()
        tags = model.Tag.query.all()
    else:
        role.require_in_project(project_id)
        if tag_name is None:
            return get_project_order_tag_ids_info(project_id)
        else:
            search = "%{}%".format(tag_name)
            tags = model.Tag.query.filter_by(project_id=project_id).filter(model.Tag.name.like(search)).all()
    for tag in tags:
        output.append(row_to_dict(tag))
    return output


def get_tag(tag_id):
    tag = model.Tag.query.filter_by(id=tag_id).first()
    return row_to_dict(tag)


def check_tags(project_id, tag_name):
    return model.Tag.query.filter_by(project_id=project_id, name=tag_name).count()


def create_tags(project_id, args):
    if args.get("name", None) is None:
        return None
    end_tag_object = model.Tag.query.filter_by(project_id=project_id, next_tag_id=None).first()
    new = model.Tag(project_id=project_id, name=args.get("name"))
    if end_tag_object is not None:
        end_tag_object.next_tag = new
    db.session.add(new)
    db.session.commit()
    return new.id


def update_tag(tag_id, name):
    tag = model.Tag.query.filter_by(id=tag_id).first()
    tag.name = name
    db.session.commit()
    return tag.id


def delete_tag(tag_id):
    tag_query = model.Tag.query.filter_by(id=tag_id)
    before_tag, next_tag = tag_query.first().before_tag, tag_query.first().next_tag
    if before_tag is not None:
        before_tag.next_tag = next_tag
    model.Tag.query.filter_by(id=tag_id).delete()
    db.session.commit()

    # Need to delete tag from issues which has that tag.
    mapping = {}
    for issue_tag in model.IssueTag.query.all():
        tag_id_list = issue_tag.tag_id
        if tag_id in tag_id_list:
            tag_id_list.remove(tag_id)
            mapping[issue_tag.issue_id] = tag_id_list

    # Unable to update IssueTag in the same for loop.
    for issue_id, tag_ids in mapping.items():
        issue_tag = model.IssueTag.query.get(issue_id)
        issue_tag.tag_id = tag_ids
        db.session.commit()

    return tag_id


def get_user_project_ids(user_id):
    output = []
    projects = (
        model.ProjectUserRole.query.filter_by(user_id=user_id).filter(model.ProjectUserRole.project_id != -1).all()
    )
    if projects is None:
        return output
    for project in projects:
        output.append(project.project_id)
    return output


######### Tag order #############
def get_project_order_tag_ids_info(project_id: int) -> list[dict[str, Any]]:
    tag_object = model.Tag.query.filter_by(project_id=project_id, next_tag_id=None).first()
    return get_project_order_tag_ids_info_helper(tag_object, [])


def get_project_order_tag_ids_info_helper(tag_object: model.Tag, all_tag_ids: list[int]) -> list[dict[str, Any]]:
    if tag_object is None:
        return all_tag_ids
    all_tag_ids = [row_to_dict(tag_object)] + all_tag_ids

    return get_project_order_tag_ids_info_helper(tag_object.before_tag, all_tag_ids)


def move_tag(tag_id: int, to_tag_id: Union[int, None]) -> None:
    if to_tag_id is None:
        return move_tag_to_end(tag_id)
    move_tag_to_certain_tag_before(tag_id, to_tag_id)


def move_tag_to_end(tag_id: int) -> None:
    # Update the 'next_tag_id' value of tag that come before tag_id to the 'next_tag_id' value of tag_id.
    tag_object = model.Tag.query.get(tag_id)
    pj_id = tag_object.project_id
    tag_next_tag, tag_before_tag = tag_object.next_tag, tag_object.before_tag
    if tag_before_tag is not None:  # tag is not the head.
        tag_before_tag.next_tag = tag_next_tag

    # Set tag to the end
    end_tag_object = model.Tag.query.filter_by(project_id=pj_id, next_tag_id=None).first()
    if tag_object.id == end_tag_object.id:  # not moving, do not need to change
        return

    end_tag_object.next_tag = tag_object
    tag_object.next_tag = None
    db.session.commit()


def move_tag_to_certain_tag_before(tag_id: int, to_tag_id: int) -> None:
    # Update the 'next_tag_id' value of tag that come before tag_id to the 'next_tag_id' value of tag_id.
    tag_object = model.Tag.query.get(tag_id)
    tag_next_tag, tag_before_tag = tag_object.next_tag, tag_object.before_tag

    if tag_next_tag is not None and tag_next_tag.id == to_tag_id:  # not moving, do not need to change
        return

    if tag_before_tag is not None:  # tag is not the head.
        tag_before_tag.next_tag = tag_next_tag

    # Insert tag order into between to_tag and to_tag's before tag.
    to_tag_object = model.Tag.query.get(to_tag_id)
    to_tag_before_tag = to_tag_object.before_tag
    if to_tag_before_tag is not None:  # to_tag is not the head.
        to_tag_before_tag.next_tag = tag_object

    tag_object.next_tag = to_tag_object
    db.session.commit()


def order_pj_tags_by_id() -> None:
    # Order by aesc id
    has_tag_pj_ids = [tag.project_id for tag in model.Tag.query.with_entities(model.Tag.project_id).distinct().all()]
    for has_tag_pj_id in has_tag_pj_ids:
        pj_tags_objects = model.Tag.query.filter_by(project_id=has_tag_pj_id).order_by(desc(model.Tag.id)).all()
        pre_tag_id = pj_tags_objects[0].id
        for pj_tags_object in pj_tags_objects[1:]:
            pj_tags_object.next_tag_id = pre_tag_id
            db.session.commit()
            pre_tag_id = pj_tags_object.id
