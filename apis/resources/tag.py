from flask_jwt_extended import jwt_required, get_jwt_identity
from flask_restful import Resource, reqparse
from sqlalchemy.orm.exc import NoResultFound
from enums.action_type import ActionType
from .activity import record_activity

import model
import util as util
from model import db
from resources import role

error_tag_name_is_exists = "Tag Name was Created"


def row_to_dict(row):
    ret = {}
    if row is None:
        return row
    for key in type(row).__table__.columns.keys():
        if key == 'project_id':
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
        output[int(tag.id)] = {'id': int(tag.id), 'name': tag.name}
    return output


def get_tags(project_id=None, tag_name=None):
    output = []
    if project_id is None:
        role.require_admin()
        tags = model.Tag.query.all()
    else:
        role.require_in_project(project_id)
        if tag_name is None:
            tags = model.Tag.query.filter_by(project_id=project_id).all()
        else:
            search = "%{}%".format(tag_name)
            tags = model.Tag.query.filter_by(project_id=project_id). \
                filter(model.Tag.name.like(search)).all()
    for tag in tags:
        output.append(row_to_dict(tag))
    return output


def get_tag(tag_id):
    tag = model.Tag.query.filter_by(id=tag_id).first()
    return row_to_dict(tag)


def check_tags(project_id, tag_name):
    return model.Tag.query.filter_by(project_id=project_id, name=tag_name).count()


# @record_activity(ActionType.ADD_TAG)
def create_tags(project_id, args):
    if args.get('name', None) is None:
        return None
    new = model.Tag(
        project_id=project_id,
        name=args.get('name')
    )
    db.session.add(new)
    db.session.commit()
    return new.id


def update_tag(tag_id, name):
    tag = model.Tag.query.filter_by(id=tag_id).first()
    tag.name = name
    db.session.commit()
    return tag.id

# @record_activity(ActionType.DELETE_TAG)
def delete_tag(tag_id):
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
    projects = model.ProjectUserRole.query. \
        filter_by(user_id=user_id). \
        filter(model.ProjectUserRole.project_id != -1) \
        .all()
    if projects is None:
        return output
    for project in projects:
        output.append(project.project_id)
    return output


class UserTags(Resource):
    @jwt_required
    def get(self):
        try:
            identity = get_jwt_identity()
            user_id = identity['user_id']
            project_id = get_user_project_ids(user_id)
            return util.success({"tags": get_tags_for_dict(project_id)})
        except NoResultFound:
            return util.respond(404)


class Tags(Resource):
    @jwt_required
    def get(self):
        try:
            parser = reqparse.RequestParser()
            parser.add_argument('project_id', type=int)
            parser.add_argument('tag_name', type=str)
            args = parser.parse_args()
            if args.get('project_id', None) is None:
                return util.success({"tags": get_tags()})
            else:
                return util.success({
                    "tags": get_tags(args.get('project_id'), args.get('tag_name', None))
                })
        except NoResultFound:
            return util.respond(404)

    @jwt_required
    def post(self):
        try:
            parser = reqparse.RequestParser()
            parser.add_argument('project_id', type=str, required=True)
            parser.add_argument('name', type=str, required=True)
            args = parser.parse_args()
            tag_name = args.get('name')
            project_id = args.get('project_id')
            if check_tags(project_id, tag_name) > 0:
                return util.respond(403, error_tag_name_is_exists)
            return util.success({"tags": {"id": create_tags(project_id, args)}})
        except NoResultFound:
            return util.respond(404)


class Tag(Resource):
    @jwt_required
    def get(self, tag_id):
        try:
            return util.success({"tag": get_tag(tag_id)})
        except NoResultFound:
            return util.respond(404)

    @jwt_required
    def put(self, tag_id):
        try:
            parser = reqparse.RequestParser()
            parser.add_argument('name', type=str, required=True)
            args = parser.parse_args()
            return util.success({"tag": update_tag(tag_id, args.get('name'))})
        except NoResultFound:
            return util.respond(404)

    @jwt_required
    def delete(self, tag_id):
        try:
            return util.success({"tag": delete_tag(tag_id)})
        except NoResultFound:
            return util.respond(404)
