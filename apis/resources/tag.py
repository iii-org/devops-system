import base64
import json

from flask_jwt_extended import jwt_required, get_jwt_identity
from flask_restful import Resource, reqparse, inputs
from sqlalchemy.orm.exc import NoResultFound

import model
import util as util
from model import db
from resources import apiError, role

error_tagname_is_exists = "Tag Name was Created"


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

def get_tags_for_dict(project_id = None):
    output = {}
    if project_id is None:
        tags = model.Tag.query.all()
    else:
        tags = model.Tag.query.filter_by(project_id=project_id).all()
    for tag in tags:
        output[int(tag.id)] = {'id': int(tag.id), 'name': tag.name}
    return output



def get_tags(project_id=None):
    output = []
    if project_id is None:
        tags = model.Tag.query.all()
    else:
        tags = model.Tag.query.filter_by(project_id=project_id).all()
    for tag in tags:
        output.append(row_to_dict(tag))
    return output


def get_tag(tag_id):
    tag = model.Tag.query.filter_by(id=tag_id).first()
    return row_to_dict(tag)


def check_tags(project_id, tag_name):
    return model.Tag.query.filter_by(project_id=project_id, name=tag_name).count()


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


def delete_tag(tag_id):
    model.Tag.query.filter_by(id=tag_id).delete()
    db.session.commit()
    return tag_id


class Tags(Resource):
    @jwt_required
    def get(self):
        try:
            parser = reqparse.RequestParser()
            parser.add_argument('project_id', type=int)
            args = parser.parse_args()
            if args.get('project_id', None) is None:
                return util.success({"tags": get_tags()})
            else:
                return util.success({"tags": get_tags(args.get('project_id'))})
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
                return util.respond(404, error_tagname_is_exists)
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
