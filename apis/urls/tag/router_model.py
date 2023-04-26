from marshmallow import Schema, fields, validates_schema
from util import CommonBasicResponse
from model import Tag
from resources import apiError

### Tag Get

#################################### Schema ####################################

########## API Action ##########


class TagSchema(Schema):
    name = fields.Str(required=False, doc="name", example="tag name")


#################################### Response ####################################

########## Module ##########

########## API Action ##########
class TagDataTagResponse(Schema):
    id = fields.Integer(required=False, doc=1)
    name = fields.Str(required=False, doc="name")


class TagDataResponse(Schema):
    tag = fields.Dict(example={"id": 1, "name": "name"}, required=False)


class TagResponse(CommonBasicResponse):
    data = fields.Nested(TagDataResponse, required=True)


class PutTagDataResponse(CommonBasicResponse):
    tag = fields.Integer(required=True, example=1)


class PutTagResponse(CommonBasicResponse):
    data = fields.Nested(PutTagDataResponse, required=True)


##################################################################


### Tags

#################################### Schema ####################################

########## API Action ##########


class PostTagsSchema(Schema):
    project_id = fields.Integer(required=False, doc="project_id", example=231)


class TagsSchema(PostTagsSchema):
    name = fields.Str(required=False, doc="name", example="1")


#################################### Response ####################################

########## Module ##########

########## API Action ##########


class GetTagsDataResponse(CommonBasicResponse):
    tags = fields.List(fields.Dict(example={"id": 1, "name": "name"}, required=False))


class GetTagsResponse(CommonBasicResponse):
    data = fields.Nested(GetTagsDataResponse, required=True)


##################################################################


### Tag's order
class TagOrderSchema(Schema):
    tag_id = fields.Integer(required=True, doc="tag_id", example=1)
    to_tag_id = fields.Integer(required=False, doc="to_tag_id", example=2)

    @validates_schema
    def validate_to_tag_id_and_tag_id_is_in_same_pj(self, data, **kwargs):
        tag_id, to_tag_id = data["tag_id"], data.get("to_tag_id")
        if to_tag_id is not None:
            tags_object = Tag.query.filter(Tag.id.in_([tag_id, to_tag_id])).all()
            if tags_object[0].project_id != tags_object[1].project_id:
                raise apiError.DevOpsError(
                    409,
                    "Tag and to_tag must in the same project",
                    error=apiError.argument_error("to_tag_id"),
                )
