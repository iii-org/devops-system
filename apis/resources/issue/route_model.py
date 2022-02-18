from marshmallow import Schema, fields

from util import CommonBasicResponse


##### Response #####

### Module ###
class CommonIsssueSchema(Schema):
    id = fields.Int(required=True)
    name = fields.Str(required=True)


class SingleIssuePutProjectSchema(CommonIsssueSchema):
    id = fields.Int(required=True)
    name = fields.Str(required=True)
    display = fields.Str(required=True)


class SingleIssueGetDataAuthorSchema(CommonIsssueSchema):
    login = fields.Str(required=True)


class IssueTagSchema(Schema):
    tags = fields.List(fields.Nested(
       CommonIsssueSchema, required=True, default=[]))


class RelationsSchema(IssueTagSchema):
    id = fields.Int(required=True)
    issue_id = fields.Int(required=True)
    issue_to_id = fields.Int(required=True)
    relation_type = fields.Str(required=True)
    delay = fields.Str(required=True, allow_none=True)


class SingleIssueGetDataChildrenSchema(CommonIsssueSchema, IssueTagSchema):
    status = fields.Nested(CommonIsssueSchema, required=True)
    assigned_to = fields.Nested(SingleIssueGetDataAuthorSchema, required=True)
    tracker = fields.Nested(CommonIsssueSchema, required=True)


class SingleIssueGetDataAttachSchema(Schema):
    id = fields.Int(required=True)
    filename = fields.Str(required=True)
    filesize = fields.Int(required=True)
    content_type = fields.Str(required=True)
    description = fields.Str(required=True)
    content_url = fields.Str(required=True)
    thumbnail_url = fields.Str(required=True)
    author = fields.Nested(CommonIsssueSchema, required=True)
    created_on = fields.Str(required=True, example="1970-01-01T00:00:00.000000")


class JournalDetailsSchema(Schema):
    name = fields.Str()
    property = fields.Str(allow_none=True)
    old_value = fields.Str(allow_none=True)
    new_value = fields.Str(allow_none=True)


class SingleIssueGetDataJournalSchema(Schema):
    id = fields.Int(required=True)
    user = fields.Nested(CommonIsssueSchema, required=True)
    notes = fields.Str(required=True)
    created_on = fields.Str(required=True, example="1970-01-01T00:00:00.000000")
    # private_notes = fields.Bool
    details = fields.List(fields.Nested(
       JournalDetailsSchema, required=True))
    private_notes = fields.Bool(required=True)


class CommonSingleIssueSchema(Schema):
    id = fields.Int(required=True)
    name = fields.Str(required=True)
    project = fields.Nested(CommonIsssueSchema, required=True)
    description = fields.Str(required=True)
    start_date = fields.Str(required=True, example="1970-01-01")
    assigned_to = fields.Nested(SingleIssueGetDataAuthorSchema, required=True)
    fixed_version = fields.Nested(CommonIsssueSchema, default={})
    due_date = fields.Str(required=True, example="1970-01-01")
    tracker = fields.Nested(CommonIsssueSchema, default={})
    status = fields.Nested(CommonIsssueSchema, default={})
    priority = fields.Nested(CommonIsssueSchema, default={})
    author = fields.Nested(CommonIsssueSchema, default={})
    done_ratio = fields.Int(required=True)
    estimated_hours = fields.Float(required=True)
    created_date = fields.Str(required=True, example="1970-01-01T00:00:00.000000")   
    issue_link = fields.Str(required=True)
    is_closed = fields.Bool(required=True)
    point = fields.Int(required=True)
    relations = fields.List(fields.Nested(
        RelationsSchema, required=True))


class ParentSchema(CommonSingleIssueSchema):
    attachments = fields.List(fields.Nested(
       SingleIssueGetDataAttachSchema), default=[])
    relations = fields.List(fields.Nested(
        RelationsSchema, required=True))
    parent = fields.List(fields.Nested(
        RelationsSchema, required=True))
    # changesets = fields.List(default=[])
    journals = fields.List(fields.Nested(
       SingleIssueGetDataJournalSchema, required=True))
    # watchers = fields.List(default=[])
    updated_date = fields.Str(
        required=True, example="1970-01-01T00:00:00.000000")


class SingleIssueGetDataSchema(CommonSingleIssueSchema):
    children = fields.List(fields.Nested(
       SingleIssueGetDataChildrenSchema, required=True))
    attachments = fields.List(fields.Nested(
       SingleIssueGetDataAttachSchema), default=[])
    parent = fields.Nested(
        ParentSchema, required=True)
    # changesets = fields.List(default=[])
    journals = fields.List(fields.Nested(
       SingleIssueGetDataJournalSchema, required=True))
    # watchers = fields.List(default=[])
    updated_date = fields.Str(
        required=True, example="1970-01-01T00:00:00.000000")


class SingleIssuePostDataSchema(CommonSingleIssueSchema):
    updated_on = fields.Str(
        required=True, example="1970-01-01T00:00:00.000000")
    has_children = fields.Bool(required=True)

class SingleIssuePutDataSchema(CommonSingleIssueSchema):
    project = fields.Nested(SingleIssuePutProjectSchema, required=True)
    updated_on = fields.Str(
        required=True, example="1970-01-01T00:00:00.000000")
    has_children = fields.Bool(required=True)
    children = fields.List(fields.Nested(
       SingleIssueGetDataChildrenSchema, required=True))
    parent = fields.Nested(
        ParentSchema, required=True)


### API Action ###

class SingleIssueGetResponse(CommonBasicResponse):
    data = fields.Nested(
        SingleIssueGetDataSchema, required=True)


class SingleIssuePostResponse(CommonBasicResponse):
    data = fields.Nested(
        SingleIssuePostDataSchema, required=True)


class SingleIssuePutResponse(CommonBasicResponse):
    data = fields.Nested(
        SingleIssuePutDataSchema, required=True)

class SingleIssueDeleteResponse(CommonBasicResponse):
    data = fields.Str(default="success")

##### Schema ######

### Module ###

class CommonSingleIssueSchema(Schema):
    description = fields.Str(doc='description', example="string")
    assigned_to_id = fields.Str(doc='assigned_to_id', example=-1)
    estimated_hours = fields.Int(doc='estimated_hours', example=0)
    parent_id = fields.Str(doc='parent_id', example="-1")
    fixed_version_id = fields.Str(doc='fixed_version_id', example="-1")
    start_date = fields.Str(doc='start_date', example="1970-01-01")
    due_date = fields.Str(doc='due_date', example="1970-01-01")
    done_ratio = fields.Int(doc='done_ratio', example=-1)
    point = fields.Int(doc='point', example=0)
    tags = fields.Str(doc='tags', example="1,2")
    # Attachment upload
    upload_file = fields.Raw(type='werkzeug.datastructures.FileStorage', doc='upload_file', example="(binary)")
    upload_filename = fields.Str(doc='upload_filename', example="string")
    upload_description = fields.Str(doc='upload_description', example="string")
    upload_content_type = fields.Str(doc='upload_content_type', example="string")


### API Action ###

class SingleIssuePostSchema(CommonSingleIssueSchema):
    project_id = fields.Int(doc='project_id', example=-1, required=True)
    tracker_id = fields.Int(doc='tracker_id', example=-1, required=True)
    status_id = fields.Int(doc='status_id', example=-1, required=True)
    priority_id = fields.Int(doc='priority_id', example=-1, required=True)
    name = fields.Str(doc='name', example="string", required=True)
    
    
class SingleIssuePutSchema(CommonSingleIssueSchema):
    project_id = fields.Int(doc='project_id', example=-1)
    tracker_id = fields.Int(doc='tracker_id', example=-1)
    status_id = fields.Int(doc='status_id', example=-1)
    priority_id = fields.Int(doc='priority_id', example=-1)
    name = fields.Str(doc='name', example="string")
    note = fields.Str(doc='name', example="string")

class SingleIssueDeleteSchema(Schema):
    force = fields.Bool(doc='force', example="True")

# class FileSchema(Schema):
#     upload_file = fields.Raw(type='werkzeug.datastructures.FileStorage', doc='upload_file', example="")