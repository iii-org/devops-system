from marshmallow import Schema, fields, missing
from util import CommonBasicResponse
from resources.system_parameter import check_upload_type
from urls.route_model import BasicIsssueResponse, SingleIssueGetDataAuthorResponse, ProjectExtraResponse, RelationsResponse

### Issue single

#################################### Schema ####################################

########## Module ##########
class FileSchema(Schema):
    upload_file = fields.Raw(doc='upload_file', example="(binary)", validate=check_upload_type)

class CommonSingleIssueSchema(Schema):
    description = fields.Str(doc='description', example="string")
    assigned_to_id = fields.Str(doc='assigned_to_id', example="-1")
    estimated_hours = fields.Int(doc='estimated_hours', example=0)
    parent_id = fields.Str(doc='parent_id', example="-1")
    fixed_version_id = fields.Str(doc='fixed_version_id', example="-1")
    start_date = fields.Str(doc='start_date', example="1970-01-01")
    due_date = fields.Str(doc='due_date', example="1970-01-01")
    done_ratio = fields.Int(doc='done_ratio', example=-1)
    point = fields.Int(doc='point', example=0)
    tags = fields.Str(doc='tags', example="1,2")
    # Attachment upload
    # still finding how to test file type.
    upload_filename = fields.Str(doc='upload_filename', example="string")
    upload_description = fields.Str(doc='upload_description', example="string")
    upload_content_type = fields.Str(doc='upload_content_type', example="string")

########## API Action ##########

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

#################################### Response ####################################

########## Module ##########



class IssueTagResponse(Schema):
    tags = fields.List(fields.Nested(
       BasicIsssueResponse, required=True, default=[]))

class SingleIssueGetDataChildrenResponse(BasicIsssueResponse, IssueTagResponse):
    status = fields.Nested(BasicIsssueResponse, required=True)
    assigned_to = fields.Nested(SingleIssueGetDataAuthorResponse, required=True)
    tracker = fields.Nested(BasicIsssueResponse, required=True)

class SingleIssueGetDataAttachResponse(Schema):
    id = fields.Int(required=True)
    filename = fields.Str(required=True)
    filesize = fields.Int(required=True)
    content_type = fields.Str(required=True)
    description = fields.Str(required=True)
    content_url = fields.Str(required=True)
    thumbnail_url = fields.Str(required=True)
    author = fields.Nested(BasicIsssueResponse, required=True)
    created_on = fields.Str(required=True, example="1970-01-01T00:00:00")


class JournalDetailsResponse(Schema):
    name = fields.Str()
    property = fields.Str(allow_none=True)
    old_value = fields.Str(allow_none=True)
    new_value = fields.Str(allow_none=True)

class SingleIssueGetDataJournalSchema(Schema):
    id = fields.Int(required=True)
    user = fields.Nested(BasicIsssueResponse, required=True)
    notes = fields.Str(required=True)
    created_on = fields.Str(required=True, example="1970-01-01T00:00:00")
    # private_notes = fields.Bool
    details = fields.List(fields.Nested(
       JournalDetailsResponse, required=True))
    private_notes = fields.Bool(required=True)

class CommonSingleIssueResponse(Schema):
    id = fields.Int(required=True)
    name = fields.Str(required=True)
    project = fields.Nested(BasicIsssueResponse, required=True)
    description = fields.Str(required=True)
    start_date = fields.Str(required=True, example="1970-01-01", default=None)
    assigned_to = fields.Nested(SingleIssueGetDataAuthorResponse, default={})
    fixed_version = fields.Nested(BasicIsssueResponse, default={})
    due_date = fields.Str(required=True, example="1970-01-01", default=None)
    done_ratio = fields.Int(required=True)
    is_closed = fields.Bool(required=True)
    issue_link = fields.Str(required=True)
    tracker = fields.Nested(BasicIsssueResponse, default={})
    priority = fields.Nested(BasicIsssueResponse, default={})
    status = fields.Nested(BasicIsssueResponse, default={})
    author = fields.Nested(BasicIsssueResponse, default={})

class ParentResponse(CommonSingleIssueResponse):
    estimated_hours = fields.Float(required=True)
    created_date = fields.Str(required=True, example="1970-01-01T00:00:00")   
    point = fields.Int(required=True)
    attachments = fields.List(fields.Nested(
       SingleIssueGetDataAttachResponse), default=[])
    relations = fields.List(fields.Nested(
        RelationsResponse, required=True))
    parent = fields.List(fields.Nested(
        RelationsResponse, required=True))
    # changesets = fields.List(default=[])
    journals = fields.List(fields.Nested(
       SingleIssueGetDataJournalSchema, required=True))
    # watchers = fields.List(default=[])
    updated_date = fields.Str(
        required=True, example="1970-01-01T00:00:00")

# ? Nested parent info
class SingleIssueGetDataResponse(CommonSingleIssueResponse):
    estimated_hours = fields.Float(required=True)
    created_date = fields.Str(required=True, example="1970-01-01T00:00:00")   
    point = fields.Int(required=True)
    relations = fields.List(fields.Dict(), required=True)
    children = fields.List(fields.Dict(), required=True)
    attachments = fields.List(fields.Nested(
       SingleIssueGetDataAttachResponse), default=[])
    parent = fields.Nested(
        ParentResponse, required=True)
    # changesets = fields.List(default=[])
    journals = fields.List(fields.Nested(
       SingleIssueGetDataJournalSchema, required=True))
    # watchers = fields.List(default=[])
    updated_date = fields.Str(
        required=True, example="1970-01-01T00:00:00")

class SingleIssuePostDataResponse(CommonSingleIssueResponse):
    estimated_hours = fields.Float(required=True)
    created_date = fields.Str(required=True, example="1970-01-01T00:00:00")   
    point = fields.Int(required=True)
    relations = fields.List(fields.Nested(
        RelationsResponse, required=True))
    updated_on = fields.Str(
        required=True, example="1970-01-01T00:00:00")
    has_children = fields.Bool(required=True)
    children = fields.List(fields.Dict(), required=True)
    parent = fields.Nested(
        ParentResponse, required=True)
    family = fields.Bool(required=True)

class SingleIssuePutDataResponse(CommonSingleIssueResponse):
    estimated_hours = fields.Float(required=True)
    created_date = fields.Str(required=True, example="1970-01-01T00:00:00")   
    point = fields.Int(required=True)
    relations = fields.List(fields.Dict(), required=True)
    project = fields.Nested(ProjectExtraResponse, required=True)
    updated_on = fields.Str(
        required=True, example="1970-01-01T00:00:00")
    has_children = fields.Bool(required=True)
    children = fields.List(fields.Dict(), required=True)
    parent = fields.Nested(
        ParentResponse, required=True)
    family = fields.Bool(required=True)

class IssueFamilyDataParentResponse(CommonSingleIssueResponse, IssueTagResponse):
    project = fields.Nested(ProjectExtraResponse, required=True)

class IssueFamilyDataChildrenResponse(CommonSingleIssueResponse, IssueTagResponse):
    project = fields.Nested(ProjectExtraResponse, required=True)
    updated_on = fields.Str(
        required=True, example="1970-01-01T00:00:00")
    family = fields.Bool(required=True)
    has_children = fields.Bool(required=True)

class IssueFamilyDataRelationResponse(CommonSingleIssueResponse, IssueTagResponse):
    project = fields.Nested(ProjectExtraResponse, required=True)
    updated_on = fields.Str(
        required=True, example="1970-01-01T00:00:00")
    has_children = fields.Bool(required=True)
    relation_id = fields.Int(required=True)

class IssueFamilyDataResponse(Schema):
    parent = fields.Nested(IssueFamilyDataParentResponse)
    children = fields.List(
        fields.Nested(IssueFamilyDataChildrenResponse))
    relations = fields.List(
        fields.Nested(IssueFamilyDataRelationResponse))

class MyOpenIssueStatisticsDataResponse(Schema):
    active_issue_number = fields.Int(required=True)

########## API Action ##########

class SingleIssueGetResponse(CommonBasicResponse):
    data = fields.Nested(
        SingleIssueGetDataResponse, required=True)

class SingleIssuePostResponse(CommonBasicResponse):
    data = fields.Nested(
        SingleIssuePostDataResponse, required=True)

class SingleIssuePutResponse(CommonBasicResponse):
    data = fields.Nested(
        SingleIssuePutDataResponse, required=True)

class SingleIssueDeleteResponse(CommonBasicResponse):
    data = fields.Str(default="success")


### Issue Family

#################################### Schema ####################################

class IssueIssueFamilySchema(Schema):
    with_point = fields.Str(doc='with_point', example=True)

#################################### Response ####################################

class IssueFamilyResponse(CommonBasicResponse):
    data = fields.Nested(IssueFamilyDataResponse, required=True)


### Issue Statistics

#################################### Response ####################################

########## Module ##########

class MyIssuePeirodStatisticsDataResponse(Schema):
    open = fields.Int(required=True)
    closed = fields.Int(required=True)

########## API Action ##########

class MyOpenIssueStatisticsResponse(CommonBasicResponse):
    data = fields.Nested(MyOpenIssueStatisticsDataResponse, required=True)

class MyIssueWeekStatisticsResponse(CommonBasicResponse):
    data = fields.Nested(MyIssuePeirodStatisticsDataResponse, required=True)

class MyIssueMonthStatisticsResponse(CommonBasicResponse):
    data = fields.Nested(MyIssuePeirodStatisticsDataResponse, required=True)


##### Issue's Relation issue

#################################### Schema ####################################

class RelationSchema(Schema):
    issue_id = fields.Int(doc='issue_id', example=1)
    issue_to_ids = fields.List(fields.Int(), doc='issue_id', example=[1,2,3])


##### Issue closable

#################################### Response ####################################

class CheckIssueClosableResponse(CommonBasicResponse):
    data = fields.Bool(required=True)


##### Issue commit relationship 

#################################### Schema ####################################

class IssueCommitRelationGetSchema(Schema):
    commit_id = fields.Str(doc='commit_id', example='abc123def456', required=True)

class IssueCommitRelationPatchSchema(IssueCommitRelationGetSchema):
    issue_ids = fields.List(fields.Int(), doc='issue_ids', required=True, example=[1,2,3])
    

#################################### Response ####################################

########## Module ##########

class IssueCommitRelationDataResponse(Schema):
    issue_ids = fields.Dict(required=True, example={"1": True})

########## API Action ##########

class IssueCommitRelationResponse(CommonBasicResponse):
    data = fields.Nested(IssueCommitRelationDataResponse, required=True)