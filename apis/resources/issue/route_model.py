from marshmallow import Schema, fields
from util import CommonBasicResponse


#################################### Schema ####################################

########## Module ##########
# !!!
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
    upload_file = fields.Raw(type='werkzeug.datastructures.FileStorage', doc='upload_file', example="(binary)")
    upload_filename = fields.Str(doc='upload_filename', example="string")
    upload_description = fields.Str(doc='upload_description', example="string")
    upload_content_type = fields.Str(doc='upload_content_type', example="string")


class CommonIssueSchema(Schema):
    fixed_version_id = fields.Str(doc='fixed_version_id', example="1")
    status_id = fields.Str(doc='status_id', example="1")
    tracker_id = fields.Str(doc='tracker_id', example="1")
    assigned_to_id = fields.Str(doc='assigned_to_id', example="1")
    priority_id = fields.Str(doc='priority_id', example="1")
    only_subproject_issues = fields.Bool(doc='only_subproject_issues', example=True, default=False)
    limit = fields.Int(doc='limit', example=1)
    offset = fields.Int(doc='offset', example=1)
    search = fields.Str(doc='search', example="string")
    selection = fields.Str(doc='selection', example="string")
    sort = fields.Str(doc='sort', example="string")
    

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


# class FileSchema(Schema):
#     upload_file = fields.Raw(type='werkzeug.datastructures.FileStorage', doc='upload_file', example="")


class IssueByProjectSchema(CommonIssueSchema):
    parent_id = fields.Str(doc='parent_id', example="1")
    due_date_start = fields.Str(doc='due_date_start', example="1970-01-01")
    due_date_end = fields.Str(doc='due_date_end', example="1970-01-01")
    with_point = fields.Str(doc='with_point', example=True)
    status_id = fields.Str(doc='tags', example="1,2,3")

    
# !!
class IssueByUserSchema(CommonIssueSchema):
    project_id = fields.Int(doc='project_id', example=1)
    # this one is reserved word!!!
    # from = fields.Str(doc='from', example="string")
    tags = fields.Str(doc='tags', example="string")


class IssueIssueFamilySchema(Schema):
    with_point = fields.Str(doc='with_point', example=True)


class IssuesProgressByProjectSchema(Schema):
    fixed_version_id = fields.Int(doc='fixed_version_id', example=-1)


#################################### Response ####################################

########## Module ##########
class PaginationPageResponse(Schema):
    current = fields.Int(required=True)
    prev = fields.Int(required=True, default=None)
    next = fields.Int(required=True)
    pages = fields.Int(required=True)
    limit = fields.Int(required=True)
    offset = fields.Int(required=True)
    total = fields.Int(required=True)


class PaginationResponse(Schema):
    page = fields.Nested(PaginationPageResponse, required=True)

class BasicIsssueResponse(Schema):
    id = fields.Int(required=True)
    name = fields.Str(required=True)


class ProjectExtraResponse(BasicIsssueResponse):
    id = fields.Int(required=True)
    name = fields.Str(required=True)
    display = fields.Str(required=True)


class SingleIssueGetDataAuthorResponse(BasicIsssueResponse):
    login = fields.Str(required=True)


class IssueTagResponse(Schema):
    tags = fields.List(fields.Nested(
       BasicIsssueResponse, required=True, default=[]))


class RelationsResponse(IssueTagResponse):
    id = fields.Int(required=True)
    issue_id = fields.Int(required=True)
    issue_to_id = fields.Int(required=True)
    relation_type = fields.Str(required=True)
    delay = fields.Str(required=True, allow_none=True)


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
    relations = fields.List(fields.Nested(
        RelationsResponse, required=True))
    children = fields.List(fields.Nested(
       SingleIssueGetDataChildrenResponse, required=True))
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

class SingleIssuePutDataResponse(CommonSingleIssueResponse):
    estimated_hours = fields.Float(required=True)
    created_date = fields.Str(required=True, example="1970-01-01T00:00:00")   
    point = fields.Int(required=True)
    relations = fields.List(fields.Nested(
        RelationsResponse, required=True))
    project = fields.Nested(ProjectExtraResponse, required=True)
    updated_on = fields.Str(
        required=True, example="1970-01-01T00:00:00")
    has_children = fields.Bool(required=True)
    children = fields.List(fields.Nested(
       SingleIssueGetDataChildrenResponse, required=True))
    parent = fields.Nested(
        ParentResponse, required=True)


class IssueByProjectDataResponse(CommonSingleIssueResponse, IssueTagResponse):
    estimated_hours = fields.Float(required=True)
    created_date = fields.Str(required=True, example="1970-01-01T00:00:00")   
    point = fields.Int(required=True)
    relations = fields.List(fields.Nested(
        RelationsResponse, required=True))
    project = fields.Nested(ProjectExtraResponse, required=True)
    is_private = fields.Bool(required=True)
    updated_on = fields.Str(
        required=True, example="1970-01-01T00:00:00")
    closed_on = fields.Str(
        required=True, example="1970-01-01T00:00:00", default=None)
    family = fields.Bool(required=True)
    has_children = fields.Bool(required=True)
    

class IssueByProjectDataWithPageResponse(PaginationResponse):
    issue_list = fields.Nested(
        IssueByProjectDataResponse, required=True)

class IssueByUserDataResponse(CommonSingleIssueResponse, IssueTagResponse):
    estimated_hours = fields.Float(required=True)
    created_date = fields.Str(required=True, example="1970-01-01T00:00:00")   
    point = fields.Int(required=True)
    relations = fields.List(fields.Nested(
        RelationsResponse, required=True))
    updated_on = fields.Str(
        required=True, example="1970-01-01T00:00:00")
    family = fields.Bool(required=True)
    has_children = fields.Bool(required=True)
    

class IssueByUserDataWithPageResponse(PaginationResponse):
    issue_list = fields.List(fields.Nested(
       IssueByUserDataResponse, required=True))

class IssueFamilyDataParentResponse(CommonSingleIssueResponse, IssueTagResponse):
    project = fields.Nested(ProjectExtraResponse, required=True)

class IssueFamilyDataChildrenResponse(CommonSingleIssueResponse, IssueTagResponse):
    project = fields.Nested(ProjectExtraResponse, required=True)
    updated_on = fields.Str(
        required=True, example="1970-01-01T00:00:00")
    family = fields.Bool(required=True)
    has_children = fields.Bool(required=True)

class IssueRelationDataChildrenResponse(CommonSingleIssueResponse, IssueTagResponse):
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
        fields.Nested(IssueRelationDataChildrenResponse))


class IssueStatusDataResponse(BasicIsssueResponse):
    is_closed = fields.Bool(required=True)


class IssuePriorityDataResponse(BasicIsssueResponse):
    is_closed = fields.Bool(required=True)


class IssueTrackerDataResponse(BasicIsssueResponse):
    pass


class BasicParentResponse(BasicIsssueResponse):
    status = fields.Nested(BasicIsssueResponse, default={})
    tracker = fields.Nested(BasicIsssueResponse, default={})
    assigned_to = fields.Nested(SingleIssueGetDataAuthorResponse, default={})



class IssueByTreeByProjectChildrenDataResponse(Schema):
    pass


class IssueByTreeByProjectChildrenCDataResponse(CommonSingleIssueResponse, IssueTagResponse):
    project = fields.Nested(ProjectExtraResponse, required=True)
    updated_on = fields.Str(
        required=True, example="1970-01-01T00:00:00")
    has_children = fields.Bool(required=True)
    parent = fields.Nested(BasicParentResponse, default=None)
    children = fields.List(
        fields.Nested(IssueByTreeByProjectChildrenDataResponse))

# ? nested children
class IssueByTreeByProjectChildrenDataResponse(CommonSingleIssueResponse, IssueTagResponse):
    project = fields.Nested(ProjectExtraResponse, required=True)
    updated_on = fields.Str(
        required=True, example="1970-01-01T00:00:00")
    has_children = fields.Bool(required=True)
    parent = fields.Nested(BasicParentResponse, default=None)
    children = fields.List(
        fields.Nested(IssueByTreeByProjectChildrenCDataResponse), default=[])


class IssueByTreeByProjectDataResponse(CommonSingleIssueResponse, IssueTagResponse):
    project = fields.Nested(ProjectExtraResponse, required=True)
    updated_on = fields.Str(
        required=True, example="1970-01-01T00:00:00")
    has_children = fields.Bool(required=True)
    parent = fields.Nested(BasicParentResponse, default=None)
    children = fields.List(
        fields.Nested(IssueByTreeByProjectChildrenDataResponse), default=[])


class IssueByStatusByProjectDataContentResponse(CommonSingleIssueResponse):
    updated_on = fields.Str(
        required=True, example="1970-01-01T00:00:00")
    parent = fields.Nested(BasicParentResponse, default=None)

    

class IssueByStatusByProjectDataResponse(Schema):
    Assigned = fields.List(
        fields.Nested(IssueByStatusByProjectDataContentResponse))
    Active = fields.List(
        fields.Nested(IssueByStatusByProjectDataContentResponse))
    Verified = fields.List(
        fields.Nested(IssueByStatusByProjectDataContentResponse))
    InProgress = fields.List(
        fields.Nested(IssueByStatusByProjectDataContentResponse))
    Closed = fields.List(
        fields.Nested(IssueByStatusByProjectDataContentResponse))
    Solved = fields.List(
        fields.Nested(IssueByStatusByProjectDataContentResponse))


class IssuesProgressByProjectDataResponse(Schema):
    Assigned = fields.Int()
    Active = fields.Int()
    Verified = fields.Int()
    InProgress = fields.Int()
    Closed = fields.Int()
    Solved = fields.Int()


########## API Action#############

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


class IssueByProjectResponseWithPage(CommonBasicResponse):
    data = fields.List(fields.Nested(
       IssueByProjectDataWithPageResponse, required=True))


class IssueByUserResponseWithPage(CommonBasicResponse):
    data = fields.List(fields.Nested(
       IssueByUserDataWithPageResponse, required=True))

class IssueFamilyResponse(CommonBasicResponse):
    data = fields.Nested(IssueFamilyDataResponse, required=True)


class IssueStatusResponse(CommonBasicResponse):
    data = fields.List(fields.Nested(
        IssueStatusDataResponse, required=True))


class IssuePriorityResponse(CommonBasicResponse):
    data = fields.List(fields.Nested(
        IssuePriorityDataResponse, required=True))


class IssueTrackerResponse(CommonBasicResponse):
    data = fields.List(fields.Nested(
        IssueTrackerDataResponse, required=True))


class IssueByTreeByProjectResponse(CommonBasicResponse):
    data = fields.List(fields.Nested(
       IssueByTreeByProjectDataResponse, required=True))


class IssueByStatusByProjectResponse(CommonBasicResponse):
    data = fields.Nested(IssueByStatusByProjectDataResponse, required=True)


class IssuesProgressByProjectResponse(CommonBasicResponse):
    data = fields.Nested(IssuesProgressByProjectDataResponse, required=True)