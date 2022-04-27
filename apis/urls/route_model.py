from marshmallow import Schema, fields, missing
from util import CommonBasicResponse


#################################### Schema ####################################

########## Module ##########
# !!!

class CommonIssueSchema(Schema):
    fixed_version_id = fields.Str(doc='fixed_version_id', example="1")
    status_id = fields.Str(doc='status_id', example="1")
    tracker_id = fields.Str(doc='tracker_id', example="1")
    assigned_to_id = fields.Str(doc='assigned_to_id', example="1")
    priority_id = fields.Str(doc='priority_id', example="1")
    only_superproject_issues = fields.Bool(doc='only_superproject_issues', example=True, missing=False)
    limit = fields.Int(doc='limit', example=1)
    offset = fields.Int(doc='offset', example=1)
    search = fields.Str(doc='search', example="string")
    selection = fields.Str(doc='selection', example="string")
    sort = fields.Str(doc='sort', example="string")
    

########## API Action ##########    

# class FileSchema(Schema):
#     upload_file = fields.Raw(type='werkzeug.datastructures.FileStorage', doc='upload_file', example="")

 
# !!!
class IssueByUserSchema(CommonIssueSchema):
    project_id = fields.Int(doc='project_id', example=1)
    # this one is reserved word!!!
    # from = fields.Str(doc='from', example="string")
    tags = fields.Str(doc='tags', example="string")



class IssueFilterByProjectPostAndPutSchema(Schema):
    name = fields.Str(doc='name', example='string', required=True)
    type = fields.Str(doc='type', example='string', required=True)
    assigned_to_id = fields.Str(doc='assigned_to_id', example='1', allow_none=True)
    fixed_version_id = fields.Str(doc='fixed_version_id', example='1', allow_none=True)
    focus_tab = fields.Str(doc='focus_tab', example='string', allow_none=True)
    group_by = fields.Dict(
        doc='group_by', 
        example={"dimension": "status", "value": [{"id": 1, "name": "Active", "is_closed": False}]},
        allow_none=True
    )
    priority_id = fields.Str(doc='priority_id', example='1', allow_none=True)
    show_closed_issues = fields.Bool(doc='show_closed_issues', example=True, allow_none=True)
    show_closed_versions = fields.Bool(doc='show_closed_versions', example=True, allow_none=True)
    status_id = fields.Str(doc='status_id', example='1', allow_none=True)
    tags = fields.Str(doc='tags', example='1,2,3', allow_none=True)
    tracker_id = fields.Str(doc='tracker_id', example='1', allow_none=True)

class IssueTrackerSchema(Schema):
    new = fields.Bool()
    project_id = fields.Int()

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


class MyIssuePeirodStatisticsDataResponse(Schema):
    open = fields.Int(required=True)
    closed = fields.Int(required=True)


class BasicDashboardIssueDataResponse(Schema):
    name = fields.Str(required=True)
    number = fields.Int(required=True)


class GetFlowTypeDataResponse(Schema):
    name = fields.Str(required=True)
    flow_type_id = fields.Int(required=True)


class IssueFilterByProjectDataResponse(BasicIsssueResponse):
    user_id = fields.Int(required=True)
    project_id = fields.Int(required=True)
    type = fields.Str(required=True)
    custom_filter = fields.Dict(required=True)


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



class IssueByUserResponseWithPage(CommonBasicResponse):
    data = fields.List(fields.Nested(
       IssueByUserDataWithPageResponse, required=True))


class IssueStatusResponse(CommonBasicResponse):
    data = fields.List(fields.Nested(
        IssueStatusDataResponse, required=True))


class IssuePriorityResponse(CommonBasicResponse):
    data = fields.List(fields.Nested(
        IssuePriorityDataResponse, required=True))


class IssueTrackerResponse(CommonBasicResponse):
    data = fields.List(fields.Nested(
        IssueTrackerDataResponse, required=True))


class DashboardIssuePriorityResponse(CommonBasicResponse):
    data = fields.List(fields.Nested(
       BasicDashboardIssueDataResponse, required=True))


class DashboardIssueProjectResponse(CommonBasicResponse):
    data = fields.List(fields.Nested(
       BasicDashboardIssueDataResponse, required=True))


class DashboardIssueTypeResponse(CommonBasicResponse):
    data = fields.List(fields.Nested(
       BasicDashboardIssueDataResponse, required=True))

class GetFlowTypeResponse(CommonBasicResponse):
    data = fields.List(fields.Nested(
       GetFlowTypeDataResponse, required=True))


###### TraceOrder ######

#################################### Schema ####################################

class TraceOrdersSchema(Schema):
    project_id = fields.Int(example=1, required=True)

class TraceOrdersPostSchema(Schema):
    name = fields.Str(example="name", required=True)
    project_id = fields.Int(example=1, required=True)
    order = fields.List(fields.Str(), required=True)
    default = fields.Bool(example=True, required=True)

class TraceOrdersPutSchema(Schema):
    name = fields.Str(example="name")
    project_id = fields.Int(example=1)
    order = fields.List(fields.Str())
    default = fields.Bool(example=True)


#################################### Response ####################################

########## Module ##########

class TraceOrdersGetData(BasicIsssueResponse):
    order = fields.List(fields.Str(), example=["Epic", "Feature", "Test Plan"])
    default = fields.Bool(example=True)

class GetTraceResultData(Schema):
    project_id = fields.Int()
    total_num = fields.Int()
    current_num = fields.Int()
    result = fields.List(fields.Dict(example={
        "Epic": {
            "id": 1,
            "name": "name",
            "tracker": "Epic",
            "status": {
                "id": 1,
                "name": "Active"
            }
        }
    }))
    start_time = fields.Str(example="1970-01-01 00:00:00.000000")
    finish_time = fields.Str(example="1970-01-01 00:00:00.000000")
    exception = fields.Str(default=None)

########## API action ##########

class TraceOrdersGetResponse(CommonBasicResponse):
    data = fields.List(fields.Nested(TraceOrdersGetData))

class TraceOrdersPostResponse(CommonBasicResponse):
    data = fields.Dict(example={"trace_order": 1})

class GetTraceResultResponse(CommonBasicResponse):
    data = fields.Nested(GetTraceResultData)
