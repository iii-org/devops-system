from marshmallow import Schema, fields
from util import CommonBasicResponse

### Project Relation

#################################### Schema ####################################

########## API Action ##########

class GetProjectFamilymembersByUserDataSchema(Schema):
    id = fields.Int(required=True)
    name = fields.Str(required=True)
    role_id = fields.Int(required=True)
    role_name = fields.Str(required=True)

#################################### Response ####################################

########## Module ##########

class GetProjectFamilymembersByUserDataSchema(Schema):
    id = fields.Int(required=True)
    name = fields.Str(required=True)
    role_id = fields.Int(required=True)
    role_name = fields.Str(required=True)

########## API Action ##########

class CheckhasSonProjectResponse(Schema):
    has_child = fields.Bool(required=True)

class GetProjectRootIDResponse(Schema):
    root_project_id = fields.Int(required=True)

class GetProjectFamilymembersByUserResponse(CommonBasicResponse):
    data = fields.List(fields.Nested(
        GetProjectFamilymembersByUserDataSchema, required=True))


### Project issue_list

#################################### Schema ####################################

########## Module ##########

class CommonIssueSchema(Schema):
    fixed_version_id = fields.Str(doc='fixed_version_id', example="1")
    status_id = fields.Str(doc='status_id', example="1")
    tracker_id = fields.Str(doc='tracker_id', example="1")
    assigned_to_id = fields.Str(doc='assigned_to_id', example="1")
    priority_id = fields.Str(doc='priority_id', example="1")
    only_subproject_issues = fields.Bool(doc='only_subproject_issues', example=True, missing=False)
    limit = fields.Int(doc='limit', example=1)
    offset = fields.Int(doc='offset', example=1)
    search = fields.Str(doc='search', example="string")
    selection = fields.Str(doc='selection', example="string")
    sort = fields.Str(doc='sort', example="string")

########## API Action ##########

class IssueByProjectSchema(CommonIssueSchema):
    parent_id = fields.Str(doc='parent_id', example="1")
    due_date_start = fields.Str(doc='due_date_start', example="1970-01-01")
    due_date_end = fields.Str(doc='due_date_end', example="1970-01-01")
    with_point = fields.Str(doc='with_point', example=True)
    status_id = fields.Str(doc='tags', example="1,2,3")

class IssuesProgressByProjectSchema(Schema):
    fixed_version_id = fields.Int(doc='fixed_version_id', example=-1)

#################################### Response ####################################

########## Module ##########

class BasicIsssueResponse(Schema):
    id = fields.Int(required=True)
    name = fields.Str(required=True)

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

class IssueTagResponse(Schema):
    tags = fields.List(fields.Nested(
       BasicIsssueResponse, required=True, default=[]))

class ProjectExtraResponse(BasicIsssueResponse):
    id = fields.Int(required=True)
    name = fields.Str(required=True)
    display = fields.Str(required=True)

class SingleIssueGetDataAuthorResponse(BasicIsssueResponse):
    login = fields.Str(required=True)

class RelationsResponse(IssueTagResponse):
    id = fields.Int(required=True)
    issue_id = fields.Int(required=True)
    issue_to_id = fields.Int(required=True)
    relation_type = fields.Str(required=True)
    delay = fields.Str(required=True, allow_none=True)

class BasicParentResponse(BasicIsssueResponse):
    status = fields.Nested(BasicIsssueResponse, default={})
    tracker = fields.Nested(BasicIsssueResponse, default={})
    assigned_to = fields.Nested(SingleIssueGetDataAuthorResponse, default={})

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

class IssueByTreeByProjectDataResponse(CommonSingleIssueResponse, IssueTagResponse):
    project = fields.Nested(ProjectExtraResponse, required=True)
    updated_on = fields.Str(
        required=True, example="1970-01-01T00:00:00")
    has_children = fields.Bool(required=True)
    parent = fields.Dict()
    children = fields.List(fields.Dict(), default=[])

class IssueByStatusByProjectDataContentResponse(CommonSingleIssueResponse):
    updated_on = fields.Str(
        required=True, example="1970-01-01T00:00:00")
    parent = fields.Nested(BasicParentResponse, default=None)
    relations = fields.List(fields.Dict(), default=[])

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

########## API Action ##########

class IssueByProjectResponseWithPage(CommonBasicResponse):
    data = fields.List(fields.Nested(
       IssueByProjectDataWithPageResponse, required=True))

class IssueByTreeByProjectResponse(CommonBasicResponse):
    data = fields.List(fields.Nested(
       IssueByTreeByProjectDataResponse, required=True))

class IssueByStatusByProjectResponse(CommonBasicResponse):
    data = fields.Nested(IssueByStatusByProjectDataResponse, required=True)

class IssuesProgressByProjectResponse(CommonBasicResponse):
    data = fields.Nested(IssuesProgressByProjectDataResponse, required=True)

class IssuesStatisticsByProjectResponse(CommonBasicResponse):
    ''' hard to implement
    "data": {
        "assigned_to": {
            "李毅山(John)": {
                "Active": 0,
                "Assigned": 1,
                "InProgress": 1,
                "Solved": 0,
                "Verified": 1,
                "Closed": 1
            },
        }
    }
    '''
    data = fields.Dict()