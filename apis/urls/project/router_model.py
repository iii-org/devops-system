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

##### Filter issue by project ######

#################################### Schema ####################################
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


#################################### Response ####################################

########## Module ##########

class IssueFilterByProjectDataResponse(BasicIsssueResponse):
    user_id = fields.Int(required=True)
    project_id = fields.Int(required=True)
    type = fields.Str(required=True)
    custom_filter = fields.Dict(required=True)

class IssueFilterByProjectPostDataResponse(Schema):
    custom_filter_id = fields.Int(required=True)

########## API Action ##########

class IssueFilterByProjectGetResponse(CommonBasicResponse):
    data = fields.List(fields.Nested(
       IssueFilterByProjectDataResponse, required=True))

class IssueFilterByProjectPostResponse(CommonBasicResponse):
    data = fields.Nested(IssueFilterByProjectPostDataResponse, required=True)

class IssueFilterByProjectPutResponse(CommonBasicResponse):
    data = fields.Nested(IssueFilterByProjectDataResponse, required=True)


##### # Download project's issue as excel ######

#################################### Schema ####################################

class DownloadProjectSchema(Schema):
    fixed_version_id = fields.Str(doc='fixed_version_id',  example='1')
    status_id = fields.Str(doc='status_id',  example='1')
    tracker_id = fields.Str(doc='tracker_id',  example='1')
    assigned_to_id = fields.Str(doc='assigned_to_id',  example='1')
    priority_id = fields.Str(doc='fixed_version_id',  example='1')
    search = fields.Str(doc='search', example='string')
    selection = fields.Str(doc='selection',  example='1')
    sort = fields.Str(doc='sort', example="string")
    parent_id = fields.Str(doc='parent_id',  example='1')
    due_date_start = fields.Str(doc='due_date_start', example="1970-01-01")
    due_date_end = fields.Str(doc='due_date_end', example="1970-01-01")
    with_point = fields.Str(doc='with_point', example=True, missing=True)
    levels = fields.Int(doc='levels', example=1, missing=3)
    deploy_column = fields.List(
        fields.Dict(example={"field": "name", "display": "議題名稱"}),
        doc='deploy_column', 
        required=True
    )

#################################### Response ####################################

########## Module ##########

class DownloadProjectIsExistDataResponse(Schema):
    file_exist = fields.Bool(required=True)
    create_at = fields.Str(
        required=True, example="1970-01-01T00:00:00")

########## API Action ##########

class DownloadProjectIsExistResponse(CommonBasicResponse):
    data = fields.Nested(DownloadProjectIsExistDataResponse, required=True)

##### List projects ######

#################################### Schema ####################################

########## API Action ##########

class ListMyProjectsSchema(Schema):
    simple = fields.Str(doc='simple',  example='true')
    limit = fields.Int(doc='limit',  example=1)
    offset = fields.Int(doc='offset',  example=1)
    search = fields.Str(doc='search',  example='string')
    disabled = fields.Int(doc='disabled',  example='1')

class CalculateProjectIssuesSchema(Schema):
    project_ids = fields.Str(doc='project_ids', example="1,2,3,4", required=True)

#################################### Response ####################################

########## Module ##########

class ProjectsBasicResponse(BasicIsssueResponse):
    alert = fields.Bool(required=True)
    create_at = fields.Str(required=True, example="1970-01-01 00:00:00.000000", default=None)
    creator_id = fields.Int(required=True)
    description = fields.Str(required=True, default=None)
    disabled = fields.Bool(required=True, default=None)
    display = fields.Str(required=True)
    due_date = fields.Str(required=True, example="1970-01-01", default=None)
    is_lock = fields.Bool(required=True)
    lock_reason = fields.Str(required=True, default=None)
    owner_id = fields.Int(required=True)
    # projects = fields.List()
    ssh_url = fields.Str(required=True)
    start_date = fields.Str(required=True, example="1970-01-01", default=None)
    # trace_order = fields.List()
    update_at = fields.Str(required=True, example="1970-01-01 00:00:00.000000", default=None)
    git_url = fields.Str(required=True)
    repository_ids = fields.List(fields.Int())
    redmine_url = fields.Str(required=True)
    harbor_url = fields.Str(required=True)
    owner_name = fields.Str(required=True)
    department = fields.Str(required=True)
    
class ListMyProjectsDataProjectListResponse(ProjectsBasicResponse):
    starred = fields.Bool()
class CalculateProjectIssuesListResponse(Schema):
    id = fields.Str(required=True)
    closed_count = fields.Int(required=True)
    overdue_count = fields.Int(required=True)
    total_count = fields.Int(required=True)
    project_status = fields.Str(required=True)
    updated_time = fields.Str(required=True, example="1970-01-01 00:00:00", default=None)

class ListMyProjectsProjectListResponse(PaginationResponse):
    project_list = fields.List(fields.Nested(ListMyProjectsDataProjectListResponse), required=True)

class ListMyProjectsDataResponse(Schema):
    project_list = fields.Nested(ListMyProjectsProjectListResponse, required=True)


class CalculateProjectIssuesDataResponse(Schema):
    project_list = fields.List(fields.Nested(CalculateProjectIssuesListResponse), required=True)

########## API Action ##########

class ListMyProjectsResponse(CommonBasicResponse):
    data = fields.Nested(ListMyProjectsDataResponse, required=True)

class CalculateProjectIssuesResponse(CommonBasicResponse):
    data = fields.Nested(CalculateProjectIssuesDataResponse, required=True)

class ListMyProjectsByUserResponse(CommonBasicResponse):
    data = fields.List(fields.Nested(ListMyProjectsDataProjectListResponse), required=True)

##### Single project ######


#################################### Schema ####################################

class SingleProjectPutSchema(Schema):
    display = fields.Str(doc='display',  example='string', required=True)
    description = fields.Str(doc='description',  example="")
    disabled = fields.Bool(doc='disabled',  example=True, required=True)
    start_date = fields.Str(doc='start_date', example="1970-01-01", required=True)
    due_date = fields.Str(doc='due_date', example="1970-01-01", required=True)
    owner_id = fields.Int(doc='owner_id', example=1, required=True)
    parent_id = fields.Int(doc='parent_id', example="1")
    is_inherit_members = fields.Bool(doc='is_inherit_members', example=True)

class SingleProjectPatchSchema(Schema):
    owner_id = fields.Int(doc='owner_id', example=1, required=True)


class SingleProjectPostSchema(SingleProjectPutSchema):
    name = fields.Str(doc='name',  example='string', required=True)
    display = fields.Str(doc='display',  example='string')
    template_id = fields.Int(doc='template_id', example=1)
    tag_name = fields.Str(doc='tag_name', example="string")
    arguments = fields.Str(doc='arguments', example="string")
    owner_id = fields.Int(doc='owner_id', example=1)


#################################### Response ####################################

########## Module ##########

class SingleProjectDataGetResponse(ProjectsBasicResponse):
    pass

class SingleProjectDataPostResponse(Schema):
    project_id = fields.Int(required=True)
    plan_project_id = fields.Int(required=True)
    git_repository_id = fields.Int(required=True)
    harbor_project_id = fields.Int(required=True)
   

########## API Action ##########

class SingleProjectGetResponse(CommonBasicResponse):
    data = fields.Nested(SingleProjectDataGetResponse, required=True)

class SingleProjectPostResponse(CommonBasicResponse):
    data = fields.Nested(SingleProjectDataPostResponse, required=True)

