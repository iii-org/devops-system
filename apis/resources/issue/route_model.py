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



#################################### Response ####################################

########## Module ##########
class PaginationPageSchema(Schema):
    current = fields.Int(required=True)
    prev = fields.Int(required=True, default=None)
    next = fields.Int(required=True)
    pages = fields.Int(required=True)
    limit = fields.Int(required=True)
    offset = fields.Int(required=True)
    total = fields.Int(required=True)


class PaginationSchema(Schema):
    page = fields.Nested(PaginationPageSchema, required=True)

class BasicIsssueSchema(Schema):
    id = fields.Int(required=True)
    name = fields.Str(required=True)


class ProjectExtraSchema(BasicIsssueSchema):
    id = fields.Int(required=True)
    name = fields.Str(required=True)
    display = fields.Str(required=True)


class SingleIssueGetDataAuthorSchema(BasicIsssueSchema):
    login = fields.Str(required=True)


class IssueTagSchema(Schema):
    tags = fields.List(fields.Nested(
       BasicIsssueSchema, required=True, default=[]))


class RelationsSchema(IssueTagSchema):
    id = fields.Int(required=True)
    issue_id = fields.Int(required=True)
    issue_to_id = fields.Int(required=True)
    relation_type = fields.Str(required=True)
    delay = fields.Str(required=True, allow_none=True)


class SingleIssueGetDataChildrenSchema(BasicIsssueSchema, IssueTagSchema):
    status = fields.Nested(BasicIsssueSchema, required=True)
    assigned_to = fields.Nested(SingleIssueGetDataAuthorSchema, required=True)
    tracker = fields.Nested(BasicIsssueSchema, required=True)


class SingleIssueGetDataAttachSchema(Schema):
    id = fields.Int(required=True)
    filename = fields.Str(required=True)
    filesize = fields.Int(required=True)
    content_type = fields.Str(required=True)
    description = fields.Str(required=True)
    content_url = fields.Str(required=True)
    thumbnail_url = fields.Str(required=True)
    author = fields.Nested(BasicIsssueSchema, required=True)
    created_on = fields.Str(required=True, example="1970-01-01T00:00:00")


class JournalDetailsSchema(Schema):
    name = fields.Str()
    property = fields.Str(allow_none=True)
    old_value = fields.Str(allow_none=True)
    new_value = fields.Str(allow_none=True)


class SingleIssueGetDataJournalSchema(Schema):
    id = fields.Int(required=True)
    user = fields.Nested(BasicIsssueSchema, required=True)
    notes = fields.Str(required=True)
    created_on = fields.Str(required=True, example="1970-01-01T00:00:00")
    # private_notes = fields.Bool
    details = fields.List(fields.Nested(
       JournalDetailsSchema, required=True))
    private_notes = fields.Bool(required=True)


class CommonSingleIssueSchema(Schema):
    id = fields.Int(required=True)
    name = fields.Str(required=True)
    project = fields.Nested(BasicIsssueSchema, required=True)
    description = fields.Str(required=True)
    start_date = fields.Str(required=True, example="1970-01-01", default=None)
    assigned_to = fields.Nested(SingleIssueGetDataAuthorSchema, default={})
    fixed_version = fields.Nested(BasicIsssueSchema, default={})
    due_date = fields.Str(required=True, example="1970-01-01", default=None)
    done_ratio = fields.Int(required=True)
    is_closed = fields.Bool(required=True)
    issue_link = fields.Str(required=True)
    tracker = fields.Nested(BasicIsssueSchema, default={})
    priority = fields.Nested(BasicIsssueSchema, default={})
    status = fields.Nested(BasicIsssueSchema, default={})
    author = fields.Nested(BasicIsssueSchema, default={})


class ParentSchema(CommonSingleIssueSchema):
    estimated_hours = fields.Float(required=True)
    created_date = fields.Str(required=True, example="1970-01-01T00:00:00")   
    point = fields.Int(required=True)
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
        required=True, example="1970-01-01T00:00:00")


class SingleIssueGetDataSchema(CommonSingleIssueSchema):
    estimated_hours = fields.Float(required=True)
    created_date = fields.Str(required=True, example="1970-01-01T00:00:00")   
    point = fields.Int(required=True)
    relations = fields.List(fields.Nested(
        RelationsSchema, required=True))
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
        required=True, example="1970-01-01T00:00:00")


class SingleIssuePostDataSchema(CommonSingleIssueSchema):
    estimated_hours = fields.Float(required=True)
    created_date = fields.Str(required=True, example="1970-01-01T00:00:00")   
    point = fields.Int(required=True)
    relations = fields.List(fields.Nested(
        RelationsSchema, required=True))
    updated_on = fields.Str(
        required=True, example="1970-01-01T00:00:00")
    has_children = fields.Bool(required=True)

class SingleIssuePutDataSchema(CommonSingleIssueSchema):
    estimated_hours = fields.Float(required=True)
    created_date = fields.Str(required=True, example="1970-01-01T00:00:00")   
    point = fields.Int(required=True)
    relations = fields.List(fields.Nested(
        RelationsSchema, required=True))
    project = fields.Nested(ProjectExtraSchema, required=True)
    updated_on = fields.Str(
        required=True, example="1970-01-01T00:00:00")
    has_children = fields.Bool(required=True)
    children = fields.List(fields.Nested(
       SingleIssueGetDataChildrenSchema, required=True))
    parent = fields.Nested(
        ParentSchema, required=True)


class IssueByProjectDataResponse(CommonSingleIssueSchema, IssueTagSchema):
    estimated_hours = fields.Float(required=True)
    created_date = fields.Str(required=True, example="1970-01-01T00:00:00")   
    point = fields.Int(required=True)
    relations = fields.List(fields.Nested(
        RelationsSchema, required=True))
    project = fields.Nested(ProjectExtraSchema, required=True)
    is_private = fields.Bool(required=True)
    updated_on = fields.Str(
        required=True, example="1970-01-01T00:00:00")
    closed_on = fields.Str(
        required=True, example="1970-01-01T00:00:00", default=None)
    family = fields.Bool(required=True)
    has_children = fields.Bool(required=True)
    

class IssueByProjectDataWithPageResponse(PaginationSchema):
    issue_list = fields.Nested(
        IssueByProjectDataResponse, required=True)

class IssueByUserDataResponse(CommonSingleIssueSchema, IssueTagSchema):
    estimated_hours = fields.Float(required=True)
    created_date = fields.Str(required=True, example="1970-01-01T00:00:00")   
    point = fields.Int(required=True)
    relations = fields.List(fields.Nested(
        RelationsSchema, required=True))
    updated_on = fields.Str(
        required=True, example="1970-01-01T00:00:00")
    family = fields.Bool(required=True)
    has_children = fields.Bool(required=True)
    

class IssueByUserDataWithPageResponse(PaginationSchema):
    issue_list = fields.List(fields.Nested(
       IssueByUserDataResponse, required=True))

class IssueFamilyDataParentResponse(CommonSingleIssueSchema, IssueTagSchema):
    project = fields.Nested(ProjectExtraSchema, required=True)

class IssueFamilyDataChildrenResponse(CommonSingleIssueSchema, IssueTagSchema):
    project = fields.Nested(ProjectExtraSchema, required=True)
    updated_on = fields.Str(
        required=True, example="1970-01-01T00:00:00")
    family = fields.Bool(required=True)
    has_children = fields.Bool(required=True)

class IssueRelationDataChildrenResponse(CommonSingleIssueSchema, IssueTagSchema):
    project = fields.Nested(ProjectExtraSchema, required=True)
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


class IssueStatusDataResponse(BasicIsssueSchema):
    is_closed = fields.Bool(required=True)


class IssuePriorityDataResponse(BasicIsssueSchema):
    is_closed = fields.Bool(required=True)


class IssueTrackerDataResponse(BasicIsssueSchema):
    pass


# class IssueByTreeByProjectParentDataResponse(BasicIsssueSchema):
#     status = fields.Nested(BasicIsssueSchema, default={})
#     tracker = fields.Nested(BasicIsssueSchema, default={})
#     assigned_to = fields.Nested(SingleIssueGetDataAuthorSchema, default={})



# class IssueByTreeByProjectDataResponse(CommonSingleIssueSchema, IssueTagSchema):
#     project = fields.Nested(ProjectExtraSchema, required=True)
#     updated_on = fields.Str(
#         required=True, example="1970-01-01T00:00:00")
#     has_children = fields.Bool(required=True)
#     parent = fields.Nested(IssueByTreeByProjectParentDataResponse, default=None)
#     children = fields.List(
        # fields.Nested(), default=[])



########## API Action#############

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



# class IssueByProjectResponse(CommonBasicResponse):
    # data = fields.List(fields.Nested(
    #    IssueByProjectDataResponse, required=True))

class IssueByProjectResponseWithPage(CommonBasicResponse):
    data = fields.List(fields.Nested(
       IssueByProjectDataWithPageResponse, required=True))



# class IssueByUserResponse(CommonBasicResponse):
#     data = fields.List(fields.Nested(
#        IssueByUserDataResponse, required=True))


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



# class IssueByTreeByProjectResponse(CommonBasicResponse):
#     data = fields.List(fields.Nested(
#        IssueByUserDataWithPageResponse, required=True))