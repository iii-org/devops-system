from marshmallow import Schema, fields
from util import CommonBasicResponse

### User Login

#################################### Schema ####################################

########## API Action ##########

class LoginSchema(Schema):
    username = fields.Str(required=True, doc='username',example="admin")
    password = fields.Str(required=True, default=0, doc='password',example="III")

#################################### Response ####################################

########## Module ##########

########## API Action ##########

class DataSchema(Schema):
    pass

class LoginAdInfoJsonSchema(Schema):
    is_pass = fields.Boolean(required=True)
    login = fields.Str(required=True)
    data = fields.Nested(DataSchema,required=False)

class LoginJsonSchema(Schema):
    status = fields.Str(required=True)
    token = fields.Str(required=True)
    ad_info = fields.Nested(LoginAdInfoJsonSchema,required=True)


class LoginResponse(Schema):
    message = fields.Str(required=True)
    # input class
    data = fields.Nested(LoginJsonSchema,required=True)
    datetime = fields.Str(required=True)

##################################################################



### Create User 

#################################### Schema ####################################

class PostSingleUserSchema(Schema):
    phone = fields.Str(required=True, doc='phone',example="0999999999#123")
    name = fields.Str(required=True, doc='name',example="測試用蒸發RD")
    email = fields.Email(required=True, doc='email',example="rd@vapor.nowhere")
    login = fields.Str(required=True, doc='login',example="postman_test_rd")
    password = fields.Str(required=True, doc='password',example="OpenStack0")
    role_id = fields.Integer(required=True, doc='role_id',example=1)
    status = fields.Str(required=True, doc='status',example="enable")
    force = fields.Boolean(required=True,doc='force',example=False) 

########## API Action ##########
    

#################################### Response ####################################

########## Module ##########
class SingleUserDataResponse(Schema):
    user_id = fields.Integer(required=True, doc='user_id')
    plan_user_id = fields.Integer(required=True, doc='plan_user_id')
    repository_user_id = fields.Integer(required=True, doc='repository_user_id')
    harbor_user_id = fields.Integer(required=True, doc='harbor_user_id')
    kubernetes_sa_name = fields.Str(required=True, doc='kubernetes_sa_name')

class SingleUserDefaultRoleResponse(Schema):
    id = fields.Integer(required=False, doc='role_id')
    name = fields.Str(required=False, doc='name')

class SingleUserListResponse(Schema):
    phone = fields.Str(required=False, doc='phone',example="0999999999#123")
    name = fields.Str(required=False, doc='name',example="測試用蒸發RD")
    email = fields.Email(required=False, doc='email',example="rd@vapor.nowhere")
    login = fields.Str(required=False, doc='login',example="postman_test_rd")
    status = fields.Str(required=False, doc='status',example="enable")
    department = fields.Str(required=False, doc='department',example="department")
    title = fields.Str(required=False, doc='title',example="title")
    id = fields.Integer(required=False, doc='role_id',example=1)
    update_at = fields.Str(required=False, doc='update_at')
    from_ad = fields.Boolean(required=False,doc='from_ad',example=False)
    create_at = fields.Str(required=False,example="2020-02-21T01:00:00.000000")
    default_role = fields.Nested(SingleUserDefaultRoleResponse,required=False)

class SingleUserResponse(Schema):
    message = fields.Str(required=True, doc='message',example="success")
    data = fields.Nested(SingleUserListResponse,required=False)
    datetime = fields.Str(required=False,example="2020-02-21T01:00:00.000000")
########## API Action ##########

class CreateSingleUserResponse(SingleUserResponse):
    data = fields.Nested(SingleUserDataResponse,required=False)

##################################################################

###  Get Single User

#################################### Schema ####################################

class PutSingleUserSchema(Schema):
    phone = fields.Str(required=False, doc='phone',example="0999999999#123")
    name = fields.Str(required=False, doc='name',example="測試用蒸發RD")
    email = fields.Email(required=False, doc='email',example="rd@vapor.nowhere")
    login = fields.Str(required=False, doc='login',example="postman_test_rd")
    password = fields.Str(required=True, doc='password',example="OpenStack0")
    old_password = fields.Str(required=True, doc='old_password',example="OpenStack0")
    role_id = fields.Integer(required=False, doc='role_id',example=1)
    status = fields.Str(required=False, doc='status',example="enable")
    force = fields.Boolean(required=False,doc='force',example=False) 
    department = fields.Str(required=False, doc='department',example="department")
    title = fields.Str(required=False, doc='title',example="title")

########## API Action ##########




##################################################################




### User List

#################################### Schema ####################################

########## API Action ##########

class UserListSchema(Schema):
    role_ids = fields.Str(required=False, doc='role_ids',example=1)
    page = fields.Integer(required=False, doc='page',example=10)
    per_page = fields.Integer(required=False, doc='per_page')
    search = fields.Str(required=False, doc='search',example="3,5")

#################################### Response ####################################

########## Module ##########

########## API Action ##########
    
class SingleUserPageResponse(Schema):
    current = fields.Integer(required=True, doc=1)
    prev = fields.Integer(required=True, doc=None)
    next = fields.Integer(required=True, doc=None)
    pages = fields.Integer(required=True, doc=1)
    per_page = fields.Integer(required=False)
    total = fields.Integer(required=True, doc=4)

class SingleUserUserListResponse(Schema):
    user_list = fields.List(fields.Nested(SingleUserListResponse), required=True)

class UserListResponse(Schema):
    message = fields.Str(required=True, doc='message',example="success")
    data = fields.Nested(SingleUserDataResponse,required=False)
    datetime = fields.Str(required=False,example="2020-02-21T01:00:00.000000")
class GetUserListResponse(Schema):
    message = fields.Str(required=True, doc='message',example="success")
    data = fields.Nested(SingleUserUserListResponse,required=False)
    datetime = fields.Str(required=False,example="2020-02-21T01:00:00.000000")


### User Message Type

#################################### Schema ####################################

########## API Action ##########

class GetUserMessageTypeSchema(Schema):
    limit = fields.Integer(required=True)
    offset = fields.Integer(required=True)

class PatchUserMessageTypeSchema(Schema):
    notification = fields.Boolean()
    mail = fields.Boolean()
    teams = fields.Boolean()

#################################### Response ####################################

########## Module ##########

########## API Action ##########


class GetUserMessageTypeRes(CommonBasicResponse):
    data = fields.Dict(example=
        {    
            "mail": False,
            "notification": True,
            "teams": False,
            "user": {
                "id": 1,
                "login": "login",
                "name": "name"
            }
        }
    )

class GetUsersMessageTypeRes(CommonBasicResponse):
    data = fields.Dict(example={
        "page": {
            "current": 1,
            "limit": 10,
            "next": 2,
            "offset": 0,
            "pages": 7,
            "prev": None,
            "total": 70
        },
        "user_message_type": [
            {
                "mail": False,
                "notification": True,
                "teams": False,
                "user": {
                    "id": 1,
                    "login": "login",
                    "name": "name"
                }
            },
        ]}
    )
    