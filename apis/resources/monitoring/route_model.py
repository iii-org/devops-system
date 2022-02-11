from marshmallow import Schema, fields
from util import CommonBasicResponse, CommonResponse


class ServersAliveSchema(Schema):
    project_id = fields.Int(doc='project_id', example=-1)

class ServersAliveResAliveSchema(Schema):
    redmine = fields.Bool(required=True)    
    gitlab = fields.Bool(required=True)    
    harbor = fields.Bool(required=True)    
    k8s = fields.Bool(required=True)    
    sonarqube = fields.Bool(required=True)
    rancher = fields.Bool(required=True)
    

class ServersAliveResSchema(Schema):
    alive = fields.Nested(ServersAliveResAliveSchema, required=True)
    all_alive = fields.Bool(required=True)

# All
class ServersAliveResponse(CommonBasicResponse):
    data = fields.Nested(ServersAliveResSchema, required=True)

# Each
class ServerAliveResponse(CommonBasicResponse):
    name = fields.Str(required=True)
    status = fields.Bool(required=True)


class HarborProxyResponse(ServerAliveResponse):
    remain_limit = fields.Int(required=True)


class HarborStorageResponse(ServerAliveResponse):
    total_size = fields.Str(required=True)
    used = fields.Str(required=True)
    avail = fields.Str(required=True)


class RancherDefaultNameResponse(Schema):
    default_cluster_name = fields.Bool(required=True)


class GithubTokenVerifyResDetailSchema(Schema):
    account = fields.Str(required=True)
    token = fields.Str(required=True)


class GithubTokenVerifyResSchema(Schema):
    alert_code = fields.Int(required=True)
    detail = fields.Nested(GithubTokenVerifyResDetailSchema, required=True)
    message = fields.Str(required=True)
    resource_type = fields.Str(required=True)


class GithubTokenVerifyResponse(CommonResponse):
    error = fields.Nested(GithubTokenVerifyResSchema)
