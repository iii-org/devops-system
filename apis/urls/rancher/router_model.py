from marshmallow import Schema, fields



class CheckPipelineSchema(Schema):
    commit_id = fields.Str(required=True)
    repo_name = fields.Str(required=True)
    branch = fields.Str(required=True)
