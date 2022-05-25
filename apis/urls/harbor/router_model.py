from marshmallow import Schema, fields


class CreateHarborScan(Schema):
    branch = fields.Str(required=True, description='Branch name', example="master")
    commit_id = fields.Str(required=True, description='commit short id',
                           example="d45736e4")


class HarborScanList(Schema):
    per_page = fields.Int(required=False, description='Branch name', example="master")
    page = fields.Int(required=False, description='commit short id', example="d45736e4")
