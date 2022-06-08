from marshmallow import Schema, fields


class CreateHarborScan(Schema):
    branch = fields.Str(required=True, description='Branch name', example="master")
    commit_id = fields.Str(required=True, description='Commit short id',
                           example="d45736e4")


class HarborScanList(Schema):
    per_page = fields.Int(required=False, description='Show how many items at one page', example="10")
    page = fields.Int(required=False, description='Page number', example="1")
