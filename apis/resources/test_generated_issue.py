import json

import model
from resources import issue


def tgi_feed_postman(row):
    collections = json.loads(row.report).get('json_file')
    for col_key, result in enumerate(collections):
        assertions = result.get('assertions')
        if assertions.get('failed') > 0:
            relation_row = model.IssueCollectionRelation.query.filter_by(
                software_name='postman',
                file_name=col_key
            ).first()
            if relation_row is None:
                args = {
                    'project_id': row.project_id,
                    'tracker_id': 1,
                    'status_id': 1,
                    'priority_id': 1,
                    'subject': f'Postman Test Error in {col_key}',
                    'description': f'{col_key}: Failed {assertions.get("failed")}, Total {assertions.get("total")}'
                }
                tgi_create_issue(args)


def tgi_create_issue(args):
    rm_output = issue.create_issue(args, None)
    issue_id = rm_output.get('issue').get('id')

