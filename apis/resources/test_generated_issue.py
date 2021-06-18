import json

import model
from resources import issue


def tgi_feed_postman(row):
    collections = json.loads(row.report).get('json_file')
    for col_key, result in collections.items():
        assertions = result.get('assertions')
        if assertions.get('failed') > 0:
            _create_or_update_issue(row.project_id, 'postman',
                                    col_key, _get_postman_issue_description(row))


def _create_or_update_issue(project_id, software_name, filename, description):
    relation_row = model.IssueCollectionRelation.query.filter_by(
        software_name='postman',
        file_name=filename
    ).first()
    if relation_row is None:
        args = {
            'project_id': project_id,
            'tracker_id': 9,
            'status_id': 1,
            'priority_id': 1,
            'subject': f'{filename}__測試失敗',
            'description': description
        }
        relation_row = tgi_create_issue(args, software_name, filename)
    else:
        issue_id = relation_row.issue_id
        iss = issue.get_issue(issue_id=issue_id, with_children=False)
        print(iss)
        desc = iss.get('description')
        args = {
            'description': desc + '\n' + description
        }
        issue.update_issue(issue_id, args, None)


def tgi_create_issue(args, software_name, file_name):
    rm_output = issue.create_issue(args, None)
    issue_id = rm_output.get('issue').get('id')
    new = model.IssueCollectionRelation(
        project_id=args['project_id'],
        issue_id=issue_id,
        software_name=software_name,
        file_name=file_name
    )
    model.db.session.add(new)
    model.db.session.commit()
    return new


def _get_postman_issue_description(row):
    return f'{row.branch} #{row.commit_id} Postman 自動化測試失敗 ({row.total - row.fail}/{row.total})'
