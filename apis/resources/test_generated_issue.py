import json
from datetime import datetime

from dateutil.tz import tz
from redminelib.exceptions import ResourceNotFoundError

import model
import nexus
from accessories import redmine_lib
from resources import issue
from resources.logger import logger


TGI_TRACKER_ID = 9


def tgi_feed_postman(row):
    collections = json.loads(row.report).get('json_file')
    for col_key, result in collections.items():
        assertions = result.get('assertions')
        if assertions.get('failed') > 0:
            _handle_test_failed(row.project_id, 'postman',
                                col_key, _get_postman_issue_description(row),
                                row.branch, row.commit_id, 'test_results', row.id)
        else:
            _handle_test_success(row.project_id, 'postman',
                                 col_key, _get_postman_issue_close_description(row))


def tgi_feed_sideex(row):
    project_id = nexus.nx_get_project(name=row.project_name).id
    logger.debug(f'Sideex result is {row.result}')
    suites = json.loads(row.result).get('suites')
    for col_key, result in suites.items():
        total = result.get('total')
        passed = result.get('passed')
        if total - passed > 0:
            _handle_test_failed(project_id, 'sideex',
                                col_key, _get_sideex_issue_description(row, total, passed),
                                row.branch, row.commit_id, 'test_results', row.id)
        else:
            _handle_test_success(project_id, 'sideex',
                                 col_key, _get_sideex_issue_close_description(row, total, passed))


def _handle_test_failed(project_id, software_name, filename, description,
                        branch, commit_id, result_table, result_id):
    project_name = nexus.nx_get_project(id=project_id).name
    relation_row = model.TestGeneratedIssue.query.filter_by(
        project_id=project_id,
        software_name=software_name,
        file_name=filename
    ).first()
    # First check if issue exists
    iss = None
    if relation_row is None:
        issue_exists = False
    else:
        issue_id = relation_row.issue_id
        try:
            iss = redmine_lib.redmine.issue.get(issue_id, include=['journals'])
            issue_exists = True
        except ResourceNotFoundError:
            model.db.session.delete(relation_row)
            model.db.session.commit()
            issue_exists = False

    if not issue_exists:
        description = f'詳細報告請前往[測試報告列表](/#/scan/sideex)\n\n{description}'
        args = {
            'project_id': project_id,
            'tracker_id': TGI_TRACKER_ID,
            'status_id': 1,
            'priority_id': 3,
            'subject': _get_issue_subject(filename, software_name),
            'description': description
        }
        tgi_create_issue(args, software_name, filename,
                         branch, commit_id, result_table, result_id)
    else:
        # Check if is closed by human
        for j in reversed(iss.journals):
            detail = j.details[0]
            if (detail.get('name', '') == 'status_id' and detail.get('new_value', '-1') == '6'
                    and j.user.id != 1):  # User id 1 means Redmine admin == system operation
                # Do nothing
                return
        # Check if is previously closed (by the system). If so, reopen it.
        if iss.status.id == 6:
            iss.status_id = 1
        desc = iss.description
        iss.description = desc + '\n' + description
        iss.save()


SOFTWARE_ISSUE_TITLE = {
    'sideex': 'SideeX',
    'postman': 'Postman',
    'zap': 'Zap',
    'webinspect': 'WebInspect',
    'sonarqube': 'SonarQube',
    'checkmarx': 'CheckMarx'
}


def _get_issue_subject(filename, software_name):
    if software_name == 'postman':
        if filename == '':
            full_filename = 'postman_collection'
        else:
            full_filename = f'{filename}.postman_collection'
        return f'[{SOFTWARE_ISSUE_TITLE[software_name]}] Script: {full_filename}_測試失敗'
    else:
        return f'[{SOFTWARE_ISSUE_TITLE[software_name]}] Script: {filename}_測試失敗'


def _handle_test_success(project_id, software_name, filename, description):
    relation_row = model.TestGeneratedIssue.query.filter_by(
        project_id=project_id,
        software_name=software_name,
        file_name=filename
    ).first()
    if relation_row is None:
        # No fail issue, nothing to do
        return
    issue_id = relation_row.issue_id
    try:
        iss = redmine_lib.redmine.issue.get(issue_id)
    except ResourceNotFoundError:
        # Issue is deleted, nothing to do
        return
    if iss.status.id == 6:
        # Already closed, nothing to do
        return
    iss.status_id = 6
    desc = iss.description
    iss.description = desc + '\n' + description
    iss.save()


def tgi_create_issue(args, software_name, file_name, branch, commit_id, result_table, result_id):
    rm_output = issue.create_issue(args, None)
    issue_id = rm_output.get('id')
    new = model.TestGeneratedIssue(
        project_id=args['project_id'],
        issue_id=issue_id,
        software_name=software_name,
        file_name=file_name,
        branch=branch,
        commit_id=commit_id,
        result_table=result_table,
        result_id=result_id
    )
    model.db.session.add(new)
    model.db.session.commit()
    return new


def _cst_now_string():
    return (datetime.utcnow().replace(tzinfo=tz.tzutc()).astimezone(
        tz.gettz('Asia/Taipei'))).strftime("%Y-%m-%d %H:%M:%S")


def _get_postman_issue_description(row):
    return f'{_cst_now_string()} {row.branch} #{row.commit_id} 自動化測試失敗 ({row.total - row.fail}/{row.total})'


def _get_postman_issue_close_description(row):
    return f'{_cst_now_string()} {row.branch} #{row.commit_id} 自動化測試成功 ({row.total})'


def _get_sideex_issue_description(row, total, passed):
    return f'{_cst_now_string()} {row.branch} #{row.commit_id} 自動化測試失敗 ({passed}/{total})'


def _get_sideex_issue_close_description(row, total, passed):
    return f'{_cst_now_string()} {row.branch} #{row.commit_id} 自動化測試成功 ({total})'
