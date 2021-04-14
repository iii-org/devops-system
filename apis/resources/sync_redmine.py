import os
import model
import util
from resources.project import list_projects
from resources.user import user_list_by_project
from resources.issue import get_issue_by_project
from datetime import datetime
from decimal import Decimal, ROUND_HALF_UP
from flask_jwt_extended import jwt_required
from flask_restful import Resource


account = os.environ.get('ADMIN_INIT_LOGIN')


def round_off_float(num):
    if isinstance(num, float):
        num = str(num)
    return float(Decimal(num).quantize(Decimal('0.000'), rounding=ROUND_HALF_UP))

def calculate_expired_days(first, last):
    first_date= datetime.strptime(first, "%Y-%m-%d")
    last_date = datetime.strptime(last, "%Y-%m-%d")
    expired_days = (last_date - first_date).days
    return expired_days

def get_complete_percent(project):
    complete_percent = 0.0
    if project['closed_count'] and project['total_count']:
        complete_percent = round_off_float(project['closed_count']/project['total_count'])
    return complete_percent

def get_expired_days(project):
    if project['start_date'] != 'None' and project['due_date'] != 'None':
        return calculate_expired_days(project['start_date'], project['due_date'])
    else:
        return None

def check_overdue(last):
    if last != 'None':
        last_date = datetime.strptime(last, "%Y-%m-%d")
        if last_date < datetime.now():
            return True
        else:
            return False
    else:
        return None

def get_passing_rate(last_test_results):
    passing_rate = 0.0
    total = last_test_results.__dict__['total']
    fail = last_test_results.__dict__['fail']
    if total and fail:
        passing_rate = round_off_float(1-(fail/total))
    return passing_rate


def get_admin_user_id():
    user_detail = model.User.query.filter_by(login=account).first()
    return user_detail.id

def sync_redmine():
    sync_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    need_to_track_issue = []
    overdue_projects = []
    response = list_projects(user_id=get_admin_user_id())
    all_projects = response[0]['data']['project_list']
    for project in all_projects:
        member_count = insert_project_member(project['id'], project['name'])
        insert_project(project, member_count, sync_date)
        insert_project_member_count(project, member_count)
        if project['total_count']:
            need_to_track_issue.append(project['id'])
        if check_overdue(project['due_date']):
            overdue_projects.append(project['id'])
    insert_project_overview(len(all_projects), len(overdue_projects), len(need_to_track_issue))
    return need_to_track_issue

def insert_project(project, member_count, sync_date):
    new_project = model.RedmineProject(
        project_id = project['id'], 
        project_name = project['name'],
        pm_user_id = project['pm_user_id'],
        pm_user_name = project['pm_user_name'],
        complete_percent = get_complete_percent(project),
        closed_issue_count = project['closed_count'],
        unclosed_issue_count = project['total_count'] - project['closed_count'],
        total_issue_count = project['total_count'],
        member_count = member_count,
        expired_day = get_expired_days(project),
        start_date = project['start_date'] if project['start_date'] != 'None' else '1970-01-01', 
        end_date = project['due_date'] if project['due_date'] != 'None' else '1970-01-01',
        sync_date = sync_date
    )
    model.db.session.add(new_project)
    model.db.session.commit()

def insert_project_member_count(project, member_count):
    new_project_member = model.ProjectMemberCount(
        project_id = project['id'], 
        project_name = project['name'],
        member_count = member_count
    )
    model.db.session.add(new_project_member)
    model.db.session.commit()

def insert_project_overview(project_count, overdue_issue_count, need_to_track_issue_count):
    new_project_overview = model.ProjectOvewview(
        project_count = project_count,
        overdue_issue_count = overdue_issue_count, 
        no_started_issue_count = project_count - need_to_track_issue_count
    )
    model.db.session.add(new_project_overview)
    model.db.session.commit()

def insert_project_member(project_id, project_name):
    members_list = []
    response = user_list_by_project(project_id=project_id, args={'exclude': None})
    all_members = response[0]['data']['user_list']
    for member in all_members:
        new_member = model.ProjectMember(
            user_id = member['id'],
            user_name = member['name'],
            project_id = project_id,
            project_name = project_name,
            role_id = member['role_id'],
            role_name = member['role_name']
        )
        members_list.append(new_member)
    model.db.session.add_all(members_list)
    model.db.session.commit()
    return len(all_members)

def insert_all_issues(project_id):
    issues_list = []
    all_issues = get_issue_by_project(project_id=project_id, args=None)
    for issue in all_issues:
        new_issue = model.RedmineIssue(
            issue_id = issue['id'],
            project_id = issue['project_id'],
            project_name = issue['project_name'],
            assigned_to = issue['assigned_to'],
            assigned_to_id = issue['assigned_to_id'] if 'assigned_to_id' in issue else None,
            issue_type = issue['issue_category'],
            issue_name = issue['issue_name'],
            status_id = issue['issue_status_id'],
            is_closed = issue['is_closed'] if 'is_closed' in issue else None
        )
        issues_list.append(new_issue)
    model.db.session.add_all(issues_list)
    model.db.session.commit()

def insert_issue_rank():
    issues_list = []
    all_users = model.User.query.with_entities(model.User.id, model.User.name).all()
    for user in all_users:
        unclosed_issue_count = model.RedmineIssue.query.filter_by(assigned_to_id=user[0], is_closed=False).count()
        project_involve_count = model.ProjectMember.query.filter_by(user_id=user[0]).count()
        new_issue_rank = model.IssueRank(
            user_id = user[0],
            user_name = user[1],
            unclosed_count = unclosed_issue_count,
            project_count = project_involve_count
        )
        issues_list.append(new_issue_rank)
    model.db.session.add_all(issues_list)
    model.db.session.commit()

def clear_all_tables():
    model.RedmineIssue.query.delete()
    model.RedmineProject.query.delete()
    model.ProjectMember.query.delete()
    model.ProjectMemberCount.query.delete()
    model.ProjectOvewview.query.delete()
    model.IssueRank.query.delete()
    model.db.session.commit()

def get_project_member_count():
    query_collections = model.ProjectMemberCount.query.all()
    project_member_list = [
        {
            'id': context.__dict__['project_id'],
            'name': context.__dict__['project_name'],
            'value': context.__dict__['member_count']
        } for context in query_collections
    ]
    return project_member_list    

def get_project_overview():
    query_collections = model.ProjectOvewview.query.all()
    project_overview = [
        {
            'projects': context.__dict__['project_count'],
            'overdue': context.__dict__['overdue_issue_count'],
            'not_started': context.__dict__['no_started_issue_count']
        } for context in query_collections
    ]
    return project_overview 

def get_redmine_projects():
    query_collections = model.RedmineProject.query.all()
    redmine_projects = [
        {
            'project_id': context.__dict__['project_id'],
            'project_name': context.__dict__['project_name'],
            'pm_user_id': context.__dict__['pm_user_id'],
            'pm_user_name': context.__dict__['pm_user_name'],
            'complete_percent': context.__dict__['complete_percent'],
            'unclosed_issue_count': context.__dict__['unclosed_issue_count'],
            'closed_issue_count': context.__dict__['closed_issue_count'],
            'member_count': context.__dict__['member_count'],
            'expired_day': context.__dict__['expired_day'],
            'end_date': context.__dict__['end_date'].strftime("%Y-%m-%d"),
        } for context in query_collections
    ]
    return redmine_projects

def get_redmine_issue_rank():
    query_collections = model.IssueRank.query.order_by(model.IssueRank.project_count.desc()).limit(5).all()
    issue_rank = [
        {
            'user_id': context.__dict__['user_id'],
            'user_name': context.__dict__['user_name'],
            'unclosed_count': context.__dict__['unclosed_count'],
            'project_count': context.__dict__['project_count']
        } for context in query_collections
    ]
    return issue_rank 

def get_unclosed_issues_by_user(user_id):
    query_collections = model.RedmineIssue.query.filter_by(assigned_to_id=user_id, is_closed=False)
    unclosed_issues = [
        {
            'issue_id': context.__dict__['issue_id'],
            'project_id': context.__dict__['project_id'],
            'project_name': context.__dict__['project_name'],
            'assigned_to': context.__dict__['assigned_to'],
            'assigned_to_id': context.__dict__['assigned_to_id'],
            'issue_type': context.__dict__['issue_type'],
            'issue_name': context.__dict__['issue_name'],
            'status_id': context.__dict__['status_id'],
            'is_closed': context.__dict__['is_closed'],
        } for context in query_collections
    ]
    return unclosed_issues

def get_involved_project_by_user(user_id):
    project_member_collections = model.ProjectMember.query.filter_by(user_id=user_id)
    involed_projects_id = [context.__dict__['project_id'] for context in project_member_collections]
    project_collections = model.RedmineProject.query.filter(model.RedmineProject.project_id.in_(involed_projects_id)).all()
    redmine_projects = [
        {
            'project_id': context.__dict__['project_id'],
            'project_name': context.__dict__['project_name'],
            'pm_user_id': context.__dict__['pm_user_id'],
            'pm_user_name': context.__dict__['pm_user_name'],
            'complete_percent': context.__dict__['complete_percent'],
            'unclosed_issue_count': context.__dict__['unclosed_issue_count'],
            'closed_issue_count': context.__dict__['closed_issue_count'],
            'member_count': context.__dict__['member_count'],
            'expired_day': context.__dict__['expired_day'],
            'end_date': context.__dict__['end_date'].strftime("%Y-%m-%d"),
        } for context in project_collections
    ]
    return redmine_projects

def get_postman_passing_rate():
    all_passing_rate = []
    project_id_collections = model.TestResults.query.with_entities(model.TestResults.project_id).distinct()
    for project_id in project_id_collections:
        last_test_results = model.TestResults.query.filter(
            model.TestResults.run_at < datetime.today(), 
            model.TestResults.project_id==project_id[0]).order_by(model.TestResults.run_at.desc()).first()
        test_results_count = model.TestResults.query.filter(
            model.TestResults.run_at < datetime.today(), 
            model.TestResults.project_id==project_id[0]).count()
        passing_rate = get_passing_rate(last_test_results)
        test_results = {
            'project_id': project_id[0],
            'project_name': model.RedmineProject.query.filter_by(project_id=project_id[0]).first().project_name,
            'test_result_id': last_test_results.__dict__['id'],
            'passing_rate': passing_rate,
            'total': last_test_results.__dict__['total'] if last_test_results.__dict__['total'] else 0,
            'fail': last_test_results.__dict__['fail'] if last_test_results.__dict__['fail'] else 0,
            'run_at': last_test_results.__dict__['run_at'].strftime("%Y-%m-%d %H:%M:%S"),
            'count': test_results_count
        }
        all_passing_rate.append(test_results)
    return all_passing_rate

# --------------------- Resources ---------------------

class SyncRedmine(Resource):
    @jwt_required
    def get(self):
        clear_all_tables()
        need_to_track_issue = sync_redmine()
        for project_id in need_to_track_issue:
            insert_all_issues(project_id)
        insert_issue_rank()
        return util.success()


class ProjectMembers(Resource):
    @jwt_required
    def get(self):
        project_member_list = get_project_member_count()
        return util.success(project_member_list)


class ProjectOverview(Resource):
    @jwt_required
    def get(self):
        project_overview = get_project_overview()
        return util.success(project_overview)


class RedmineProjects(Resource):
    @jwt_required
    def get(self):
        redmine_projects = get_redmine_projects()
        return util.success(redmine_projects)


class RedmineIssueRank(Resource):
    @jwt_required
    def get(self):
        issue_rank = get_redmine_issue_rank()
        return util.success(issue_rank)


class UnclosedIssues(Resource):
    @jwt_required
    def get(self, user_id):
        unclosed_issues = get_unclosed_issues_by_user(user_id)
        return util.success(unclosed_issues)


class InvolvedProjects(Resource):
    @jwt_required
    def get(self, user_id):
        involed_projects = get_involved_project_by_user(user_id)
        return util.success(involed_projects)


class PassingRate(Resource):
    @jwt_required
    def get(self):
        passing_rate = get_postman_passing_rate()
        return util.success(passing_rate)