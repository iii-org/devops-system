import json

import requests
from flask_jwt_extended import jwt_required, get_jwt_identity
from flask_restful import Resource, reqparse
from sqlalchemy.orm.exc import NoResultFound
from urllib.parse import urlparse

import config
import model
from model import db
import util as util
from resources import apiError, kubernetesClient, role
from resources.apiError import DevOpsError
from resources.logger import logger
from datetime import datetime, date
import nexus
from .issue import update_issue
from .gitlab import gitlab, gl_release
from .redmine import redmine, rm_release
from .harbor import hb_release

error_redmine_issues_closed = "Unable closed all issues"
error_issue_not_all_closed = "Not All Issues are closed in Versions"
error_harbor_no_image = "No such image found in harbor"
error_gitlab_not_found = 'No such repository found in database.'
error_release_build = 'Unable to build the release.'
version_info_keys = ['id', 'name', 'status']
release_info_keys = ['description', 'created_at', 'released_at']
key_return_json = ['versions', 'issues' ]

def row_to_dict(row):
    ret = {}
    if row is None:
        return row
    for key in type(row).__table__.columns.keys():
        value = getattr(row, key)
        if type(value) is datetime or type(value) is date:
            ret[key] = str(value)
        elif key in key_return_json and value is not None:
            ret[key] = json.loads(value)
        else:
            ret[key] = value    
    return ret


def transfer_array_to_object(targets, key):
    output = {}
    for target in targets:
        key_value = str(target[key])
        output[key_value] = target
    return output


def mapping_function_by_key(versions, releases):
    output = {}
    for key in versions:
        info = {}
        if key in releases:
            for version_key in version_info_keys:
                info[version_key] = versions[key][version_key]
            for release_keys in release_info_keys:
                info[release_keys] = releases[key][release_keys]
            output[key] = info
    return output


def get_mapping_list_info(versions, releases):
    output = {}
    rm_key_versions = {}
    gl_key_releases = {}
    rm_key_versions = transfer_array_to_object(versions, 'name')
    gl_key_releases = transfer_array_to_object(releases, 'tag_name')
    output = mapping_function_by_key(rm_key_versions, gl_key_releases)
    return list(output.values())


def create_release(project_id, args, versions, issues, branch_name, release_name, user_id):
    new = model.Release(
        project_id= project_id,
        version_id=args.get('main'),
        versions=json.dumps(versions),
        issues=json.dumps(issues),
        branch=branch_name,
        commit=args.get('commit'),
        tag_name=release_name,
        note=args.get('note'),
        creator_id=user_id,
        create_at=str(datetime.now())
    )
    db.session.add(new)
    db.session.commit()




def get_releases_by_project_id(project_id):
    project = model.Project.query.filter_by(id=project_id).first()
    releases = model.Release.query.\
        filter(model.Release.project_id == project_id).\
        all()
    output = []
    gitlab_base = f'{config.get("GITLAB_BASE_URL")}/root'
    harbor_base = f'docker pull {urlparse(config.get("HARBOR_EXTERNAL_BASE_URL")).netloc}'
    for release in releases:
        if releases is not None:
            ret = row_to_dict(release)
            ret['git_url'] = f'{gitlab_base}/{project.name}/-/releases/{ret.get("tag_name")}' 
            ret['docker'] = f'{harbor_base}/{project.name}/{ret.get("branch")}:{ret.get("tag_name")}' 
            output.append(ret)
    return output


class Releases(Resource):
    def __init__(self):
        self.plugin_relation = None
        self.project = None
        self.versions = None
        self.harbor_info = None
        self.gitlab_info = None
        self.redmine_info = None
        self.versions_by_key = None
        self.closed_statuses = None
        self.valid_info = None

    def check_release_status(self, args, release_name, branch_name, commit):
        issues_by_versions = redmine.rm_list_issues_by_versions_and_closed(self.plugin_relation.plan_project_id,
                                                                           args['versions'],
                                                                           self.closed_statuses)
        self.redmine_info = rm_release.check_redemine_release(
            issues_by_versions, self.versions_by_key, args['main'])
        self.harbor_info = hb_release.check_harbor_release(
            hb_release.get_list_artifacts(self.project.name, branch_name),
            release_name, commit)
        self.gitlab_info = gl_release.check_gitlab_release(
            self.plugin_relation.git_repository_id, release_name)

    def check_release_states(self):
        checklist = {'redmine': self.redmine_info,
                     'gitlab': self.gitlab_info, 'harbor': self.harbor_info}
        output = {'check': True, "items": [],
                  'messages': [], 'errors': {}, 'targets': {}}
        for key in checklist:
            if checklist[key]['check'] is False:
                output['check'] = False
                output['items'].append(key)
                output['messages'].append(checklist[key]['info'])
                if 'errors' in checklist[key]:
                    output['errors'][key] = checklist[key]['errors']
                if 'target' in checklist[key]:
                    output['targets'][key] = checklist[key]['target']
        self.valid_info = output

    def delete_gitlab_tag(self, release_name):
        try:
            gitlab.gl_delete_tag(
                self.plugin_relation.git_repository_id, release_name)
        except NoResultFound:
            return util.respond(404, error_gitlab_not_found,
                                error=apiError.repository_id_not_found(self.plugin_relation.git_repository_id))

    def delete_harbor_tag(self, branch_name):
        try:
            tag_artifact = self.valid_info['targets']['harbor'].get(
                'duplicate', None)
            if tag_artifact is not None:
                hb_release.delete_harbor_tag(self.project.name, branch_name,
                                             tag_artifact)
        except NoResultFound:
            return util.respond(404, error_harbor_no_image,
                                error=apiError.release_unable_to_build(self.plugin_relation.git_repository_id))

    def closed_issues(self):
        try:
            issue_ids = []
            user_id = get_jwt_identity()['user_id']
            operator_plugin_relation = nexus.nx_get_user_plugin_relation(
                user_id=user_id)
            plan_operator_id = operator_plugin_relation.plan_user_id
            for issue in self.redmine_info['issues']:
                if int(issue['status']['id']) not in self.closed_statuses:
                    data = {
                        'status_id': self.closed_statuses[0]
                    }
                    issue_ids.append(issue['id'])
                    redmine.rm_update_issue(
                        issue['id'], data, plan_operator_id)
        except NoResultFound:
            return util.respond(404, error_redmine_issues_closed,
                                error=apiError.redmine_unable_to_forced_closed_issues(issue_ids))

    def forced_close(self, release_name, branch_name):
        # Delete Gitlab Tags
        if 'gitlab' in self.valid_info['errors']:
            self.delete_gitlab_tag(release_name)
        # Delete Harbor Tags
        if self.valid_info['targets'].get('harbor', None) is not None:
            self.delete_harbor_tag(branch_name)

        # Forced Closed Redmine Issues
        if 'redmine' in self.valid_info['errors']:
            self.closed_issues()

    @jwt_required
    def get(self, project_id):
        plugin_relation = model.ProjectPluginRelation.query.filter_by(
            project_id=project_id).first()
        try:
            rm_list_versions = redmine.rm_get_version_list(
                plugin_relation.plan_project_id)
        except NoResultFound:
            return util.respond(404, error_gitlab_not_found,
                                error=apiError.redmine_project_not_found(plugin_relation.plan_project_id))
        try:
            gl_list_releases = gitlab.gl_list_releases(
                plugin_relation.git_repository_id),
        except NoResultFound:
            return util.respond(404, error_gitlab_not_found,
                                error=apiError.repository_id_not_found(plugin_relation.git_repository_id))
        list_versions = rm_list_versions['versions']
        list_releases = gl_list_releases[0]
        return util.success(get_mapping_list_info(list_versions, list_releases))

    def get_redmine_issue(self):
        issue_ids = []
        issues = self.redmine_info.get('issues', None)
        if issues is not None:
            for issue in issues:
                issue_ids.append(issue['id'])
        return issue_ids

    def get_redmine_versions(self):
        version_ids = []
        versions = self.redmine_info.get('versions', None)
        if len(versions) > 0:
            for version in versions:
                version_ids.append(version)
        return version_ids

    @jwt_required
    def post(self, project_id):
        user_id = get_jwt_identity()["user_id"]
        role.require_in_project(project_id, 'Error to create release')
        self.plugin_relation = model.ProjectPluginRelation.query.filter_by(
            project_id=project_id).first()
        self.project = model.Project.query.filter_by(id=project_id).first()
        parser = reqparse.RequestParser()
        parser.add_argument('main', type=int)
        parser.add_argument('versions', action='append')
        parser.add_argument('branch', type=str)
        parser.add_argument('commit', type=str)
        parser.add_argument('note', type=str)
        parser.add_argument('released_at', type=str)
        parser.add_argument('forced', action='store_true')
        args = parser.parse_args()
        gitlab_ref = branch_name = args.get('branch')
        if args.get('commit', None) is None:
            args.update({'commit': 'latest'})
        else:
            gitlab_ref = args.get('commit')
            # args.set('commit', 'latest')
        args['main'] = str(args.get('main'))
        list_versions = redmine.rm_get_version_list(
            self.plugin_relation.plan_project_id)
        self.versions_by_key = transfer_array_to_object(
            list_versions['versions'], 'id')

        release_name = self.versions_by_key[args['main']]['name']
        list_statuses = redmine.rm_get_issue_status()
        self.closed_statuses = redmine.get_closed_status(
            list_statuses['issue_statuses'])

        self.check_release_status(
            args, release_name, branch_name, args.get('commit'))
        # Verify Issues is all closed in versions
        self.check_release_states()
        try:

            if args['forced'] == 'True' and self.valid_info['check'] is False:
                self.forced_close(release_name, branch_name)
            elif self.valid_info['check'] is False:
                return util.respond(404, error_release_build,
                                    error=apiError.release_unable_to_build(self.valid_info))

            #  Close Redmine Versions
            for version in args['versions']:
                params = {"version": {"status": "closed"}}
                redmine.rm_put_version(version, params)

            gitlab_data = {
                'tag_name': release_name,
                'ref': gitlab_ref,
                'description': args['note']
            }
            #  Create Gitlab Release
            if args['released_at'] != "":
                gitlab_data['release_at'] = args['released_at']

            gitlab.gl_create_release(
                self.plugin_relation.git_repository_id, gitlab_data)

            #  Create Harbor Release
            if self.harbor_info['target'].get('release', None) is not None:
                hb_release.create(self.project.name, branch_name,
                                  self.harbor_info['target']['release']['digest'], release_name)

            create_release(
                project_id, 
                args, 
                self.get_redmine_versions(), 
                self.get_redmine_issue(), 
                branch_name, 
                release_name, 
                user_id
            )                        
            return util.success()
        except NoResultFound:
            return util.respond(404, error_redmine_issues_closed,
                                error=apiError.redmine_unable_to_forced_closed_issues(args['versions']))

    @jwt_required
    def get(self, project_id):
        self.plugin_relation = model.ProjectPluginRelation.query.filter_by(
            project_id=project_id).first()
        role.require_in_project(project_id, 'Error to get release')
        try:
            return util.success({'plugin_list': get_releases_by_project_id(project_id)})
        except NoResultFound:
            return util.respond(404, error_redmine_issues_closed)


class Release(Resource):
    @jwt_required
    def get(self, project_id, release_name):
        plugin_relation = model.ProjectPluginRelation.query.filter_by(
            project_id=project_id).first()
        try:
            gl_release = gitlab.gl_get_release(
                plugin_relation.git_repository_id, release_name)
            rm_list_versions = redmine.rm_get_version_list(
                plugin_relation.plan_project_id),
            rm_key_versions = transfer_array_to_object(
                rm_list_versions[0]['versions'], 'name')
            if release_name not in rm_key_versions:
                return util.success({})
            return util.success({'gitlab': gl_release, 'redmine': rm_key_versions[release_name]})
        except NoResultFound:
            return util.respond(404, error_gitlab_not_found,
                                error=apiError.repository_id_not_found(plugin_relation.git_repository_id))
