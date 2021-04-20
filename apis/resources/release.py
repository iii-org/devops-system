import json

import requests
from flask_jwt_extended import jwt_required, get_jwt_identity
from flask_restful import Resource, reqparse
from sqlalchemy.orm.exc import NoResultFound

import config
import model
import util as util
from resources import apiError, kubernetesClient, role
from resources.apiError import DevOpsError
from resources.logger import logger
from datetime import datetime
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

    def check_release_status(self, args, release_name, branch_name):
        issues_by_versions = redmine.rm_list_issues_by_versions_and_closed(self.plugin_relation.plan_project_id,
                                                                           args['versions'],
                                                                           self.closed_statuses)

        self.redmine_info = rm_release.check_redemine_release(
            issues_by_versions, self.versions_by_key, args['main'])
        self.harbor_info = hb_release.check_harbor_release(
            hb_release.get_list_artifacts(self.project.name, branch_name),
            release_name)
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

    def forced_close(self, release_name, branch_name):
        # Delete Gitlab Tags
        if 'gitlab' in self.valid_info['errors']:
            try:
                gitlab.gl_delete_tag(
                    self.plugin_relation.git_repository_id, release_name)
            except NoResultFound:
                return util.respond(404, error_gitlab_not_found,
                                    error=apiError.repository_id_not_found(self.plugin_relation.git_repository_id))
        # Delete Harbor Tags
        if 'harbor' in self.valid_info['errors']:
            try:
                hb_release.delete_harbor_tag(self.project.name, branch_name,
                                                           self.valid_info['errors']['harbor'])
            except NoResultFound:
                return util.respond(404, error_gitlab_not_found,
                                    error=apiError.repository_id_not_found(self.plugin_relation.git_repository_id))
        # Forced Closed Redmine Issues
        if 'redmine' in self.valid_info['errors']:
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

    @jwt_required
    def post(self, project_id):
        self.plugin_relation = model.ProjectPluginRelation.query.filter_by(
            project_id=project_id).first()
        self.project = model.Project.query.filter_by(id=project_id).first()
        parser = reqparse.RequestParser()
        parser.add_argument('main', type=int)
        parser.add_argument('versions', action='append')
        parser.add_argument('branch', type=str)
        parser.add_argument('description', type=str)
        parser.add_argument('released_at', type=str)
        parser.add_argument('forced', action='store_true')
        args = parser.parse_args()
        args['main'] = str(args['main'])
        list_versions = redmine.rm_get_version_list(
            self.plugin_relation.plan_project_id)
        self.versions_by_key = transfer_array_to_object(
            list_versions['versions'], 'id')
        branch_name = args['branch']
        release_name = self.versions_by_key[args['main']]['name']
        list_statuses = redmine.rm_get_issue_status()
        self.closed_statuses = redmine.get_closed_status(
            list_statuses['issue_statuses'])
        self.check_release_status(args, release_name, branch_name)

        # Verify Issues is all closed in versions
        self.check_release_states()

        if args['forced'] == 'True' and self.valid_info['check'] is False:
            self.forced_close(release_name, branch_name)
        elif self.valid_info['check'] is False:
            return util.respond(404, error_release_build,
                                error=apiError.release_unable_to_build(self.valid_info))
        try:
            gitlab_data = {
                'tag_name': release_name,
                'ref': branch_name,
                'description': args['description']
            }
            if args['released_at'] != "":
                gitlab_data['release_at'] = args['released_at']

            gitlab.gl_create_release(
                self.plugin_relation.git_repository_id, gitlab_data)
            for version in args['versions']:
                params = {"version": {"status": "closed"}}
                redmine.rm_put_version(version, params)
            hb_release.create(self.project.name, branch_name,
                              self.harbor_info['target']['digest'], release_name)
            return util.success()
        except NoResultFound:
            return util.respond(404, error_redmine_issues_closed,
                                error=apiError.redmine_unable_to_forced_closed_issues(args['versions']))


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
