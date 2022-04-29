import json
from datetime import datetime, date, timedelta
from urllib.parse import urlparse

from flask_jwt_extended import jwt_required, get_jwt_identity
from flask_restful import Resource, reqparse
from sqlalchemy.orm.exc import NoResultFound
from resources.harbor import hb_list_artifacts_with_params, hb_copy_artifact_and_retage, hb_get_artifact, \
    hb_delete_artifact_tag, hb_create_artifact_tag, hb_list_tags, hb_copy_artifact, hb_list_repositories, \
    hb_list_tags, hb_delete_artifact, hb_list_artifacts

import config
import model
import nexus
import util as util
from model import db
from resources import apiError, role
from .gitlab import gitlab, gl_release
from .harbor import hb_release
from .redmine import redmine, rm_release

error_redmine_issues_closed = "Unable closed all issues"
error_issue_not_all_closed = "Not All Issues are closed in Versions"
error_harbor_no_image = "No such image found in harbor"
error_gitlab_not_found = 'No such repository found in database.'
error_release_build = 'Unable to build the release.'
version_info_keys = ['id', 'name', 'status']
release_info_keys = ['description', 'created_at', 'released_at']
key_return_json = ['versions', 'issues']


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


def create_release(project_id, args, versions, issues, branch_name, release_name, user_id, image_path):
    new = model.Release(
        project_id=project_id,
        version_id=args.get('main'),
        versions=json.dumps(versions),
        issues=json.dumps(issues),
        branch=branch_name,
        commit=args.get('commit'),
        tag_name=release_name,
        note=args.get('note'),
        creator_id=user_id,
        create_at=str(datetime.now()),
        image_paths=image_path
    )
    db.session.add(new)
    db.session.commit()


def get_hb_tags(artifacts):
    output = []
    for artifact in artifacts:
        output.append(artifact.get('name'))
    return output


def get_hb_branch_tags(project_name, branch_name):
    output = []
    artifacts = hb_release.get_list_artifacts(project_name, branch_name)
    for artifact in artifacts:
        output.append(artifact.get('name'))
    return output


def get_gitlab_base(url):
    return url[:-4]


def analysis_release(release, info, hb_list_tags, image_need):
    ret = row_to_dict(release)
    ret['docker'] = []
    gitlab_project_url = info.get('gitlab_project_url')
    # harbor_base = info.get('harbor_base')
    project_name = info.get('project_name')
    if ret.get('branch') is not None and ret.get('commit') is not None:
        ret['git_url'] = f'{gitlab_project_url}/-/releases/{ret.get("tag_name")}'
        image_paths = ret.pop("image_paths") if ret.get("image_paths") is not None else []
        main_release_path = f'{project_name}/{ret["branch"]}:{ret["tag_name"]}'
        main_path_index = image_paths.index(main_release_path) if main_release_path in image_paths else len(image_paths)
        
        temp_repo_mapping = {}
        temp_tag_mapping = {}
        for image_path in image_paths:
            split_image_path = image_path.split(":")
            tag = split_image_path[-1]
            branch = split_image_path[0].split("/")[-1]
            # check harbor image exists
            if tag in get_hb_branch_tags(project_name, branch):
                if tag == release.tag_name:
                    # Put the main tag in the first of the list.
                    temp_repo_mapping.setdefault(branch, []).insert(0, tag)
                else:
                    temp_repo_mapping.setdefault(branch, []).append(tag)
            
            # Filter out same brach:tag and add by create_repo
            if image_paths.index(image_path) < main_path_index:
                temp_tag_mapping.setdefault(tag, []).append(image_path)

        # Generate field: "image_tags"
        ret["image_tags"] = [{tag: data} for tag, data in temp_tag_mapping.items()]
        ret["docker"] = [{
            "repo": repo,
            "tags": tags,
            "default": repo == ret["branch"]
        } for repo, tags in temp_repo_mapping.items()]
        ret["harbor_external_base_url"] = config.get("HARBOR_EXTERNAL_BASE_URL")

    if image_need and ret.get('docker') == []:
        ret = None

    return ret, hb_list_tags


def get_releases_by_project_id(project_id, args):
    project = model.Project.query.filter_by(id=project_id).first()
    releases = model.Release.query. \
        filter(model.Release.project_id == project_id). \
        all()
    output = []
    info = {
        'project_name': project.name,
        'gitlab_project_url': f'{project.http_url[:-4]}',
    }
    hb_list_tags = {}
    for release in releases:
        if releases is not None:
            ret, hb_list_tags = analysis_release(release, info, hb_list_tags, args.get('image', False))
            if ret is not None:
                output.append(ret)
    return output


def get_release_image_list(project_id, args):
    from resources.gitlab import get_project_plugin_object
    project_name = model.Project.query.filter_by(id=project_id).first().name
    branch_name = args["branch_name"]
    not_all = args.get("not_all", "false") == "true" 
    only_image = args.get("only_image", "false") == "true" 

    releases = model.Release.query.filter_by(project_id=project_id).all()
    release_tag_mapping = {release.commit: release.tag_name for release in releases}

    last_push_time = None
    if not_all:
        if releases != []:
            last_push_time = releases[-1].create_at

    image_list = hb_list_artifacts_with_params(project_name, branch_name, push_time=last_push_time)
    commits = gitlab.gl_get_commits(get_project_plugin_object(project_id).git_repository_id,
                                        branch_name, per_page=3000, since=last_push_time)
    if only_image:
        commit_images = {commit["short_id"][:-1]: commit["title"] for commit in commits}
        ret = [{
            "image": image["digest"], 
            "push_time": image["push_time"][:-5],
            "commit_id": image["name"],
            "commit_message": commit_images[image["name"]],
            "tag": release_tag_mapping.get(image["name"])
        } for image in image_list if image["name"] in commit_images]
        total_count = len(ret)
        ret = ret[args["offset"]: args["offset"]+ args["limit"]]
    else:
        image_mapping = {image["name"]: image for image in image_list}
        total_count = len(commits)
        ret = []
        for commit in commits[args["offset"]: args["offset"]+ args["limit"]]:
            short_commit = commit["short_id"][:-1]
            image = image_mapping.get(short_commit)
            data = {
                "image": image["digest"] if image is not None else None,
                "push_time": image["push_time"][:-5] if image is not None else handle_gitlab_datetime(commit["created_at"]),
                "commit_id": commit["short_id"][:-1],
                "commit_message": commit["title"],
                "tag": release_tag_mapping.get(short_commit)
            }
            ret.append(data)


    page_dict = util.get_pagination(total_count, args['limit'], args["offset"])
    output = {"image_list": ret, "page": page_dict}
    return output

def handle_gitlab_datetime(create_time):
    datetime_obj = datetime.strptime(create_time, "%Y-%m-%dT%H:%M:%S.%f%z") - timedelta(hours=8)
    return datetime_obj.strftime("%Y-%m-%dT%H:%M:%S")

def get_distinct_image_path(release_obj):
    ret = []
    for image_path in release_obj.image_paths:
        distinct_image_path = image_path.split(":")[0] 
        if distinct_image_path not in ret:
            ret.append(distinct_image_path)
    return ret


def create_release_image_repo(project_id, release_id, args):
    project_name = model.Project.query.filter_by(id=project_id).first().name
    release = model.Release.query.filter_by(id=release_id).first()
    if release is not None:
        dest_image_path = args["image_path"]
        temp = dest_image_path.split(":")
        dest_repo, dest_tag = temp[0], temp[1]
        before_image_path = release.image_paths
        repo_list = [hb_repo["name"].split("/")[-1] for hb_repo in hb_list_repositories(project_name)]
        if f"{project_name}/{dest_image_path}" not in before_image_path:
            # Put it in the end of list in order to easily filter it out in get releases API.
            release.image_paths = before_image_path + [f"{project_name}/{dest_image_path}"]
            db.session.commit()
            digest = hb_get_artifact(project_name, release.branch, release.tag_name)[0]["digest"]
            
            try:
                copy_image = add_tag = False
                if dest_repo not in repo_list or hb_list_artifacts(project_name, dest_repo) == []:
                    hb_copy_artifact(project_name, dest_repo, f"{project_name}/{release.branch}@{digest}")
                    copy_image = True
                    for removed_tag in [hb_tag.get("name") for hb_tag in hb_list_tags(project_name, release.branch, digest) if hb_tag.get("name") is not None]:
                        hb_delete_artifact_tag(project_name, dest_repo, digest, removed_tag, keep=True)
                hb_create_artifact_tag(project_name, dest_repo, digest, dest_tag)
                add_tag = True
                return util.success()
            except Exception as e:
                release.image_paths = before_image_path
                db.session.commit()
                if copy_image:
                    hb_delete_artifact(project_name, dest_repo, digest)
                elif add_tag:
                    hb_delete_artifact_tag(project_name, dest_repo, digest, dest_tag)
                return util.respond(500, str(e))

                
def delete_release_image_repo(project_id, release_id, args):
    project_name = model.Project.query.filter_by(id=project_id).first().name
    release = model.Release.query.filter_by(id=release_id).first()
    removed_repo_name = args["repo_name"]
    if release is not None and removed_repo_name != release.branch: 
        before_image_paths = release.image_paths
        after_image_paths = []
        delete_tags = []
        for image_path in before_image_paths:
            temp = image_path.split("/")[-1].split(":")
            repo_name, tag = temp[0], temp[1]
            if repo_name == removed_repo_name:
                delete_tags.append(tag)
            else:
                after_image_paths.append(image_path)
        digest = hb_get_artifact(project_name, release.branch, release.tag_name)[0]["digest"]
        release.image_paths = after_image_paths
        db.session.commit()
        try:
            hb_delete_artifact(project_name, removed_repo_name, digest)
            return util.success()
        except Exception as e:
            release.image_paths = before_image_paths
            db.session.commit()
            return util.respond(500, str(e))


def create_release_image_tag(project_id, release_id, args):
    project_name = model.Project.query.filter_by(id=project_id).first().name
    release = model.Release.query.filter_by(id=release_id).first()
    if release is not None:
        dest_tags = args["tags"]
        distinct_image_paths = get_distinct_image_path(release)
        before_image_path = release.image_paths

        # Must to update DB first, otherwise the value won't change.
        added_image_paths = [f"{distinct_image_path}:{dest_tags}" for 
            distinct_image_path in distinct_image_paths 
            if f"{distinct_image_path}:{dest_tags}" not in release.image_paths]
        # added_image_paths = list(map(lambda x: f"{x}:{dest_tags}", distinct_image_paths))

        if before_image_path is not None:
            added_image_paths += before_image_path

        release.image_paths = added_image_paths
        db.session.commit()

        # Then add tag on all image_path
        digest = hb_get_artifact(project_name, release.branch, release.tag_name)[0]["digest"]
        try:
            release_image_tag_helper(
                project_name, distinct_image_paths, dest_tags, digest)
            return util.success()
        except Exception as e:
            release.image_paths = before_image_path
            db.session.commit()
            release_image_tag_helper(
                project_name, distinct_image_paths, dest_tags, digest, delete=True)
            return util.respond(500, str(e))


def delete_release_image_tag(project_id, release_id, args):
    project_name = model.Project.query.filter_by(id=project_id).first().name
    release = model.Release.query.filter_by(id=release_id).first()
    if release is not None:
        dest_tags = args["tags"]
        before_image_paths = release.image_paths
        if dest_tags == release.tag_name:
            return
        distinct_image_paths = get_distinct_image_path(release)

        # Must to update DB first, otherwise the value won't change.
        updated_release_images = [
            image_path for image_path in before_image_paths if not image_path.endswith(dest_tags)]
        release.image_paths = updated_release_images
        db.session.commit()

        # Then add tag on all image_path
        digest =  hb_get_artifact(project_name, release.branch, release.tag_name)[0]["digest"]
        try:
            release_image_tag_helper(
                project_name, distinct_image_paths, dest_tags, digest, delete=True)
            return util.success()
        except Exception as e:
            release.image_paths = before_image_paths
            db.session.commit()
            release_image_tag_helper(
                project_name, distinct_image_paths, dest_tags, digest)
            return util.respond(500, str(e))


def release_image_tag_helper(project_name, distinct_image_paths, dest_tags, digest, delete=False):
    for distinct_image_path in distinct_image_paths:
        repo_name = distinct_image_path.split("/")[1]
        if not delete:
            if dest_tags not in [tag.get("name", "") for tag in hb_list_tags(project_name, repo_name, digest)]:  
                hb_create_artifact_tag(project_name, repo_name, digest, dest_tags)
        else:
            if dest_tags in [tag.get("name", "") for tag in hb_list_tags(project_name, repo_name, digest)]:  
                hb_delete_artifact_tag(project_name, repo_name, digest, dest_tags)


class Releases(Resource):
    def __init__(self):
        self.plugin_relation = None
        self.project = None
        self.versions = None
        self.harbor_info = {'check': False, 'tag': False, 'image': False,
                            "info": "", "target": {}, "errors": {}, "type": 2}
        self.gitlab_info = {'check': False, "info": "", "errors": {}}
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
        if branch_name is not None:
            self.harbor_info = hb_release.check_harbor_release(
                hb_release.get_list_artifacts(self.project.name, branch_name),
                release_name, commit)
        if release_name is not None:
            self.gitlab_info = gl_release.check_gitlab_release(
                self.plugin_relation.git_repository_id, release_name, branch_name, commit)

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
            if self.valid_info['errors']['gitlab'] != "":
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
        issue_ids = []
        try:
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
        parser.add_argument('extra_image_path', type=str)
        args = parser.parse_args()
        gitlab_ref = branch_name = args.get('branch')
        branch_name = None if branch_name == "" else branch_name
        if args.get('commit', None) is None and branch_name is not None:
            args.update({'commit': 'latest'})
        else:
            gitlab_ref = args.get('commit')
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
            # Close Redmine Versions
            closed_version = False
            for version in args['versions']:
                params = {"version": {"status": "closed"}}
                redmine.rm_put_version(version, params)
                closed_version = True
            # check  Gitalb Release
            check_gitlab_release = False
            # if self.gitlab_info.get('check') == True:
            gitlab_data = {
                'tag_name': release_name,
                'ref': gitlab_ref,
                'description': args['note']
            }
            if args['released_at'] != "":
                gitlab_data['release_at'] = args['released_at']
            gitlab.gl_create_release(
                self.plugin_relation.git_repository_id, gitlab_data)
            check_gitlab_release = True
            #  Create Harbor Release
            create_harbor_release = False
            image_path = [f"{self.project.name}/{branch_name}:{release_name}"]
            if self.harbor_info['target'].get('release', None) is not None:
                if args.get("extra_image_path") is not None and f"{self.project.name}/{args.get('extra_image_path')}" not in image_path: 
                    image_path = [f"{self.project.name}/{args.get('extra_image_path')}"] + image_path
                    extra_image_path = args.get("extra_image_path").split(":")
                    extra_dest_repo, extra_dest_tag = extra_image_path[0], extra_image_path[1]
                    hb_copy_artifact_and_retage(self.project.name, branch_name, extra_dest_repo, args.get("commit"), extra_dest_tag)
                hb_copy_artifact_and_retage(self.project.name, branch_name, branch_name, args.get("commit"), release_name)
                create_harbor_release = True

            create_release(
                project_id,
                args,
                self.get_redmine_versions(),
                self.get_redmine_issue(),
                branch_name,
                release_name,
                user_id,
                image_path
            )

            return util.success()
        except:
            # Roll back
            ## Open redmine version
            if closed_version:
                for version in args['versions']:
                    params = {"version": {"status": "open"}}
                    redmine.rm_put_version(version, params)

            ## check  Gitalb Release
            if check_gitlab_release:
                gitlab.gl_delete_release(
                    self.plugin_relation.git_repository_id, release_name)
            
            ## Create Harbor Release
            if create_harbor_release:
                for image in image_path:
                    removed_image_path = image.split("/")[-1].split(":")
                    removed_dest_repo, removed_dest_tag = removed_image_path[0], removed_image_path[1]
                    if removed_dest_repo != branch_name:
                        hb_copy_artifact_and_retage(self.project.name, removed_dest_repo, branch_name, removed_dest_tag, args.get("commit"))
                    else:
                        digest = hb_get_artifact(self.project.name, branch_name, removed_dest_tag)[0]["digest"]
                        hb_delete_artifact_tag(self.project.name, branch_name, digest, removed_dest_tag, keep=True)

            if NoResultFound:
                return util.respond(404, error_redmine_issues_closed,
                                    error=apiError.redmine_unable_to_forced_closed_issues(args['versions']))

    @jwt_required
    def get(self, project_id):
        self.plugin_relation = model.ProjectPluginRelation.query.filter_by(
            project_id=project_id).first()
        role.require_in_project(project_id, 'Error to get release')
        try:
            parser = reqparse.RequestParser()
            parser.add_argument('image', type=bool)
            args = parser.parse_args()
            return util.success({'releases': get_releases_by_project_id(project_id, args)})
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

class ReleaseFile:
    def __init__(self, release_id):
        self.release = model.Release.query.filter_by(id=release_id).first()
        self.project_plugin_relation = model.ProjectPluginRelation.query.filter_by(
            project_id=self.release.project_id).first()

    def get_release_env_from_file(self):
        if self.release.commit is None or len(self.release.commit) < 6:
            return []
        file = gitlab.gl_get_file_from_lib(
            self.project_plugin_relation.git_repository_id,
            'iiidevops/app.env',
            self.release.commit

        )
        if file is not None:
            content = str(file.decode(), 'utf-8')
            lines = content.splitlines()
            items = []
            for line in lines:
                if line[0] == '#':
                    continue
                key, value = line[1:].split('=', 1)
                items.append({
                    'key': key,
                    'value': value,
                    'type': 'configmap'
                })
            return items
        else:
            return None
