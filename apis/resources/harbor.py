import re
from urllib.parse import quote, quote_plus

from flask_jwt_extended import jwt_required, get_jwt_identity
from flask_restful import Resource, reqparse
from requests.auth import HTTPBasicAuth
from time import sleep
import config
import model
import nexus
import util
from resources import apiError, role
from resources.apiError import DevOpsError
from resources.logger import logger
from datetime import datetime

HAR_PASS_REG = '((?=.*\d)(?=.*[a-z])(?=.*[A-Z])).{8,20}$'
DEFAULT_PASSWORD = 'IIIdevops_12345'


def check_passsword(password):
    return bool(re.match(HAR_PASS_REG, password))


# API bridge methods
def __api_request(method, path, headers=None, params=None, data=None):
    if headers is None:
        headers = {}
    if params is None:
        params = {}
    if 'Content-Type' not in headers:
        headers['Content-Type'] = 'application/json'
    auth = HTTPBasicAuth(config.get('HARBOR_ACCOUNT'),
                         config.get('HARBOR_PASSWORD'))
    url = "{0}{1}".format(config.get('HARBOR_INTERNAL_BASE_URL'), path)
    output = util.api_request(method, url, headers=headers,
                              params=params, data=data, auth=auth)
    logger.debug('Harbor api {0} {1}, params={2}, body={5}, response={3} {4}'.format(
        method, url, params.__str__(), output.status_code, output.text, data))
    if int(output.status_code / 100) != 2:
        raise DevOpsError(
            output.status_code,
            'Got non-2xx response from Harbor.',
            apiError.error_3rd_party_api('Harbor', output))
    return output


def __api_get(path, params=None, headers=None):
    return __api_request('GET', path, params=params, headers=headers)


def __api_post(path, params=None, headers=None, data=None):
    return __api_request('POST', path, headers=headers, data=data, params=params)


def __api_put(path, params=None, headers=None, data=None):
    return __api_request('PUT', path, headers=headers, data=data, params=params)


def __api_delete(path, params=None, headers=None):
    return __api_request('DELETE', path, params=params, headers=headers)


def __encode(repository_name):
    return quote(quote(repository_name, safe=""))


# Regular methods
def hb_get_id_by_name(project_name):
    projects = __api_get('/projects', params={'name': project_name}).json()
    if len(projects) == 0:
        raise DevOpsError(404, 'Harbor does not have such project.',
                          error=apiError.project_not_found(project_name))
    return projects[0]['project_id']


def hb_create_project(project_name):
    data = {
        'project_name': project_name,
        'cve_whitelist': {
            'items': [{'cve_id': 'string'}]
        },
        'storage_limit': 10737418240,
        'metadata': {
            'enable_content_trust': 'string',
            'auto_scan': 'true',
            'severity': 'string',
            'reuse_sys_cve_whitelist': 'string',
            'public': 'false',
            'prevent_vul': 'string'
        },
        'public': False
    }
    try:
        __api_post('/projects', data=data)
    except DevOpsError as e:
        if e.unpack_response()['errors'][0]['code'] == 'CONFLICT':
            raise DevOpsError(422, 'Harbor already has a project using this name.',
                              error=apiError.identifier_has_been_taken(project_name))
        else:
            raise e
    return hb_get_id_by_name(project_name)


def hb_delete_project(harbor_param):
    try:
        repositories = hb_list_repositories(harbor_param[1])
        if len(repositories) != 0:
            for repository in repositories:
                split_list = repository["name"].split("/")
                project_name = split_list[0]
                repository_name = '/'.join(split_list[1:])
                hb_delete_repository(project_name, repository_name)
        __api_delete('/projects/{0}'.format(harbor_param[0]))
    except DevOpsError as e:
        if e.status_code in [404, 403]:
            # 404: Deleting a not existing project , let it go
            # 403: list not existing repositories, let it go
            pass
        else:
            raise e


def hb_create_user(args, is_admin=False):
    login = args['login']
    pass_quality = check_passsword(args['password'])
    harbor_password = args['password']
    if pass_quality is False:
        harbor_password = DEFAULT_PASSWORD
    data = {
        "username": login,
        "password": harbor_password,
        "realname": args['name'],
        "email": args['email']
    }
    if is_admin:
        data['sysadmin_flag'] = True
    __api_post('/users', data=data)
    res = __api_get('/users/search', params={'username': login}).json()
    return res[0]['user_id']


def hb_list_user(args):
    return __api_get('/users', params=args)


def hb_delete_user(user_id):
    __api_delete('/users/{0}'.format(user_id))


def hb_update_user_password(user_id, new_pwd, old_pwd):
    pass_quality = check_passsword(new_pwd)
    if pass_quality is False:
        new_pwd = DEFAULT_PASSWORD
    data = {
        "new_password": new_pwd,
        "old_password": old_pwd
    }
    try:
        __api_put(f'/users/{user_id}/password', data=data)
    except DevOpsError as e:
        if e.status_code == 400 and \
                e.error_value['details']['response']['errors'][0][
                    'message'] == 'the new password can not be same with the old one':
            pass
        else:
            raise e


def hb_update_user_email(user_id, user_name, new_email):
    data = {
        'email': new_email,
        'realname': user_name
    }
    try:
        __api_put(f'/users/{user_id}', data=data)
    except DevOpsError as e:
        if e.status_code == 400 and \
                e.error_value['details']['response']['errors'][0][
                    'message'] == 'the new password can not be same with the old one':
            pass
        else:
            raise e


def hb_list_member(project_id, args):
    return __api_get('/projects/{0}/members'.format(project_id), params=args)


def hb_add_member(project_id, user_id):
    data = {
        "role_id": 1,
        "member_user": {
            "user_id": user_id
        }
    }
    __api_post('/projects/{0}/members'.format(project_id), data=data)


def hb_remove_member(project_id, user_id):
    members = __api_get('/projects/{0}/members'.format(project_id)).json()
    member_id = None
    for member in members:
        if member['entity_id'] == user_id:
            member_id = member['id']
            break
    if member_id is None:
        raise DevOpsError(404, 'User is not in the project.',
                          error=apiError.user_not_found(user_id))
    __api_delete('/projects/{0}/members/{1}'.format(project_id, member_id))


def hb_list_repositories(project_name):
    repositories = __api_get(
        '/projects/{0}/repositories'.format(project_name)).json()
    ret = []
    for repo in repositories:
        repo['harbor_link'] = hb_build_external_link('/harbor/projects/{0}/repositories/{1}'.format(
            repo['project_id'],
            repo['name'].replace((project_name + "/"), "")))
        ret.append(repo)
    return ret


def check_scan_overview_exists(scan_overview):
    vul = ''
    if scan_overview is None:
        return vul
    scan = next(iter(scan_overview.values()))
    if (scan is None) or ('summary' not in scan) or ('total' not in scan['summary']):
        vul = ''
    else:
        vul = '{0} ({1})'.format(scan['severity'], scan['summary']['total'])
    return vul


def generate_artifacts_output(art):
    output = []
    vul = check_scan_overview_exists(art.get('scan_overview', None))
    if 'tags' in art and art['tags'] is not None:
        for tag in art['tags']:
            output.append({
                'artifact_id': art['id'],
                'tag_id': tag['id'],
                'name': tag.get('name', ""),
                'size': art['size'],
                'vulnerabilities': vul,
                'digest': art['digest'],
                'labels': art['labels'],
                'push_time': art['push_time']
            })
    else:
        output.append({
            'artifact_id': art['id'],
            'tag_id': '',
            'name': '',
            'size': art['size'],
            'vulnerabilities': vul,
            'digest': art['digest'],
            'labels': art['labels'],
            'push_time': art['push_time']
        })
    return output


def hb_list_artifacts_with_params(project_name, repository_name, push_time=None):
    ret = []
    args = {"page": 1, "page_size": 15}
    while True:
        data = hb_list_artifacts_with_params_helper(project_name, repository_name, args, push_time)
        if data == []:
            break
        ret += data
        args["page"] += 1
    return ret


def hb_list_artifacts_with_params_helper(project_name, repository_name, args, push_time=None):
    page_size = args.get('page_size', 10)
    page = args.get("page", 1)
    params = {'with_scan_overview': True, 'with_tag': True, "page": page, "page_size": page_size}
    if push_time is not None:
        now_time = datetime.now().strftime("%Y-%m-%dT%H:%M:%S")
        params["q"] = f'push_time=[{push_time}~{now_time}]'
    artifacts = __api_get(f'/projects/{project_name}/repositories'
                          f'/{__encode(repository_name)}/artifacts',
                          params=params).json()
    ret = []
    for art in artifacts:
        ret = ret + generate_artifacts_output(art)
    return ret

def hb_get_artifacts_with_tag(project_name, repository_name, tag):
    params = {"q": f"tags={tag}"}
    artifacts = __api_get(f'/projects/{project_name}/repositories'
                          f'/{__encode(repository_name)}/artifacts',
                          params=params).json()
    if artifacts != []:
        return generate_artifacts_output(artifacts[0])
    return []


def hb_list_artifacts(project_name, repository_name):
    artifacts = __api_get(f'/projects/{project_name}/repositories'
                          f'/{__encode(repository_name)}/artifacts',
                          params={'with_scan_overview': True}).json()
    ret = []
    for art in artifacts:
        ret = ret + generate_artifacts_output(art)
    return ret


def hb_get_artifact(project_name, repository_name, tag_name):
    artifact = __api_get(f'/projects/{project_name}/repositories'
                         f'/{__encode(repository_name)}/artifacts/'
                         f'{__encode(tag_name)}', params={'with_scan_overview': True}).json()

    return generate_artifacts_output(artifact)


def hb_copy_artifact(project_name, repository_name, from_image):
    url = f"/projects/{project_name}/repositories/{repository_name}/artifacts?from={quote_plus(from_image)}"
    return __api_post(url)


def hb_copy_artifact_and_retage(project_name, from_repo_name, dest_repo_name, from_tag, dest_tag, forced=True):
    # if from_repo:from_tag == dest_repo:dest_tag, then do nothing.
    if from_repo_name == dest_repo_name and from_tag == dest_tag:
        logger.info("from_repo:from_tag and dest_repo:dest_tag is same.")
        print("from_repo:from_tag and dest_repo:dest_tag is same.")
        return

    # if from_repo:from_tag not found, then do nothing as well.
    try:
        digest = hb_get_artifact(project_name, from_repo_name, from_tag)[0]["digest"]
        print(digest)
    except:
        logger.info(f"Can not find {from_repo_name}:{from_tag}")
        print(f"Can not find {from_repo_name}:{from_tag}")
        return

    # if dest_repo:dest_tag is exist, delete it.
    try:
        dest_digest = hb_get_artifact(project_name, dest_repo_name, dest_tag)[0]["digest"]
        print(dest_digest)
        a = hb_delete_artifact(project_name, dest_repo_name, dest_digest)
        logger.info(f"Replace the old {dest_repo_name}:{dest_digest}")
        print(f"Replace the old {dest_repo_name}:{dest_digest}")
    except:
        pass

    from_image = f'{project_name}/{from_repo_name}@{digest}'
    hb_copy_artifact(project_name, dest_repo_name, from_image)
    hb_create_artifact_tag(project_name, dest_repo_name, digest, dest_tag, forced=forced)

    # if from_repo != dest_repo, delete the dest_repo:from_tag's tag
    if from_repo_name != dest_repo_name:
        hb_delete_artifact_tag(project_name, dest_repo_name, digest, from_tag)

    logger.info(f"Copy from {from_repo_name}:{from_tag} to {dest_repo_name}:{dest_tag}")
    print(f"Copy from {from_repo_name}:{from_tag} to {dest_repo_name}:{dest_tag}")


def hb_get_repository_info(project_name, repository_name):
    return __api_get(f'/projects/{project_name}/repositories/{__encode(repository_name)}').json()


def hb_update_repository(project_name, repository_name, args):
    return __api_put(f'/projects/{project_name}/repositories/{__encode(repository_name)}',
                     data={'description': args['description']})


def hb_delete_repository(project_name, repository_name):
    return __api_delete(f'/projects/{project_name}/repositories/{__encode(repository_name)}')


def hb_delete_artifact(project_name, repository_name, reference):
    return __api_delete(f'/projects/{project_name}/repositories/{__encode(repository_name)}'
                        f'/artifacts/{reference}')


def hb_list_tags(project_name, repository_name, reference):
    return __api_get(f'/projects/{project_name}/repositories/{__encode(repository_name)}'
                     f'/artifacts/{reference}/tags').json()


def hb_create_artifact_tag(project_name, repository_name, reference, tag_name, forced=False):
    exist_tag_artifact = hb_get_artifacts_with_tag(project_name, repository_name, tag_name)
    if exist_tag_artifact != []:
        if forced:
            hb_delete_artifact_tag(
                project_name, repository_name, exist_tag_artifact[0]['digest'], tag_name, keep=True)
        else:
            raise apiError.DevOpsError(
                500, f'{tag_name.capitalize()} already exist in this Harbor repository.',
                error=apiError.harbor_tag_already_exist(tag_name, repository_name)) 

    return __api_post(f'/projects/{project_name}/repositories/{__encode(repository_name)}'
                      f'/artifacts/{reference}/tags', data={'name': tag_name})


def hb_delete_artifact_tag(project_name, repository_name, reference, tag_name, keep=False):
    __api_delete(f'/projects/{project_name}/repositories/{__encode(repository_name)}'
                 f'/artifacts/{reference}/tags/{tag_name}')
    if len(hb_list_tags(project_name, repository_name, reference)) == 0 and not keep:
        hb_delete_artifact(project_name, repository_name, reference)


def hb_get_project_summary(project_id):
    return __api_get('/projects/{0}/summary'.format(project_id)).json()


def hb_build_external_link(path):
    return f"{config.get('HARBOR_EXTERNAL_BASE_URL')}{path}"


def get_storage_usage(project_id):
    harbor_info = hb_get_project_summary(project_id)
    usage_info = {}
    usage_info['title'] = 'Harbor'
    usage_info['used'] = {}
    usage_info['used']['value'] = harbor_info['quota']['used']['storage']
    usage_info['used']['unit'] = ''
    usage_info['quota'] = {}
    usage_info['quota']['value'] = harbor_info['quota']['hard']['storage']
    usage_info['quota']['unit'] = ''
    return usage_info


def hb_get_registries(registry_id=None, args=None):
    if registry_id:
        registry = __api_get('/registries/{0}'.format(registry_id)).json()
    elif args:
        registry = __api_get('/registries?q={0}'.format(args)).json()
    else:
        registry = __api_get('/registries').json()
    return registry


def hb_create_registries(args):
    user_id = get_jwt_identity()['user_id']
    if args['type'] == 'aws-ecr':
        args['url'] = 'https://api.ecr.{location}.amazonaws.com'.format(
            location=args['location'])
    elif args['type'] == 'azure-acr':
        args['url'] = 'https://{login_server}'.format(
            login_server=args['login_server'])
    elif args['type'] == 'harbor':
        args['url'] = '{login_server}'.format(
            login_server=args['login_server'])
    __api_post('/registries/ping', data=args)

    args['credential'] = {
        'access_key': args['access_key'],
        'access_secret': args['access_secret'],
        'type': 'basic'
    }
    __api_post('/registries', data=args)
    if args['type'] == 'harbor':
        args['access_secret'] = util.base64encode(args['access_secret'])
    registries_id = hb_get_registries(
        args='name={0}'.format(args['name']))[0].get('id')
    new_registries = model.Registries(
        registries_id=registries_id,
        name=args['name'],
        user_id=user_id,
        description=args['description'],
        access_key=args['access_key'],
        access_secret=args['access_secret'],
        url=args['url'],
        type=args['type'],
        disabled=False
    )
    model.db.session.add(new_registries)
    model.db.session.commit()
    return registries_id


def hb_put_registries(registry_id, args):
    if args['type'] == 'aws-ecr':
        args['url'] = 'https://api.ecr.{location}.amazonaws.com'.format(
            location=args['location'])
    elif args['type'] == 'azure-acr':
        args['url'] = 'https://{login_server}'.format(
            login_server=args['login_server'])
    elif args['type'] == 'harbor':
        args['url'] = '{login_server}'.format(
            login_server=args['login_server'])
    __api_post('/registries/ping', data=args)
    args['credential'] = {
        'access_key': args['access_key'],
        'access_secret': args['access_secret'],
        'type': 'basic'
    }
    __api_put(
        f'/registries/{registry_id}', data=args)

    registries_id = hb_get_registries(
        args='name={0}'.format(args['name']))[0].get('id')
    if args['type'] == 'harbor':
        args['access_secret'] = util.base64encode(args['access_secret'])
    registry = model.Registries.query.filter_by(registries_id=registry_id).first()

    for key in args.keys():
        if not hasattr(registry, key):
            continue
        elif args[key] is not None:
            setattr(registry, key, args[key])
    model.db.session.commit()
    return registries_id


def hb_delete_registries(registry_id):
    return __api_delete(f'/registries/{registry_id}')


#  Replication Policy


def hb_get_replication_policy_data(args):
    dest_registry = hb_get_registries(registry_id=args['registry_id'])
    data = {
        "name": args.get('policy_name'),
        "description": args.get('description'),
        "dest_registry": dest_registry,
        "trigger": {
            "type": "manual",
            "trigger_settings": {"cron": ""}
        },
        "enabled": True,
        "deletion": False,
        "override": True,
        "dest_namespace": args.get('dest_repo_name'),
        "filters": [
            {
                "type": "name",
                "value": args.get('repo_name') + '/' + args.get('image_name')
            },
            {
                "type": "resource",
                "value": "image"
            },
            {
                "type": "tag",
                "value": args.get('tag_name')
            }
        ]
    }
    return data


replication_polices_base_url = '/replication/policies'


def hb_get_replication_policies(args=None):
    if args.get('name', None) is not None:
        policy_name = args.get('name')
        policies = __api_get(
            f'{replication_polices_base_url}?name={policy_name}').json()
    else:
        policies = __api_get(replication_polices_base_url).json()
    return policies


def hb_get_replication_policy(policy_id=None):
    if policy_id:
        policies = __api_get(
            f'{replication_polices_base_url}/{policy_id}').json()
    else:
        policies = __api_get(replication_polices_base_url).json()
    return policies


def hb_create_replication_policy(args):
    data = hb_get_replication_policy_data(args)
    __api_post(replication_polices_base_url, data=data)
    output = hb_get_replication_policies({'name': args.get('policy_name')})
    return output[0].get('id')


def hb_put_replication_policy(args, policy_id):
    data = hb_get_replication_policy_data(args)
    __api_put(
        f'{replication_polices_base_url}/{policy_id}', data=data)
    return policy_id


def hb_delete_replication_policy(policy_id):
    __api_delete(
        f'{replication_polices_base_url}/{policy_id}')
    return policy_id


def hb_execute_replication_policy(policy_id):
    data = {"policy_id": policy_id}
    __api_post('/replication/executions', data=data)

    policies = hb_get_replication_policy(policy_id)
    name = [context['value']
            for context in policies['filters'] if context['type'] == 'name'][0]
    tag = [context['value']
           for context in policies['filters'] if context['type'] == 'tag'][0]
    dest_registry = policies.get('dest_registry')
    dest_credential = dest_registry.get('credential')
    if dest_registry.get('type') == 'aws-ecr':
        account_id = util.AWSEngine(
            dest_credential.get('access_key'),
            dest_credential.get('access_secret')
        ).get_account_id()
        location = dest_registry.get('url').split('.')[2]
        image_uri = f'{account_id}.dkr.ecr.{location}.amazonaws.com/{name}:{tag}'
    elif dest_registry.get('type') == 'azure-acr':
        dest_server = dest_registry.get('url')[8:]
        image_uri = f'{dest_server}/{name}:{tag}'
    elif dest_registry.get('type') == 'harbor':
        dest_server = dest_registry.get('url')[8:]
        dest_repo = policies.get('dest_namespace')
        project_name = name[(name.find('/') + 1):]
        image_uri = f'{dest_server}/{dest_repo}/{project_name}:{tag}'
    else:
        image_uri = None
    return image_uri


def hb_get_replication_executions(policy_id):
    data = {"policy_id": policy_id}
    return __api_get('/replication/executions/', params=data).json()


def hb_get_replication_execution_task(execution_id):
    return __api_get(f'/replication/executions/{execution_id}/tasks').json()


def hb_get_replication_executions_tasks_log(execution_id, task_id):
    return __api_get(f'/replication/executions/{execution_id}/tasks/{task_id}/log')


def hb_ping_registries(args):
    data = {"id": args['registries_id']}
    __api_post('/registries/ping', data=data)


# ----------------- Resources -----------------
def extract_names():
    parser = reqparse.RequestParser()
    parser.add_argument('repository_fullname', type=str)
    args = parser.parse_args()
    name = args['repository_fullname']
    names = name.split('/')
    return names[0], '/'.join(names[1:])


class HarborRepository(Resource):
    @jwt_required
    def get(self, nexus_project_id):
        role.require_in_project(nexus_project_id)
        project_name = nexus.nx_get_project(id=nexus_project_id).name
        return util.success(hb_list_repositories(project_name))

    @jwt_required
    def put(self):
        project_name, repository_name = extract_names()
        role.require_in_project(project_name=project_name)
        parser = reqparse.RequestParser()
        parser.add_argument('description', type=str)
        args = parser.parse_args()
        hb_update_repository(project_name, repository_name, args)
        return util.success()

    @jwt_required
    def delete(self):
        project_name, repository_name = extract_names()
        role.require_in_project(project_name=project_name)
        hb_delete_repository(project_name, repository_name)
        return util.success()


def check_tag_name(artifacts, tag_name):
    output = []
    if artifacts is None:
        return artifacts
    for artifact in artifacts:
        if artifact.get('name') == tag_name:
            output.append(artifact)
    return output


class HarborArtifact(Resource):
    @jwt_required
    def get(self):
        project_name, repository_name = extract_names()
        role.require_in_project(project_name=project_name)
        parser = reqparse.RequestParser()
        parser.add_argument('repository_fullname', type=str)
        parser.add_argument('tag_name', type=str)
        args = parser.parse_args()
        artifacts = hb_list_artifacts(project_name, repository_name)
        if args.get('tag_name', None) is not None:
            return util.success(check_tag_name(artifacts, args.get('tag_name')))
        else:
            return util.success(artifacts)

    @jwt_required
    def delete(self):
        project_name, repository_name = extract_names()
        role.require_in_project(project_name=project_name)
        parser = reqparse.RequestParser()
        parser.add_argument('digest', type=str)
        parser.add_argument('tag_name', type=str)
        args = parser.parse_args()
        hb_delete_artifact_tag(project_name, repository_name,
                               args['digest'], args['tag_name'])
        return util.success()


class HarborProject(Resource):
    @jwt_required
    def get(self, nexus_project_id):
        role.require_in_project(nexus_project_id)
        project_id = nexus.nx_get_project_plugin_relation(
            nexus_project_id=nexus_project_id).harbor_project_id
        return util.success(hb_get_project_summary(project_id))


class HarborRelease():

    @jwt_required
    def get_list_artifacts(self, project_name, repository_name):
        return hb_list_artifacts(project_name, repository_name)

    def check_harbor_status(self, image, tag_name):
        output = 2
        if image is True and tag_name is True:
            output = 1
        elif image is True:
            output = 0
        return output

    def check_harbor_release(self, artifacts, tag_name, commit):
        output = {'check': False, 'tag': False, 'image': False,
                  "info": "", "target": {}, "errors": {}, "type": 2}

        for art in artifacts:
            #  Tag duplicate
            if art['name'] == tag_name:
                output['tag'] = True
                output['info'] = '{0} is exists in harbor'.format(tag_name)
                output['target']['duplicate'] = art
            #  Image Find
            if art['name'] == commit:
                output['image'] = True
                output['info'] = '{0} is exists in harbor'.format(commit)
                output['target']['release'] = art
        output['type'] = self.check_harbor_status(
            output['image'], output['tag'])
        if output['type'] == 0:
            output['check'] = True
        elif output['type'] == 2:
            output['info'] = '{0} image is not exists in harbor'.format(commit)
        return output

    def create(self, project_name, repository_name, reference, tag_name):
        return hb_create_artifact_tag(project_name, repository_name, reference, tag_name)

    def delete_harbor_tag(self, project_name, repository_name, hb_info):
        return hb_delete_artifact_tag(project_name, repository_name, hb_info['digest'], hb_info['name'])


hb_release = HarborRelease()


class HarborRegistry(Resource):
    @jwt_required
    def get(self, registry_id):
        role.require_admin()
        return util.success(hb_get_registries(registry_id))

    @jwt_required
    def put(self, registry_id):
        role.require_admin()
        parser = reqparse.RequestParser()
        parser.add_argument('name', type=str, required=True)
        parser.add_argument('type', type=str, required=True)
        parser.add_argument('access_key', type=str, required=True)
        parser.add_argument('access_secret', type=str, required=True)
        parser.add_argument('location', type=str, required=False)
        parser.add_argument('login_server', type=str, required=False)
        parser.add_argument('description', type=str)
        parser.add_argument('insecure', type=bool)
        parser.add_argument('disabled', type=bool)
        args = parser.parse_args()
        return util.success({'registry_id': hb_put_registries(registry_id, args)})

    @jwt_required
    def delete(self, registry_id):
        role.require_admin()
        hb_delete_registries(registry_id)
        return util.success()


class HarborRegistries(Resource):
    @jwt_required
    def get(self):
        return util.success(hb_get_registries())

    @jwt_required
    def post(self):
        role.require_admin()
        parser = reqparse.RequestParser()
        parser.add_argument('name', type=str, required=True)
        parser.add_argument('type', type=str, required=True)
        parser.add_argument('access_key', type=str, required=True)
        parser.add_argument('access_secret', type=str, required=True)
        parser.add_argument('location', type=str, required=False)
        parser.add_argument('login_server', type=str, required=False)
        parser.add_argument('description', type=str)
        parser.add_argument('insecure', type=bool)
        args = parser.parse_args()
        return util.success({'registry_id': hb_create_registries(args)})


class HarborRegistriesPing(Resource):
    @jwt_required
    def post(self):
        parser = reqparse.RequestParser()
        parser.add_argument('registries_id', type=str, required=True)
        args = parser.parse_args()
        hb_ping_registries(args)
        return util.success()


class HarborReplicationPolicy(Resource):
    @jwt_required
    def get(self, replication_policy_id):
        policies = hb_get_replication_policy(replication_policy_id)
        return util.success(policies)

    @jwt_required
    def put(self, replication_policy_id):
        parser = reqparse.RequestParser()
        parser.add_argument('policy_name', type=str, required=True)
        parser.add_argument('repo_name', type=str, required=True)
        parser.add_argument('image_name', type=str, required=True)
        parser.add_argument('tag_name', type=str, required=True)
        parser.add_argument('registry_id', type=int, required=True)
        parser.add_argument('description', type=str, required=True)
        parser.add_argument('dest_repo_name', type=str, required=True)
        args = parser.parse_args()
        return util.success({'replication_policy_id': hb_put_replication_policy(args, replication_policy_id)})

    @jwt_required
    def delete(self, replication_policy_id):
        return util.success({'replication_policy_id': hb_delete_replication_policy(replication_policy_id)})


class HarborReplicationPolices(Resource):
    @jwt_required
    def get(self):
        parser = reqparse.RequestParser()
        parser.add_argument('name', type=str)
        args = parser.parse_args()
        policies = hb_get_replication_policies(args)
        return util.success(policies)

    @jwt_required
    def post(self):
        parser = reqparse.RequestParser()
        parser.add_argument('policy_name', type=str, required=True)
        parser.add_argument('repo_name', type=str, required=True)
        parser.add_argument('image_name', type=str, required=True)
        parser.add_argument('tag_name', type=str, required=True)
        parser.add_argument('registry_id', type=int, required=True)
        parser.add_argument('description', type=str, required=True)
        parser.add_argument('dest_repo_name', type=str, required=True)
        args = parser.parse_args()
        return util.success({'policy_id': hb_create_replication_policy(args)})


class HarborReplicationExecution(Resource):
    @jwt_required
    def post(self):
        parser = reqparse.RequestParser()
        parser.add_argument('policy_id', type=int)
        args = parser.parse_args()
        output = hb_execute_replication_policy(args.get('policy_id'))
        return util.success({'image_uri': output})

    @jwt_required
    def get(self):
        parser = reqparse.RequestParser()
        parser.add_argument('policy_id', type=int)
        args = parser.parse_args()
        output = hb_get_replication_executions(args.get('policy_id'))
        return util.success({'executions': output})


class HarborReplicationExecutionTasks(Resource):
    @jwt_required
    def get(self, execution_id):
        print(execution_id)
        output = hb_get_replication_execution_task(execution_id)
        return util.success({'task': output})


class HarborReplicationExecutionTaskLog(Resource):
    @jwt_required
    def get(self, execution_id, task_id):
        output = hb_get_replication_executions_tasks_log(execution_id, task_id)
        return util.success({'logs': output.text.splitlines()})


class HarborCopyImageRetage(Resource):
    @jwt_required
    def post(self):
        parser = reqparse.RequestParser()
        parser.add_argument('project_name', type=str, required=True)
        parser.add_argument('from_repo_name', type=str, required=True)
        parser.add_argument('dest_repo_name', type=str, required=True)
        parser.add_argument('from_tag', type=str, required=True)
        parser.add_argument('dest_tag', type=str, required=True)
        args = parser.parse_args()

        return util.success(
            hb_copy_artifact_and_retage(
                args["project_name"], args["from_repo_name"], args["dest_repo_name"], args["from_tag"], args["dest_tag"]))
