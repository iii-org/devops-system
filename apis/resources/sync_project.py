import model
import util
import nexus

from collections import defaultdict
from flask_restful import Resource
from services import redmine_lib
from resources import harbor, redmine, gitlab, rancher, kubernetesClient, \
                      project, logger, user, sonarqube
from kubernetes.client import ApiException


class ResourceMembers(object):
    def __init__(self):
        self.all_users = defaultdict(list)
        self.project_members = defaultdict(list)

    def set_all_members(self):
        self.all_users['rm_all_users_id'] = [
            context['id'] for context in redmine_lib.redmine.user.all()
        ]
        self.all_users['gl_all_users_id'] = [
            context['id'] for context in self.handle_gl_user_page()
        ]
        self.all_users['hb_all_users_id'] = [
            context['user_id'] for context in self.handle_hb_user_page()
        ]
        self.all_users['k8s_all_users_sa'] = kubernetesClient.list_service_account()
        self.all_users['sq_all_users_login'] = [
            context['login'] for context in self.handle_sq_user_page()
        ]

    def set_projects_members(self, pj_name, pj_relation):
        self.project_members['rm_members_id'] = [
            context['user']['id'] for context in redmine.redmine.rm_get_memberships_list(
                pj_relation.plan_project_id)['memberships']
            ]
        self.project_members['gl_members_id'] = [
            context['id'] for context in self.handle_gl_user_page(
                pj_relation.git_repository_id)
            ]
        self.project_members['hb_members_id'] = [
            context['entity_id'] for context in self.handle_hb_user_page(
                pj_relation.harbor_project_id)
        ]
        self.project_members['k8s_members_name'] = [
            context.metadata.name for context in kubernetesClient.list_role_binding_in_namespace(
                pj_name).items
        ]
        self.project_members['sq_members_name'] = [
            context['login'] for context in self.handle_sq_user_page(pj_name)
        ]

    def handle_gl_user_page(self, project_id=None):
        gl_users = []
        page = 1
        x_total_pages = 10
        while page <= x_total_pages:
            params = {'page': page}
            if project_id:
                output = gitlab.gitlab.gl_project_list_member(project_id, params)
            else:
                output = gitlab.gitlab.gl_get_user_list(params)
            gl_users.extend(output.json())
            x_total_pages = int(output.headers['X-Total-Pages'])
            page += 1
        return gl_users

    def handle_hb_user_page(self, project_id=None):
        hb_users = []
        page = 1
        page_size = 10
        total_size = 20
        while total_size > 0:
            params = {'page': page, 'page_size': page_size}
            if project_id:
                output = harbor.hb_list_member(project_id, params)
            else:
                output = harbor.hb_list_user(params)
            hb_users.extend(output.json())
            if output.headers.get('X-Total-Count', None):
                total_size = int(output.headers['X-Total-Count'])-(page*page_size)
                page += 1
            else:
                total_size = -1
        return hb_users

    def handle_sq_user_page(self, project_name=None):
        sq_users = []
        page = 1
        page_size = 50
        total_size = 20
        while total_size > 0:
            params = {'p': page, 'ps': page_size}
            if project_name:
                output = sonarqube.sq_list_member(project_name, params).json()
            else:
                output = sonarqube.sq_list_user(params).json()
            sq_users.extend(output['users'])
            total_size = int(output['paging']['total'])-(page*page_size)
            page += 1
        return sq_users


rc_members = ResourceMembers()


def set_args(project):
    args = {
        'id': project.id,
        'name': project.name,
        'description': project.description,
        'start_date': project.start_date,
        'due_date': project.due_date,
        'disabled': project.disabled,
        'display': project.display,
        'owner_id': project.owner_id,
        'creator_id': project.creator_id
    }
    return args


def members_process(projects_name):
    rc_members.set_all_members()
    for name in projects_name:
        logger.logger.info(f'Checking project {name} members.')
        pj = nexus.nx_get_project(name=name)
        pj_relation = nexus.nx_get_project_plugin_relation(nexus_project_id=pj.id)
        rc_members.set_projects_members(name, pj_relation)
        result = model.db.session.query(
            model.UserPluginRelation).join(model.User).join(model.ProjectUserRole).filter(
                model.ProjectUserRole.project_id == pj.id, model.ProjectUserRole.role_id.notin_([5, 6, 7]))
        if result:
            for user_relation in result:
                check_rm_members(pj_relation, user_relation, rc_members.all_users['rm_all_users_id'])
                check_gl_members(pj_relation, user_relation, rc_members.all_users['gl_all_users_id'])
                check_hb_members(pj_relation, user_relation, rc_members.all_users['hb_all_users_id'])
                check_k8s_members(pj, user_relation, rc_members.all_users['k8s_all_users_sa'])
                check_sq_members(pj, user_relation, rc_members.all_users['sq_all_users_login'])


def check_rm_members(pj_relation, user_relation, rm_all_users_id):
    if user_relation.plan_user_id not in rm_all_users_id:
        user_row = nexus.nx_get_user(id=user_relation.user_id)
        logger.logger.info(f'User {user_row.login} not found in redmine.')
        return
    elif user_relation.plan_user_id not in rc_members.project_members['rm_members_id']:
        logger.logger.info(f'User redmine id {user_relation.plan_user_id} not found '
                           f'in redmine {pj_relation.plan_project_id} '
                           f'members {rc_members.project_members["rm_members_id"]}.')
        logger.logger.info(f'Adding redmine user id {user_relation.plan_user_id} '
                           f'to redmine project id {pj_relation.project_id}.')
        role_id = user.get_role_id(user_relation.user_id)
        redmine_role_id = user.to_redmine_role_id(role_id)
        redmine.redmine.rm_create_memberships(
            pj_relation.plan_project_id,
            user_relation.plan_user_id,
            redmine_role_id
        )


def check_gl_members(pj_relation, user_relation, gl_all_users_id):
    if user_relation.repository_user_id not in gl_all_users_id:
        user_row = nexus.nx_get_user(id=user_relation.user_id)
        logger.logger.info(f'User {user_row.login} not found in gitlab.')
        return
    elif user_relation.repository_user_id not in rc_members.project_members['gl_members_id']:
        logger.logger.info(f'User gitlab id {user_relation.repository_user_id} '
                           f'not found in gitlab {pj_relation.git_repository_id} '
                           f'members {rc_members.project_members["gl_members_id"]}.')
        logger.logger.info(f'Adding gitlab user id {user_relation.repository_user_id} '
                           f'to gitlab project id {pj_relation.git_repository_id}.')
        gitlab.gitlab.gl_project_add_member(
            pj_relation.git_repository_id,
            user_relation.repository_user_id
        )


def check_hb_members(pj_relation, user_relation, hb_all_users_id):
    if user_relation.harbor_user_id not in hb_all_users_id:
        user_row = nexus.nx_get_user(id=user_relation.user_id)
        logger.logger.info(f'User {user_row.login} not found in harbor.')
        return
    elif user_relation.harbor_user_id not in rc_members.project_members['hb_members_id']:
        logger.logger.info(f'User harbor id {user_relation.harbor_user_id} not found '
                           f'in harbor {pj_relation.harbor_project_id} '
                           f'members {rc_members.project_members["hb_members_id"]}.')
        logger.logger.info(f'Adding harbor user id {user_relation.harbor_user_id} '
                           f'to harbor project id {pj_relation.harbor_project_id}.')
        harbor.hb_add_member(
            pj_relation.harbor_project_id,
            user_relation.harbor_user_id
        )


def check_k8s_members(pj, user_relation, k8s_all_users_sa):
    sa_name = '{0}-rb'.format(user_relation.kubernetes_sa_name)
    if user_relation.kubernetes_sa_name not in k8s_all_users_sa:
        logger.logger.info(f'User k8s sa {user_relation.kubernetes_sa_name} not found in k8s.')
        return
    elif sa_name not in rc_members.project_members['k8s_members_name']:
        logger.logger.info(f'User sa {user_relation.kubernetes_sa_name} not found '
                           f'in k8s namespace {pj.name} '
                           f'members {rc_members.project_members["k8s_members_name"]}.')
        logger.logger.info(f'Adding user {user_relation.kubernetes_sa_name} to k8s namespace {pj.name}.')
        kubernetesClient.create_role_binding(
            pj.name,
            user_relation.kubernetes_sa_name
        )


def check_sq_members(pj, user_relation, sq_all_users_login):
    user_row = nexus.nx_get_user(id=user_relation.user_id)
    if user_row.login not in sq_all_users_login:
        logger.logger.info(f'User {user_row.login} not found in sonarqube.')
        return
    elif user_row.login not in rc_members.project_members['sq_members_name']:
        logger.logger.info(f'User login {user_row.login} not found '
                           f'in sonarqube {pj.name} '
                           f'members {rc_members.project_members["sq_members_name"]}.')
        logger.logger.info(f'Adding user {user_row.login} to sonarqube project {pj.name}.')
        sonarqube.sq_add_member(
            pj.name,
            user_row.login
        )


def check_rm_pj(projects_name):
    redmine_projects = list(redmine_lib.redmine.project.all().values_list('identifier', flat=True))
    rm_pj = list(set(projects_name)-set(redmine_projects))
    nexus_pj = [nexus.nx_get_project(name=name) for name in rm_pj]
    return nexus_pj


def check_gl_repo(projects_name):
    gl_repo = []
    for name in projects_name:
        pj = nexus.nx_get_project(name=name)
        try:
            pj_relation = nexus.nx_get_project_plugin_relation(nexus_project_id=pj.id)
            gitlab.gitlab.gl_get_project(repo_id=pj_relation.git_repository_id)
        except Exception:
            gl_repo.append(pj.name)
    nexus_pj = [nexus.nx_get_project(name=name) for name in gl_repo]
    return nexus_pj


def check_hb_pj(projects_name):
    harbor_projects = []
    page = 1
    page_size = 10
    total_size = 20
    while total_size > 0:
        params = {'page': page, 'page_size': page_size}
        output = harbor.__api_get('/projects', params=params)
        harbor_projects.extend([context['name'] for context in output.json()])
        if output.headers.get('X-Total-Count', None):
            total_size = int(output.headers['X-Total-Count'])-(page*page_size)
            page += 1
        else:
            total_size = -1
    hb_pj = list(set(projects_name)-set(harbor_projects))
    nexus_pj = [nexus.nx_get_project(name=name) for name in hb_pj]
    return nexus_pj


def check_sq_pj(projects_name):
    sonarqube_projects = []
    page = 1
    page_size = 50
    total_size = 20
    while total_size > 0:
        params = {'p': page, 'ps': page_size}
        output = sonarqube.sq_list_project(params).json()
        sonarqube_projects.extend([pj['key'] for pj in output['components']])
        total_size = int(output['paging']['total'])-(page*page_size)
        page += 1
    sq_pj = list(set(projects_name)-set(sonarqube_projects))
    nexus_pj = [nexus.nx_get_project(name=name) for name in sq_pj]
    return nexus_pj


def check_project_relation(project_id):
    pj_relation = model.ProjectPluginRelation.query.filter_by(project_id=project_id).all()
    if not pj_relation:
        logger.logger.info(f'Project id {project_id} relation not exist, create new one.')
        new_pj_relation = model.ProjectPluginRelation(project_id=project_id)
        model.db.session.add(new_pj_relation)
        model.db.session.commit()


def check_project_members(project_id, user_id):
    role_id = user.get_role_id(user_id)
    row = model.ProjectUserRole.query.filter_by(
        user_id=user_id, project_id=project_id, role_id=role_id).first()
    if row:
        logger.logger.info(f'User {user_id} already in project {project_id}.')
    else:
        new = model.ProjectUserRole(project_id=project_id, user_id=user_id, role_id=role_id)
        model.db.session.add(new)
        model.db.session.commit()


def create_redmine_project(args):
    response = redmine.redmine.rm_create_project(args)
    new_rm_pj_id = response['project']['id']
    logger.logger.info('Create membership in redmine project')
    role_id = user.get_role_id(args['creator_id'])
    plan_user_id = nexus.nx_get_user_plugin_relation(user_id=args['creator_id']).plan_user_id
    redmine.redmine.rm_create_memberships(new_rm_pj_id, plan_user_id, role_id)
    check_project_members(args['id'], args['creator_id'])
    if args['owner_id'] != args['creator_id']:
        try:
            project.project_add_subadmin(args['id'], args['creator_id'])
        except Exception as e:
            logger.logger.info(e)
            pass
    return new_rm_pj_id


def create_gitlab_repo(args):
    response = gitlab.gitlab.gl_create_project(args)
    new_gl_repo_attr = {
        'id': response['id'],
        'name': response['name'],
        'ssh_url': response['ssh_url_to_repo'],
        'http_url': response['http_url_to_repo']
    }
    logger.logger.info('Create membership in gitlab repository')
    repository_user_id = nexus.nx_get_user_plugin_relation(user_id=args['creator_id']).repository_user_id
    gitlab.gitlab.gl_project_add_member(new_gl_repo_attr['id'], repository_user_id)
    check_project_members(args['id'], args['creator_id'])
    if args['owner_id'] != args['creator_id']:
        try:
            project.project_add_subadmin(args['id'], args['creator_id'])
        except Exception as e:
            logger.logger.info(e)
            pass
    return new_gl_repo_attr


def create_harbor_project(args):
    new_hb_pj_id = harbor.hb_create_project(args['name'])
    logger.logger.info('Create membership in harbor project')
    harbor_user_id = nexus.nx_get_user_plugin_relation(user_id=args['creator_id']).harbor_user_id
    harbor.hb_add_member(new_hb_pj_id, harbor_user_id)
    check_project_members(args['id'], args['creator_id'])
    if args['owner_id'] != args['creator_id']:
        try:
            project.project_add_subadmin(args['id'], args['creator_id'])
        except Exception as e:
            logger.logger.info(e)
            pass
    return new_hb_pj_id


def k8s_namespace_process(projects_name, check_bot_list):
    k8s_ns_list = kubernetesClient.list_namespace()
    non_exist_projects = list(set(projects_name)-set(k8s_ns_list))
    if non_exist_projects:
        logger.logger.info(f'Non-exist k8s namespaces found: {non_exist_projects}.')
        for project_name in non_exist_projects:
            pj_row = model.Project.query.filter_by(name=project_name).one()
            user_row = model.User.query.filter_by(id=pj_row.creator_id).one()
            try:
                kubernetesClient.create_namespace(project_name)
                kubernetesClient.create_role_in_namespace(project_name)
                kubernetesClient.create_namespace_quota(project_name)
                kubernetesClient.create_namespace_limitrange(project_name)
                logger.logger.info('Create k8s role binding')
                kubernetesClient.create_role_binding(pj_row.name, util.encode_k8s_sa(user_row.login))
            except ApiException as e:
                if e.status == 409:
                    logger.logger.info('Kubernetes already has this identifier.')
                    pass
                else:
                    kubernetesClient.delete_namespace(project_name)
                    logger.logger.info(e)
                break
            check_project_members(pj_row.id, user_row.id)
            if pj_row.owner_id != pj_row.creator_id:
                try:
                    project.project_add_subadmin(pj_row.id, user_row.id)
                except Exception:
                    pass
            check_bot_list.append(pj_row.id)


def redmine_process(projects_name, check_bot_list):
    rm_pj = check_rm_pj(projects_name)
    if rm_pj:
        logger.logger.info(f'Non-exist redmine projects found: {rm_pj}.')
        for pj in rm_pj:
            args = set_args(pj)
            logger.logger.info(f'Create redmine project: {pj.name}.')
            new_rm_pj_id = create_redmine_project(args)
            logger.logger.info(f'Update relation for new plan_project_id: {new_rm_pj_id}.')
            check_project_relation(pj.id)
            nexus.nx_update_project_relation(pj.id, {'plan_project_id': new_rm_pj_id})
            check_bot_list.append(pj.id)


def gitlab_process(projects_name, check_bot_list):
    gl_repo = check_gl_repo(projects_name)
    if gl_repo:
        logger.logger.info(f'Non-exist gitlab repository found: {gl_repo}.')
        for pj in gl_repo:
            args = set_args(pj)
            logger.logger.info(f'Create gitlab repository: {pj.name}.')
            new_gl_repo_attr = create_gitlab_repo(args)
            logger.logger.info(f'Update relation for new git_repository_id: {new_gl_repo_attr["id"]}.')
            check_project_relation(pj.id)
            nexus.nx_update_project_relation(pj.id, {'git_repository_id': new_gl_repo_attr['id']})
            logger.logger.info('Update project for new ssh_url & http_url.')
            nexus.nx_update_project(pj.id, {
                'ssh_url': new_gl_repo_attr['ssh_url'],
                'http_url': new_gl_repo_attr['http_url']
                }
            )
            check_bot_list.append(pj.id)


def harbor_process(projects_name, check_bot_list):
    hb_pj = check_hb_pj(projects_name)
    if hb_pj:
        logger.logger.info(f'Non-exist harbor repository found: {hb_pj}.')
        for pj in hb_pj:
            args = set_args(pj)
            logger.logger.info(f'Create harbor project: {args["name"]}.')
            new_hb_pj_id = create_harbor_project(args)
            logger.logger.info(f'Update relation for new harbor_project_id: {new_hb_pj_id}.')
            check_project_relation(pj.id)
            nexus.nx_update_project_relation(pj.id, {'harbor_project_id': new_hb_pj_id})
            check_bot_list.append(pj.id)


def pipeline_process(check_bot_list):
    project_git_http_url = list(sum(model.Project.query.filter(
                                      model.Project.id != -1).with_entities(
                                      model.Project.http_url).all(), ()))
    rancher.rancher.rc_get_project_id()
    pipeline_list = [pipeline['repositoryUrl'] for pipeline in rancher.rancher.rc_get_project_pipeline()]
    non_exist_pipeline = list(set(project_git_http_url)-set(pipeline_list))
    if non_exist_pipeline:
        logger.logger.info(f'Non-exist pipelines found: {non_exist_pipeline}.')
        for gitlab_pj_http_url in non_exist_pipeline:
            logger.logger.info(f'Create rancher pipeline: {gitlab_pj_http_url}.')
            new_ci_pipeline_id = rancher.rancher.rc_enable_project_pipeline(gitlab_pj_http_url)
            logger.logger.info(f'Update relation for new ci_pipeline_id: {new_ci_pipeline_id}.')
            pj_row = model.Project.query.filter_by(http_url=gitlab_pj_http_url).one()
            check_project_relation(pj_row.id)
            project_relation = model.ProjectPluginRelation.query.filter_by(project_id=pj_row.id).one()
            # project_relation = db.session.query(model.ProjectPluginRelation).join(
            #     model.Project).filter(model.Project.http_url == gitlab_pj_http_url).one()
            project_relation.ci_pipeline_id = new_ci_pipeline_id
            project_relation.ci_project_id = rancher.rancher.project_id
            model.db.session.commit()
            check_bot_list.append(pj_row.id)


def bot_process(check_bot_list):
    if check_bot_list:
        logger.logger.info(f'BOT project id to check: {check_bot_list}.')
        for nx_project_id in check_bot_list:
            pj = model.Project.query.get(nx_project_id)
            bot = model.User.query.filter_by(login=f'project_bot_{pj.id}').all()
            if bot:
                logger.logger.info(f'BOT already exist, need to delete it first: {bot.name}.')
                project.delete_bot(pj.id)
            logger.logger.info(f'Create new BOT for project: {pj.name}.')
            project.create_bot(pj.id)


def sonarqube_process(projects_name, check_bot_list):
    sq_pj = check_sq_pj(projects_name)
    if sq_pj:
        logger.logger.info(f'Non-exist sonarqube projects found: {sq_pj}.')
        for pj in sq_pj:
            user_row = nexus.nx_get_user(id=pj.creator_id)
            logger.logger.info(f'Create sonarqube project: {pj.name}.')
            sonarqube.sq_create_project(pj.name, pj.display)
            logger.logger.info('Create membership in harbor project')
            sonarqube.sq_add_member(
                pj.name,
                user_row.login
            )
            check_bot_list.append(pj.id)


def main_process():
    check_bot_list = []
    projects_name = list(sum(model.Project.query.filter(
                            model.Project.id != -1).with_entities(model.Project.name).all(), ()))
    logger.logger.info('Kubernetes namespaces start.')
    k8s_namespace_process(projects_name, check_bot_list)
    logger.logger.info('Redmine projects start.')
    redmine_process(projects_name, check_bot_list)
    logger.logger.info('Gitlab repository start.')
    gitlab_process(projects_name, check_bot_list)
    logger.logger.info('Harbor projects start.')
    harbor_process(projects_name, check_bot_list)
    logger.logger.info('Rancher pipelines start.')
    pipeline_process(check_bot_list)
    logger.logger.info('Sonarqube projects start.')
    sonarqube_process(projects_name, check_bot_list)
    logger.logger.info('Project BOT start.')
    bot_process(list(set(check_bot_list)))
    logger.logger.info('Project members start.')
    members_process(projects_name)
    logger.logger.info('All done.')


class SyncProject(Resource):
    def get(self):
        main_process()
        return util.success()