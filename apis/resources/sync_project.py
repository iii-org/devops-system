import model
import util
import nexus

from flask_restful import Resource
from services import redmine_lib
from resources import harbor, redmine, gitlab, rancher, kubernetesClient, \
                      project, logger, user, sonarqube
from kubernetes.client import ApiException
from model import db


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


def check_rm_pj(projects_name):
    redmine_projects = list(redmine_lib.redmine.project.all().values_list('identifier', flat=True))
    rm_pj = list(set(projects_name)-set(redmine_projects))
    logger.logger.info(f'Redmine projects not exist: {rm_pj}.')
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
    logger.logger.info(f'Gitlab repository not exist: {gl_repo}.')
    nexus_pj = [nexus.nx_get_project(name=name) for name in gl_repo]
    return nexus_pj


def check_hb_pj(projects_name):
    harbor_projects = []
    params = {'page': 1, 'page_size': 50}
    response = harbor.__api_get('/projects', params=params).json()
    while response:
        harbor_projects.extend([context['name'] for context in response])
        params['page'] += 1
        response = harbor.__api_get('/projects', params=params).json()
    hb_pj = list(set(projects_name)-set(harbor_projects))
    logger.logger.info(f'Harbor project not exist: {hb_pj}.')
    nexus_pj = [nexus.nx_get_project(name=name) for name in hb_pj]
    return nexus_pj


def check_sq_pj(projects_name):
    sonarqube_projects = []
    page = 1
    response = sonarqube.sq_list_project(page).json()
    while response['components']:
        page += 1
        sonarqube_projects.extend([pj['key'] for pj in response['components']])
        response = sonarqube.sq_list_project(page).json()
    sq_pj = list(set(projects_name)-set(sonarqube_projects))
    logger.logger.info(f'Sonarqube project not exist: {sq_pj}.')
    nexus_pj = [nexus.nx_get_project(name=name) for name in sq_pj]
    return nexus_pj


def check_project_relation(project_id):
    pj_relation = model.ProjectPluginRelation.query.filter_by(project_id=project_id).all()
    if not pj_relation:
        logger.logger.info(f'Project id {project_id} relation not exist, create new one.')
        new_pj_relation = model.ProjectPluginRelation(project_id=project_id)
        db.session.add(new_pj_relation)
        db.session.commit()


def check_project_members(project_id, user_id):
    role_id = user.get_role_id(user_id)

    # Check ProjectUserRole table has relationship or not
    row = model.ProjectUserRole.query.filter_by(
        user_id=user_id, project_id=project_id, role_id=role_id).first()
    # if ProjectUserRole table not has relationship
    if row:
        logger.logger.info(f'User {user_id} already in project {project_id}.')
    else:
        # insert one relationship
        new = model.ProjectUserRole(project_id=project_id, user_id=user_id, role_id=role_id)
        db.session.add(new)
        db.session.commit()


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
    logger.logger.info(f'Kubernetes namesapces not exist: {non_exist_projects}.')
    if non_exist_projects:
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
    logger.logger.info(f'Rancher pipeline not exist: {non_exist_pipeline}.')
    if non_exist_pipeline:
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
            db.session.commit()
            check_bot_list.append(pj_row.id)


def bot_process(check_bot_list):
    if check_bot_list:
        logger.logger.info(f'BOT project id to check: {check_bot_list}.')
        for nx_project_id in check_bot_list:
            pj = model.Project.query.get(nx_project_id)
            bot = model.User.query.filter_by(login=f'project_bot_{pj.id}').all()
            if bot:
                logger.logger.info(f'BOT already exist, need to delete first: {bot.name}.')
                project.delete_bot(pj.id)
            logger.logger.info(f'Create new BOT for project: {pj.name}.')
            project.create_bot(pj.id)


def sonarqube_process(projects_name, check_bot_list):
    sq_pj = check_sq_pj(projects_name)
    if sq_pj:
        for pj in sq_pj:
            logger.logger.info(f'Create sonarqube project: {pj.name}.')
            sonarqube.sq_create_project(pj.name, pj.display)
            check_bot_list.append(pj.id)


def main_process():
    check_bot_list = []
    projects_name = list(sum(model.Project.query.filter(
                            model.Project.id != -1).with_entities(model.Project.name).all(), ()))
    logger.logger.info('Kubernetes namespaces.')
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
    logger.logger.info('Checking Project BOT start.')
    bot_process(list(set(check_bot_list)))


class SyncProject(Resource):
    def get(self):
        main_process()
        return util.success()
