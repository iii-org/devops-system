import model
import util

from collections import defaultdict
from flask_restful import Resource
from services import redmine_lib
from resources import harbor, redmine, gitlab, kubernetesClient, \
                      logger, sonarqube


DEFAULT_PASSWORD = 'IIIdevops_12345'


class ResourceUsers(object):
    def __init__(self):
        self.all_users = defaultdict(list)

    def set_all_members(self):
        for context in redmine_lib.redmine.user.all():
            self.all_users['rm_all_users'].append(context['login'])
            if hasattr(context, 'email'):
                self.all_users['rm_all_users_email'].append(context['email'])

        for context in self.handle_gl_user_page():
            self.all_users['gl_all_users'].append(context['username'])
            self.all_users['gl_all_users_email'].append(context['email'])

        self.all_users['hb_all_users'] = [
            context['username'] for context in self.handle_hb_user_page()
        ]
        self.all_users['k8s_all_users_sa'] = kubernetesClient.list_service_account()
        self.all_users['sq_all_users_login'] = [
            context['login'] for context in self.handle_sq_user_page()
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

    def handle_hb_user_page(self):
        hb_users = []
        page = 1
        page_size = 10
        total_size = 20
        while total_size > 0:
            params = {'page': page, 'page_size': page_size}
            output = harbor.hb_list_user(params)
            hb_users.extend(output.json())
            if output.headers.get('X-Total-Count', None):
                total_size = int(output.headers['X-Total-Count'])-(page*page_size)
                page += 1
            else:
                total_size = -1
        return hb_users

    def handle_sq_user_page(self):
        sq_users = []
        page = 1
        page_size = 50
        total_size = 20
        while total_size > 0:
            params = {'p': page, 'ps': page_size}
            output = sonarqube.sq_list_user(params).json()
            sq_users.extend(output['users'])
            total_size = int(output['paging']['total'])-(page*page_size)
            page += 1
        return sq_users


rc_users = ResourceUsers()


def set_args(user_row):
    args = {
        'id': user_row.id,
        'name': user_row.name,
        'email': user_row.email,
        'login': user_row.login,
        'password': DEFAULT_PASSWORD,
        'is_admin': False
    }
    return args


def users_process(admin_users_id, all_users):
    rc_users.set_all_members()
    for user_row in all_users:
        args = set_args(user_row)
        if user_row.id in admin_users_id:
            args['is_admin'] = True
        check_rm_members(args, rc_users.all_users['rm_all_users'], rc_users.all_users['rm_all_users_email'])
        check_gl_members(args, rc_users.all_users['gl_all_users'], rc_users.all_users['gl_all_users_email'])
        check_hb_members(args, rc_users.all_users['hb_all_users'])
        check_k8s_members(args, rc_users.all_users['k8s_all_users_sa'])
        check_sq_members(args, rc_users.all_users['sq_all_users_login'])


def check_user_relation(nexus_user_id):
    user_relation = model.UserPluginRelation.query.filter_by(user_id=nexus_user_id).all()
    if not user_relation:
        logger.logger.info(f'User id {nexus_user_id} relation not exist, create new one.')
        new_user_relation = model.UserPluginRelation(user_id=nexus_user_id)
        model.db.session.add(new_user_relation)
        model.db.session.commit()
        user_relation = model.UserPluginRelation.query.filter_by(user_id=nexus_user_id).all()
    return user_relation[0]


def check_rm_members(args, rm_all_users, rm_all_users_email):
    if args['login'] not in rm_all_users and args['email'] in rm_all_users_email:
        logger.logger.info(f'Need attention: User {args["login"]} not found in redmine, '
                           f'but email {args["email"]} is used in redmin.')
        return
    elif args['login'] not in rm_all_users:
        logger.logger.info(f'User {args["login"]} not found in redmine.')
        logger.logger.info(f'Create {args["login"]} redmine user.')
        try:
            redmine_user = redmine.redmine.rm_create_user(args, args['password'], is_admin=args['is_admin'])
        except Exception as e:
            logger.logger.info(f'{args["login"]} redmine user create failed.')
            logger.logger.info(e)
            return
        redmine_user_id = redmine_user['user']['id']
        logger.logger.info(f'Redmine user created, id={redmine_user_id}')
        logger.logger.info('Update user relation.')
        user_relation = check_user_relation(args['id'])
        user_relation.plan_user_id = redmine_user_id
        model.db.session.commit()


def check_gl_members(args, gl_all_users, gl_all_users_email):
    if args['login'] not in gl_all_users and args['email'] in gl_all_users_email:
        logger.logger.info(f'Need attention: User {args["login"]} not found in gitlab, '
                           f'but email {args["email"]} is used in gitlab.')
        return
    elif args['login'] not in gl_all_users:
        logger.logger.info(f'User {args["login"]} not found in gitlab.')
        logger.logger.info(f'Create {args["login"]} gitlab user.')
        try:
            gitlab_user = gitlab.gitlab.gl_create_user(args, args['password'], is_admin=args['is_admin'])
        except Exception as e:
            logger.logger.info(f'{args["login"]} gitlab user create failed.')
            logger.logger.info(e)
            return
        gitlab_user_id = gitlab_user['id']
        logger.logger.info(f'Gitlab user created, id={gitlab_user_id}')
        logger.logger.info('Update user relation.')
        user_relation = check_user_relation(args['id'])
        user_relation.repository_user_id = gitlab_user_id
        model.db.session.commit()


def check_hb_members(args, hb_all_users):
    if args['login'] not in hb_all_users:
        logger.logger.info(f'User {args["login"]} not found in harbor.')
        logger.logger.info(f'Create {args["login"]} harbor user.')
        try:
            harbor_user_id = harbor.hb_create_user(args, is_admin=args['is_admin'])
        except Exception as e:
            logger.logger.info(f'{args["login"]} harbor user create failed.')
            logger.logger.info(e)
            return
        logger.logger.info(f'Harbor user created, id={harbor_user_id}')
        logger.logger.info('Update user relation.')
        user_relation = check_user_relation(args['id'])
        user_relation.harbor_user_id = harbor_user_id
        model.db.session.commit()


def check_k8s_members(args, k8s_all_users_sa):
    login_sa_name = util.encode_k8s_sa(args['login'])
    if login_sa_name not in k8s_all_users_sa:
        logger.logger.info(f'User {args["login"]} k8s sa not found in k8s.')
        logger.logger.info(f'Create {args["login"]} k8s sa.')
        try:
            kubernetes_sa = kubernetesClient.create_service_account(login_sa_name)
        except Exception as e:
            logger.logger.info(f'{args["login"]} k8s sa create failed.')
            logger.logger.info(e)
            return
        kubernetes_sa_name = kubernetes_sa.metadata.name
        logger.logger.info(f'Kubernetes user created, sa_name={kubernetes_sa_name}')
        user_relation = check_user_relation(args['id'])
        user_relation.kubernetes_sa_name = kubernetes_sa_name
        model.db.session.commit()


def check_sq_members(args, sq_all_users_login):
    if args['login'] not in sq_all_users_login:
        logger.logger.info(f'User {args["login"]} not found in sonarqube.')
        logger.logger.info(f'Create {args["login"]} sonarqube user.')
        try:
            sq_user = sonarqube.sq_create_user(args).json()
        except Exception as e:
            logger.logger.info(f'{args["login"]} sonarqube user create failed.')
            logger.logger.info(e)
            return
        logger.logger.info(f'Sonarqube user created, login={sq_user["login"]}')


def main_process():
    admin_users_id = list(sum(model.db.session.query(model.User).join(model.ProjectUserRole).filter(
            model.ProjectUserRole.project_id == -1, model.ProjectUserRole.role_id == 5).with_entities(model.User.id), ()))
    all_users = model.db.session.query(model.User).join(model.ProjectUserRole).filter(
            model.ProjectUserRole.project_id == -1, model.ProjectUserRole.role_id != 6)
    logger.logger.info('Users process start.')
    users_process(admin_users_id, all_users)
    logger.logger.info('All done.')


class SyncUser(Resource):
    def get(self):
        main_process()
        return util.success()
