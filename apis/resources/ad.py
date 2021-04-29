from array import ArrayType
import json
import numbers
from datetime import datetime, date
from ldap3 import Server, ServerPool, Connection, SUBTREE, LEVEL, ALL, ALL_ATTRIBUTES, FIRST
import util as util
import model
from model import db
from flask_jwt_extended import jwt_required, get_jwt_identity
from flask_restful import Resource, reqparse
from sqlalchemy.orm.exc import NoResultFound
from resources import role
from resources.plugin import api_plugin
from resources.apiError import DevOpsError
import resources.apiError as apiError
from resources.logger import logger
from . import user

ad_connect_timeout = 5
ad_receive_timeout = 30
invalid_ad_server = 'Get AD User Error'
default_role_id = 3
default_password = 'IIIdevops_12345'

iii_institute_need_account = [
    '系統所',
    '數位所',
    '資安所',
    '服創所',
    '資訊處', 
    '前瞻中心'
]


def get_dc_string(domains):
    output = ''
    for domain in domains:
        output += 'dc='+domain+','
    return output[:-1]


def get_db_user_by_login():
    output = {}
    rows = db.session.query(model.User).all()
    for row in rows:
        output[row.login] = {
            'id': row.id,
            'name': row.name,
            'phone': row.phone,
            'email': row.email,
            'department': row.department,
            'title': row.title,
            'update_at': row.update_at
        }
    return output


def update_user(ad_user, db_user):
    args = {
        "name": None,
        "phone": None,
        "email": None,
        "title": None,
        "department": None,
        "status": "disable",
        "password": None,
        "from_ad": True
    }

    if ad_user['is_iii'] is True:
        if ad_user["iii_name"] is not None:
            args['name'] = ad_user['iii_name']
        if ad_user["telephoneNumber"] is not None:
            args['phone'] = ad_user['telephoneNumber']
        if ad_user["userPrincipalName"] is not None:
            args['email'] = ad_user['userPrincipalName']
        if ad_user["title"] is not None:
            args['title'] = ad_user['title']
        if ad_user["department"] is not None:
            args['department'] = ad_user['department']
        if ad_user["userAccountControl"] == 512:
            args['status'] = "enable"
        if ad_user['whenChanged'] is not None:
            args['update_at'] = str(ad_user['whenChanged'])
        user.update_user(db_user['id'], args, True)
    return db_user['id']


def create_user(ad_user):
    res = None
    if ad_user['is_iii'] is True and ad_user["userAccountControl"] == 512:
        args = {
            'name': ad_user['iii_name'],
            'email': ad_user['userPrincipalName'],
            'login': ad_user['sAMAccountName'],
            'password': default_password,
            'role_id': default_role_id,
            "status": "enable",
            'phone': ad_user['telephoneNumber'],
            'title': ad_user['title'],
            'department': ad_user['department'],
            'update_at': ad_user['whenChanged'],
            'from_ad': True
        }
        res = user.create_user(args)
    return res


def check_user_from_ad(ad_users):
    res = {'new': [], 'old': [], 'none': []}
    db_users = get_db_user_by_login()
    for ad_user in ad_users:
        if ad_user['sAMAccountName'] in db_users:
            res['old'].append(update_user(
                ad_user, db_users[ad_user['sAMAccountName']]))
        elif ad_user['is_iii'] is True and ad_user['institute'] in iii_institute_need_account:
            new_user = create_user(ad_user)
            if new_user is not None:
                res['new'].append(new_user)
    return res


def add_ad_user_info_by_iii(ad_user_info):
    iii_info = {'is_iii': False}
    need_attributes = ['displayName', 'telephoneNumber', 'physicalDeliveryOfficeName',
                       'givenName', 'sn', 'title', 'telephoneNumber', 'mail', 'userAccountControl', 'sAMAccountName', 'userPrincipalName',
                       'whenChanged', 'whenCreated', 'department', 'department']
    organization = ['institute', 'director', 'section']
    if 'department' in ad_user_info and 'sn' in ad_user_info and 'givenName' in ad_user_info:
        list_departments = ad_user_info['department'].split(
            '/')
        iii_info['iii_name'] = list_departments[(
            len(list_departments)-1)]+'_'+ad_user_info['sn']+ad_user_info['givenName']
        layer = 0
        for name in list_departments:
            iii_info[organization[layer]] = name
            layer += 1
        iii_info['is_iii'] = True
    for attribute in need_attributes:
        if attribute in ad_user_info:
            iii_info[attribute] = ad_user_info[attribute]
        else:
            iii_info[attribute] = None
    return iii_info


def get_user_info_from_ad(users , info = 'iii'):
    user_info = []
    for user in users:
        if info  == 'iii':
            user = add_ad_user_info_by_iii(user['attributes'])
            user_info.append(user)
        elif info == 'raw':
            user_info.append(user)
    return user_info


class AD(object):
    def __init__(self, account=None, password=None):
        self.ad_info = {
            'is_pass': False,
            'login': account,
            'data': {}
        }
        plugin = api_plugin.get_plugin('ad_server')
        if plugin is not None and plugin['disabled'] is False:
            ad_parameter = plugin['parameter']
        server = ServerPool(None, pool_strategy=FIRST, active=True)
        for host in ad_parameter['host']:
            ip, port = host['ip_port'].split(':')
            server.add(Server(host=ip, port=int(port), get_info=ALL,
                              connect_timeout=ad_connect_timeout))
        if account is None and password is None:
            account = ad_parameter['account']
            password = ad_parameter['password']
        email = account+'@'+ad_parameter['domain']
        self.server = server
        self.conn = Connection(server, user=email,
                               password=password, read_only=True)
        if self.conn.bind() is True:
            self.ad_info['is_pass'] = True
        self.active_base_dn = get_dc_string(ad_parameter['domain'].split('.'))

    def get_users(self):
        if self.ad_info['is_pass'] is True:
            user_search_filter = '(&(|(objectclass=user)(objectclass=person))(!(isCriticalSystemObject=True)))'
            self.conn.search(search_base=self.active_base_dn,
                             search_filter=user_search_filter, attributes=ALL_ATTRIBUTES)
            res = self.conn.response_to_json()
            res = json.loads(res)['entries']
        else:
            res = {'bind': self.conn.bind(), 'server': str(self.server),
                   'bind_result': str(self.conn.result)}
        return res

    def get_ous(self):
        ou_search_filter = '(&(objectclass=OrganizationalUnit)(!(isCriticalSystemObject=True)))'
        self.conn.search(search_base=self.active_base_dn,
                         search_filter=ou_search_filter, attributes=ALL_ATTRIBUTES)
        res = self.conn.response_to_json()
        res = json.loads(res)['entries']
        return res

    def get_user(self, account):
        output = None
        user_search_filter = '(&(|(objectclass=user)(objectclass=person))(!(isCriticalSystemObject=True))(sAMAccountName='+account+'))'
        if self.ad_info['is_pass'] is True:
            self.conn.search(search_base=self.active_base_dn,
                             search_filter=user_search_filter,
                             attributes=ALL_ATTRIBUTES
                             )
            res = self.conn.response_to_json()
            output = json.loads(res)['entries'][0]
        return output

    def compare_attr(self, dn, attr, value):
        res = self.conn.compare(dn=dn, attribute=attr, value=value)
        return res

    def get_user_by_ou(self):
        self.conn.search(search_base=self.active_base_dn,
                         search_filter=self.ou_search_filter, attributes=ALL_ATTRIBUTES)
        res = self.conn.response_to_json()
        res = json.loads(res)
        return res


class User(object):
    #  check User login
    def get_user_info(self, account, password):
        try:
            output = None
            ad = AD(account, password)
            user = ad.get_user(account)
            if user is not None:
                output = add_ad_user_info_by_iii(user['attributes'])
            return output
        except NoResultFound:
            return util.respond(404, invalid_ad_server,
                                error=apiError.invalid_plugin_id(invalid_ad_server))


    def get_user_raw_info(self, account, password):
        try:
            output = None
            ad = AD(account, password)
            user = ad.get_user(account)
            if user is not None:
                output = add_ad_user_info_by_iii(user['attributes'])
            return output
        except NoResultFound:
            return util.respond(404, invalid_ad_server,
                                error=apiError.invalid_plugin_id(invalid_ad_server))

    def check_ad_info(self):
        try:
            output = {}
            output['disabled'] = True
            plugin = api_plugin.get_plugin('ad_server')
            if plugin is not None:
                output = plugin
            return output
        except NoResultFound:
            return util.respond(404, invalid_ad_server,
                                error=apiError.invalid_plugin_id(invalid_ad_server))

    def login_by_ad(self, db_user, db_info, ad_info, login_account, login_password):
        status = 'Direct login by AD pass, DB pass'
        user_id = ''
        user_login = ''
        user_role_id = ''
        # 'Direct Login AD pass, DB create User'
        if db_info['connect'] is False and ad_info['data']['is_iii'] is True:
            status = 'Direct Login AD pass, DB create User'
            new_user = create_user(ad_info['data'])
            user_id = new_user['user_id']
            user_login = login_account
            user_role_id = default_role_id
        # 'Direct login AD pass,'
        elif db_info['from_ad'] is True:
            user_id = db_user.id
            user_login = db_user.login
            user_role_id = db_info['role_id']
            # 'Direct login AD pass, DB change password'
            if db_info['is_pass'] is not True:
                status = 'Direct login AD pass, DB change password'
                err = user.update_external_passwords(
                    user.id, login_password, login_password)
                if err is not None:
                    logger.exception(err)
                db_user.password = db_info['hex_password']
            db_user.name = ad_info['data']['iii_name']
            db_user.phone = ad_info['data']['telephoneNumber']
            db_user.department = ad_info['data']['department']
            db_user.title = ad_info['data']['title']
            db_user.update_at = ad_info['data']['whenChanged']
            db.session.commit()
        token = user.get_access_token(user_id, user_login, user_role_id, True)
        return status, token


ad_user = User()


class Users(Resource):
    @jwt_required
    def get(self):
        try:
            role.require_admin('Only admins can get ad users.')
            parser = reqparse.RequestParser()
            parser.add_argument('info', type=str)
            args = parser.parse_args()            
            ad = AD()
            res = ad.get_users()
            if isinstance(res, list):
                return util.success(get_user_info_from_ad(res, args['info']))
            else:
                return res
        except NoResultFound:
            return util.respond(404, invalid_ad_server,
                                error=apiError.invalid_plugin_id(invalid_ad_server))

    @jwt_required
    def post(self):
        try:
            role.require_admin('Only admins can use ad crate user.')
            ad = AD()
            ad_users = ad.get_users()
            users = get_user_info_from_ad(ad_users, 'iii')
            res = check_user_from_ad(users)
            return util.success(res)
        except NoResultFound:
            return util.respond(404, invalid_ad_server,
                                error=apiError.invalid_plugin_id(invalid_ad_server))


class Organizations(Resource):
    @jwt_required
    def get(self):
        try:
            ad = AD()
            return util.success(ad.get_ous())
        except NoResultFound:
            return util.respond(404, invalid_ad_server,
                                error=apiError.invalid_plugin_id(invalid_ad_server))
    @jwt_required
    def post(self):
        try:
            ad = AD()            
            return util.success(ad.get_ous())
        except NoResultFound:
            return util.respond(404, invalid_ad_server,
                                error=apiError.invalid_plugin_id(invalid_ad_server))
