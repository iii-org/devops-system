from array import ArrayType
import json
import numbers
from datetime import datetime, date
from ldap3 import Server, ServerPool, Connection, SUBTREE, LEVEL, ALL, ALL_ATTRIBUTES, FIRST
import util as util
import model
from model import db
from flask_jwt_extended import jwt_required, get_jwt_identity
from flask_restful import Resource, reqparse, inputs
from sqlalchemy.orm.exc import NoResultFound
from resources import role
from resources.plugin import api_plugin
from resources.apiError import DevOpsError
import resources.apiError as apiError
from resources.logger import logger
import resources.user as user

invalid_ad_server = 'Get AD User Error'
ad_connect_timeout = 5
ad_receive_timeout = 30
default_role_id = 3
allow_user_account_control = [512, 544]


def generate_base_dn(ad_parameter, filter_by_ou=True):
    search_base = ''
    if ad_parameter.get('ou') is not None and filter_by_ou is True:
        if isinstance(ad_parameter.get('ou'), list):
            search_base += get_search_base_string('ou', ad_parameter.get('ou'))
        else:
            search_base += get_search_base_string('ou',
                                                  ad_parameter.get('ou').split(','))
    if ad_parameter.get('domain') is not None:
        search_base += get_search_base_string('dc',
                                              ad_parameter.get('domain').split('.'))
    return search_base[:-1]


def generate_search_parameter(search_type, search_values):
    search_filter = ""
    for search_value in search_values:
        search_filter = search_filter + '('+search_type+'='+search_value+')'
    if len(search_values) > 1:
        search_filter = '(|'+search_filter + ')'
    if search_filter != "":
        return search_filter
    else:
        return None


def get_search_base_string(search_type, values):
    output = ''
    for value in values:
        if value is not None:
            output += search_type+'='+value+','
    return output


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
        "password": None,
        "from_ad": True
    }
    if ad_user.get('iii') is True and ad_user.get('userPrincipalName') == db_user.get('email'):
        if ad_user.get('iii_name') != db_user.get('name'):
            args['name'] = ad_user.get('iii_name')
        if ad_user.get("telephoneNumber") != db_user.get('phone'):
            args['phone'] = ad_user.get('telephoneNumber')
        if ad_user.get("title") != db_user.get('title'):
            args['title'] = ad_user.get('title')
        if ad_user.get("department") != db_user.get('department'):
            args['department'] = ad_user['department']
        if ad_user.get('whenChanged') != db_user.get('update_at'):
            args['update_at'] = str(ad_user['whenChanged'])
        user.update_user(db_user['id'], args, True)
    return db_user['id']


def create_user(ad_user, login_password):
    res = None
    if ad_user.get('iii') is True and \
            ad_user.get("userAccountControl") in allow_user_account_control and \
            ad_user.get('userPrincipalName') is not None and \
            ad_user.get('sAMAccountName') is not None:
        args = {
            'name': ad_user.get('iii_name'),
            'email': ad_user.get('userPrincipalName'),
            'login': ad_user['sAMAccountName'],
            'password': login_password,
            'role_id': default_role_id,
            "status": "enable",
            'phone': ad_user.get('telephoneNumber'),
            'title': ad_user.get('title'),
            'department': ad_user['department'],
            'update_at': ad_user['whenChanged'],
            'from_ad': True
        }
        res = user.create_user(args)
    return res


def create_user_from_ad(ad_users, create_by=None, ad_parameter=None):
    res = {'new': [], 'old': [], 'none': []}
    users = []
    db_users = get_db_user_by_login()
    for ad_user in ad_users:
        if ad_user.get('sAMAccountName') in users:
            continue
        if ad_user.get('sAMAccountName') in db_users:
            res['old'].append(update_user(
                ad_user, db_users[ad_user.get('sAMAccountName')]))
        #  Create user
        elif ad_user.get(create_by) is True:
            new_user = create_user(
                ad_user, ad_parameter.get('default_password'))
            if new_user is not None:
                res['new'].append(new_user)
        else:
            res['none'].append(ad_user.get('sAMAccountName'))
        users.append(ad_user.get('sAMAccountName'))
    return res


def add_ad_user_info_by_iii(ad_user_info):
    iii_info = {'iii': False}
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
        iii_info['iii'] = True
    for attribute in need_attributes:
        if attribute in ad_user_info:
            iii_info[attribute] = ad_user_info[attribute]
        else:
            iii_info[attribute] = None
    return iii_info


def get_user_info_from_ad(users, info='iii'):
    list_users = []
    for user in users:
        if info == 'iii':
            user_info = add_ad_user_info_by_iii(user.get('attributes'))
            list_users.append(user_info)
        else:
            list_users.append(user)
    return list_users


def check_update_info(db_user, db_info, ad_data):
    need_change = False
    if db_info['is_pass'] is not True:
        need_change = True
    if db_user.name != ad_data['iii_name']:
        need_change = True
        db_user.name = ad_data['iii_name']
    if db_user.phone != ad_data['telephoneNumber']:
        need_change = True
        db_user.phone = ad_data['telephoneNumber']
    if db_user.department != ad_data['department']:
        need_change = True
        db_user.department = ad_data['department']
    if db_user.title != ad_data['title']:
        need_change = True
        db_user.title = ad_data['title']
    if db_user.update_at != ad_data['whenChanged']:
        need_change = True
        db_user.update_at = ad_data['whenChanged']
    if db_user.from_ad is not True:
        need_change = True
        db_user.from_ad = True
    if need_change is True:
        db.session.commit()
    return need_change


def get_k8s_key_value(parameters):
    output = {}
    for parameter in parameters:
        key = parameter.get('key')
        param_type = parameter.get('type')
        value = parameter.get('value')
        if param_type == 'int':
            value = int(value)
        output[key] = value
    return output


def check_ad_server_status():
    ad_parameter = None
    plugin = api_plugin.get_plugin('ad')
    if plugin is not None and plugin['disabled'] is False:
        ad_parameter = get_k8s_key_value(plugin['arguments'])

    return ad_parameter


def get_ad_servers(input_str):
    output = []
    if input_str is None:
        return output
    host_strs = input_str.split(',')
    for host_str in host_strs:
        if host_str == '':
            break
        param = host_str.split(':')
        if len(param) == 2:
            output.append({'ip': param[0], 'port': int(param[1])})
    return output


class AD(object):
    def __init__(self, ad_parameter, filter_by_ou=False, account=None, password=None):
        self.ad_info = {
            'is_pass': False,
            'login': account,
            'data': {}
        }
        self.account = None
        self.password = None
        self.server = ServerPool(None, pool_strategy=FIRST, active=True)
        hosts = get_ad_servers(ad_parameter.get('host'))
        for host in hosts:
            self.server.add(Server(host=host.get('ip'), port=host.get('port'), get_info=ALL,
                                   connect_timeout=ad_connect_timeout))
        if account is None and password is None:
            self.account = ad_parameter['account']
            self.password = ad_parameter['password']
        else:
            self.account = account
            self.password = password
        self.email = self.account+'@'+ad_parameter['domain']
        self.conn = Connection(self.server, user=self.email,
                               password=self.password, read_only=True)
        if self.conn.bind() is True:
            self.ad_info['is_pass'] = True
        self.active_base_dn = generate_base_dn(ad_parameter, filter_by_ou)

    def get_users(self):
        res = []
        user_search_filter = '(&(|(objectclass=user)(objectclass=person))(!(isCriticalSystemObject=True)))'
        if self.ad_info['is_pass'] is True:
            self.conn.extend.standard.paged_search(
                search_base=self.active_base_dn,
                search_filter=user_search_filter,
                attributes=ALL_ATTRIBUTES,
                paged_size=500,
                generator=False
            )
            res = self.conn.response_to_json()
            res = json.loads(res)['entries']
        return res

    def get_ous(self):
        res = []
        ou_search_filter = '(&(objectclass=OrganizationalUnit)(!(isCriticalSystemObject=True)))'
        self.conn.extend.standard.paged_search(
            search_base=self.active_base_dn,
            search_filter=ou_search_filter,
            attributes=ALL_ATTRIBUTES,
            paged_size=500,
            generator=False
        )
        res = self.conn.response_to_json()
        res = json.loads(res)['entries']
        return res

    def get_user(self, account):
        output = []
        user_search_filter = '(&(|(objectclass=user)(objectclass=person))(!(isCriticalSystemObject=True))(sAMAccountName='+account+'))'
        if self.ad_info['is_pass'] is True:
            self.conn.search(search_base=self.active_base_dn,
                             search_filter=user_search_filter,
                             attributes=ALL_ATTRIBUTES
                             )
            res = self.conn.response_to_json()
            if len(json.loads(res)['entries']) > 0:
                output = json.loads(res)['entries']
        return output

    def compare_attr(self, dn, attr, value):
        res = self.conn.compare(dn=dn, attribute=attr, value=value)
        return res

    def get_user_by_ou(self):
        self.conn.search(search_base=self.active_base_dn,
                         search_filter=self.ou_search_filter, attributes=ALL_ATTRIBUTES)
        res = self.conn.response_to_json()
        res = json.loads(res)['entries']
        return res

    def conn_unbind(self):
        return self.conn.unbind()


class ADUser(Resource):
    @jwt_required
    def get(self):
        try:
            role.require_admin('Only admins can get ad users.')
            parser = reqparse.RequestParser()
            parser.add_argument('account', type=str)
            parser.add_argument('ad_type', type=str)
            args = parser.parse_args()
            res = []
            ad_parameter = check_ad_server_status()
            if ad_parameter is None:
                return res
            ad_parameter.pop('ou')
            ad = AD(ad_parameter)
            res = ad.get_user(args['account'])
            ad.conn_unbind()
            if len(res) == 1:
                res = get_user_info_from_ad(res, args.get('ad_type'))
                return util.success(res[0])
            return util.success(res)
        except NoResultFound:
            return util.respond(404, invalid_ad_server,
                                error=apiError.invalid_plugin_id(invalid_ad_server))

    @jwt_required
    def post(self):
        try:
            role.require_admin('Only admins can get ad users.')
            parser = reqparse.RequestParser()
            parser.add_argument('account', type=str)
            parser.add_argument('ad_type', type=str)
            args = parser.parse_args()
            res = []
            ad_parameter = check_ad_server_status()
            if ad_parameter is None:
                return res
            if 'ou' in ad_parameter:
                ad_parameter.pop('ou')
            ad = AD(ad_parameter)
            res = ad.get_user(args['account'])
            ad.conn_unbind()
            if len(res) == 1:
                users = get_user_info_from_ad(res, args.get('ad_type'))
                res = create_user_from_ad(
                    users, args.get('ad_type'), ad_parameter)
            return util.success(res)
        except NoResultFound:
            return util.respond(404, invalid_ad_server,
                                error=apiError.invalid_plugin_id(invalid_ad_server))


ad_user = ADUser()


class ADUsers(Resource):
    @jwt_required
    def get(self):
        try:
            res = None
            role.require_admin('Only admins can get ad users.')
            parser = reqparse.RequestParser()
            parser.add_argument('ou', action='append')
            parser.add_argument('ad_type', type=str)
            args = parser.parse_args()
            ad_parameter = check_ad_server_status()
            if ad_parameter is None:
                return util.respond(404, invalid_ad_server,
                                    error=apiError.invalid_plugin_id(invalid_ad_server))
            if args.get('ou') is not None:
                ad_parameter['ou'] = args.get('ou')
            ad = AD(ad_parameter, True)
            res = ad.get_users()
            ad.conn_unbind()
            if isinstance(res, list):
                return util.success(get_user_info_from_ad(res, args.get('ad_type')))
            else:
                return res
        except NoResultFound:
            return util.respond(404, invalid_ad_server,
                                error=apiError.invalid_plugin_id(invalid_ad_server))
    def post(self):
        try:
            res = None
            parser = reqparse.RequestParser()
            parser.add_argument('ou', action='append', default=None)
            parser.add_argument('batch', type=inputs.boolean, default=False)
            parser.add_argument('ad_type', type=str)
            args = parser.parse_args()
            ad_parameter = check_ad_server_status()
            ad_users = []
            if ad_parameter is None:
                return res
            if args.get('ou') is not None and args.get('batch') is False:
                ad_parameter['ou'] = args.get('ou')
                ad = AD(ad_parameter, True)
                ad_users = ad.get_users()
            else:
                ous = ad_parameter.get('ou')
                if isinstance(ous, str):
                    ous = ous.split(',')
                for ou in ous:
                    ad_parameter['ou'] = [ou]
                    ad = AD(ad_parameter, True)
                    ad_users.extend(ad.get_users())
                    ad.conn_unbind()
            if len(ad_users) != 0:
                users = get_user_info_from_ad(ad_users, args.get('ad_type'))
                res = create_user_from_ad(
                    users, args.get('ad_type'), ad_parameter)
            return util.success(res)
        except NoResultFound:
            return util.respond(404, invalid_ad_server,
                                error=apiError.invalid_plugin_id(invalid_ad_server))


ad_users = ADUsers()


class ADOrganizations(Resource):

    @jwt_required
    def get(self):
        try:
            res = None
            ad_parameter = check_ad_server_status()
            if ad_parameter is None:
                return res
            ad = AD(ad_parameter)
            res = ad.get_ous()
            ad.conn_unbind()
            return util.success(res)
        except NoResultFound:
            return util.respond(404, invalid_ad_server,
                                error=apiError.invalid_plugin_id(invalid_ad_server))


organizations = ADOrganizations()


class ADAPIUser(object):
    #  check User login
    def get_user_info(self, account, password):
        try:
            output = None
            ad_parameter = check_ad_server_status()
            if ad_parameter is None:
                return output
            ad = AD(ad_parameter, False, account, password)
            user = ad.get_user(account)
            ad.conn_unbind()
            if len(user) > 0:
                user = user[0]
                output = add_ad_user_info_by_iii(user['attributes'])
            return output
        except NoResultFound:
            return util.respond(404, invalid_ad_server,
                                error=apiError.invalid_plugin_id(invalid_ad_server))

    def get_user_raw_info(self, account, password):
        try:
            output = None
            ad_parameter = check_ad_server_status()
            if ad_parameter is None:
                return output
            ad = AD(ad_parameter, False, account, password)
            user = ad.get_user(account)
            ad.conn_unbind()
            if len(user) > 0:
                user = user[0]
                output = add_ad_user_info_by_iii(user['attributes'])
            return output
        except NoResultFound:
            return util.respond(404, invalid_ad_server,
                                error=apiError.invalid_plugin_id(invalid_ad_server))

    def check_ad_info(self):
        try:
            output = {}
            output['disabled'] = True
            plugin = api_plugin.get_plugin('ad')
            if plugin is not None:
                plugin['arguments'] = get_k8s_key_value(plugin['arguments'])
                output = plugin
            return output
        except NoResultFound:
            return util.respond(404, invalid_ad_server,
                                error=apiError.invalid_plugin_id(invalid_ad_server))

    def login_by_ad(self, db_user, db_info, ad_info, login_account, login_password):
        status = 'Direct login by AD pass, DB pass'
        ad_info_data = ad_info['data']
        token = None
        # 'Direct Login AD pass, DB create User'
        if db_info['connect'] is False and ad_info_data['iii'] is True:
            status = 'Direct Login AD pass, DB create User'
            new_user = create_user(ad_info_data, login_password)
            if new_user is None:
                status = 'Direct login AD pass, Create User Fail'
                return status, token
            user_id = new_user['user_id']
            user_login = login_account
            user_role_id = default_role_id
            token = user.get_access_token(
                user_id, user_login, user_role_id, True)
        # 'Direct login AD pass,'
        elif ad_info_data['iii'] is True and ad_info_data['userPrincipalName'] == db_user.email:
            user_id = db_user.id
            user_login = db_user.login
            user_role_id = db_info['role_id']
            # 'Direct login AD pass, DB change password'
            if db_info['is_pass'] is not True:
                status = 'Direct login AD pass, DB change password'
                err = user.update_external_passwords(
                    db_user.id, login_password, login_password)
                if err is not None:
                    logger.exception(err)
                db_user.password = db_info['hex_password']
            # Check Need Update User Info
            check_update_info(db_user, db_info, ad_info_data)
            token = user.get_access_token(
                user_id, user_login, user_role_id, True)
        else:
            status = 'Not allow ad Account'
        return status, token


ad_api_user = ADAPIUser()
