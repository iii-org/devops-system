import json
import ssl

from flask_jwt_extended import jwt_required
from flask_restful import Resource, reqparse, inputs
from ldap3 import Server, ServerPool, Connection, ALL_ATTRIBUTES, FIRST, Tls
from sqlalchemy.orm.exc import NoResultFound

import model
import plugins
import util as util
import resources.apiError as apiError
import resources.user as user
from model import db
from resources import role
from resources.logger import logger

invalid_ad_server = 'Get AD PLugin Server Error'
ad_connect_timeout = 1
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
        search_filter = search_filter + '(' + search_type + '=' + search_value + ')'
    if len(search_values) > 1:
        search_filter = '(|' + search_filter + ')'
    if search_filter != "":
        return search_filter
    else:
        return None


def get_search_base_string(search_type, values):
    output = ''
    for value in values:
        if value is not None:
            output += search_type + '=' + value + ','
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


def information_modified_by_ad(ad_user, db_user):
    args = {
        "name": None,
        "phone": None,
        "email": None,
        "title": None,
        "department": None,
        "password": None,
        "from_ad": True
    }
    # Modify User Name
    if ad_user.get('iii_name') != db_user.get('name'):
        args['name'] = ad_user.get('iii_name')
    # Modify Telephone Number
    if ad_user.get("telephoneNumber") != db_user.get('phone'):
        args['phone'] = ad_user.get('telephoneNumber')
    # Modify Job Title
    if ad_user.get("title") != db_user.get('title'):
        args['title'] = ad_user.get('title')
    # Modify Department
    if ad_user.get("department") != db_user.get('department'):
        args['department'] = ad_user['department']
    # Modify Update Time
    if ad_user.get('whenChanged') != db_user.get('update_at'):
        args['update_at'] = str(ad_user['whenChanged'])
    # Modify Disabled Status
    if db_user.get("disabled", None) is not None:
        if db_user.get("disabled") is True:
            args['status'] = "disabled"
        else:
            args['status'] = "enabled"
    return args


# Update User Info
def update_user_info(ad_user, db_user):
    if ad_user.get('iii') is True and ad_user.get('userPrincipalName') == db_user.get('email'):
        user.update_user(db_user['id'], information_modified_by_ad(ad_user, db_user), True)
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
            'from_ad': True,
            'force': True
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
            res['old'].append(update_user_info(
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
                       'givenName', 'sn', 'title', 'telephoneNumber', 'mail', 'userAccountControl', 'sAMAccountName',
                       'userPrincipalName', 'whenChanged', 'whenCreated', 'department', 'department']
    if 'department' in ad_user_info and 'sn' in ad_user_info and 'givenName' in ad_user_info:
        iii_info['iii_name'] = ad_user_info['sn'] + ad_user_info['givenName']
        iii_info['iii'] = True
    for attribute in need_attributes:
        if attribute in ad_user_info:
            iii_info[attribute] = ad_user_info[attribute]
        else:
            iii_info[attribute] = None
    return iii_info


def get_user_info_from_ad(info_users, info='iii'):
    list_users = []
    for info_user in info_users:
        if info == 'iii':
            list_users.append(add_ad_user_info_by_iii(info_user.get('attributes')))
        else:
            list_users.append(info_user)
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


def get_ad_server_in_db():
    ad_parameter = None
    plugin = plugins.get_plugin_config('ad')
    if plugin is not None and plugin['disabled'] is False:
        ad_parameter = get_k8s_key_value(plugin['arguments'])
    return ad_parameter


def check_ad_server_status():
    ad_parameter = get_ad_server_in_db()
    if ad_parameter is not None:
        hosts = get_ad_servers(ad_parameter.get('host', None))
    else:
        hosts = None
    return hosts, ad_parameter


def get_ad_servers(input_str):
    output = []
    if input_str is None:
        return output
    hosts = input_str.split(',')
    for host in hosts:
        if host == '':
            break
        param = host.split(':')
        if len(param) == 2:
            output.append({'hostname': param[0], 'port': int(param[1])})
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
        self.server = None
        self.server = ServerPool(None, pool_strategy=FIRST, active=True)

        hosts = get_ad_servers(ad_parameter.get('host'))
        is_ssl = bool(ad_parameter.get('ssl', False))
        # Add TLS Object
        if is_ssl:
            tls = Tls(validate=ssl.CERT_REQUIRED, version=ssl.PROTOCOL_TLSv1_2,
                      ca_certs_data=util.base64decode(ad_parameter.get('ca_certs_data')))
        for host in hosts:
            if is_ssl:
                self.server.add(Server(host=host.get('hostname'), port=host.get('port'), use_ssl=True, tls=tls,
                                       connect_timeout=ad_connect_timeout))
            else:
                self.server.add(Server(host=host.get('hostname'), port=host.get(
                    'port'), connect_timeout=ad_connect_timeout))

        if account is None and password is None:
            self.account = ad_parameter.get('account')
            self.password = ad_parameter.get('password')
        else:
            self.account = account
            self.password = password

        self.active_base_dn = generate_base_dn(ad_parameter, filter_by_ou)
        self.email = self.account + '@' + ad_parameter['domain']
        try:
            self.conn = Connection(self.server, user=self.email,
                                   password=self.password, read_only=True,
                                   receive_timeout=3,
                                   auto_referrals=False
                                   )
            if self.conn.bind() is True:
                self.ad_info['is_pass'] = True
        except NoResultFound:
            self.ad_info['is_pass'] = False

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
        target_objectclass = '(|(objectclass=user)(objectclass=person))'
        target_status_filter = '(!(isCriticalSystemObject=True))'
        search_target = '(sAMAccountName=' + account + ')'
        user_search_filter = '(&' + target_objectclass + target_status_filter + search_target + ')'
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

    def conn_unbind(self):
        return self.conn.unbind()


class ADUser(Resource):
    @ jwt_required
    def get(self):
        try:
            role.require_admin('Only admins can get ad user information.')
            parser = reqparse.RequestParser()
            parser.add_argument('account', type=str)
            parser.add_argument('ad_type', type=str)
            args = parser.parse_args()
            res = []
            hosts, ad_parameter = check_ad_server_status()
            if ad_parameter is None or len(hosts) == 0:
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
                                error=apiError.invalid_plugin_name(invalid_ad_server))

    @ jwt_required
    def post(self):
        try:
            role.require_admin('Only admins can Add ad user.')
            parser = reqparse.RequestParser()
            parser.add_argument('account', type=str)
            parser.add_argument('ad_type', type=str)
            args = parser.parse_args()
            res = []
            hosts, ad_parameter = check_ad_server_status()
            if ad_parameter is None or len(hosts) == 0:
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
                                error=apiError.invalid_plugin_name(invalid_ad_server))


ad_user = ADUser()


class ADUsers(Resource):
    @ jwt_required
    def get(self):
        try:
            res = None
            role.require_admin('Only admins can get ad users information.')
            parser = reqparse.RequestParser()
            parser.add_argument('ou', action='append')
            parser.add_argument('ad_type', type=str)
            args = parser.parse_args()
            hosts, ad_parameter = check_ad_server_status()
            if ad_parameter is None or len(hosts) == 0:
                return util.respond(404, invalid_ad_server,
                                    error=apiError.invalid_plugin_name(invalid_ad_server))
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
                                error=apiError.invalid_plugin_name(invalid_ad_server))

    def post(self):
        try:
            res = None
            parser = reqparse.RequestParser()
            parser.add_argument('ou', action='append', default=None)
            parser.add_argument('batch', type=inputs.boolean, default=False)
            parser.add_argument('ad_type', type=str)
            args = parser.parse_args()
            hosts, ad_parameter = check_ad_server_status()
            if ad_parameter is None or len(hosts) == 0:
                return res

            ad_users = []
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
                                error=apiError.invalid_plugin_name(invalid_ad_server))


ad_users = ADUsers()


class ADOrganizations(Resource):

    @ jwt_required
    def get(self):
        try:
            res = None
            hosts, ad_parameter = check_ad_server_status()
            if ad_parameter is None or len(hosts) == 0:
                return res
            ad = AD(ad_parameter)
            res = ad.get_ous()
            ad.conn_unbind()
            return util.success(res)
        except NoResultFound:
            return util.respond(404, invalid_ad_server,
                                error=apiError.invalid_plugin_name(invalid_ad_server))


organizations = ADOrganizations()


class ADAPIUser(object):
    #  check User login
    def get_user_info(self, account, password):
        try:
            output = None
            hosts, ad_parameter = check_ad_server_status()
            if ad_parameter is None or len(hosts) == 0:
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
                                error=apiError.invalid_plugin_name(invalid_ad_server))

    def check_ad_info(self):
        try:
            output = {}
            output['disabled'] = True
            plugin = plugins.get_plugin_config('ad')
            if plugin is not None:
                plugin['arguments'] = get_k8s_key_value(plugin['arguments'])
                output = plugin
            return output
        except NoResultFound:
            return util.respond(404, invalid_ad_server,
                                error=apiError.invalid_plugin_name(invalid_ad_server))

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
