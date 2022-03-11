import json
import ssl

from flask_jwt_extended import jwt_required
from flask_restful import Resource, reqparse, inputs
from ldap3 import Server, ServerPool, Connection, ALL_ATTRIBUTES, FIRST, Tls
from sqlalchemy.orm.exc import NoResultFound
import dateutil
import pytz

import model
import plugins
import util as util
import resources.apiError as apiError
import resources.user as user_function

from model import db
from resources import role
from resources.logger import logger

invalid_ad_server = 'Get AD PLugin Server Error'
ad_connect_timeout = 1
default_role_id = 3
USER_ACCOUNT_CONTROL_ACTIVE = [512, 544, 66048, 660080]
USER_ACCOUNT_CONTROL_DEACTIVATE = [516, 546, 66050, 66082]


def generate_base_dn(ldap_parameter, filter_by_ou=True):
    search_base = ''
    if ldap_parameter.get('ou') is not None and filter_by_ou is True:
        if isinstance(ldap_parameter.get('ou'), list):
            search_base += get_search_base_string('ou', ldap_parameter.get('ou'))
        else:
            search_base += get_search_base_string('ou',
                                                  ldap_parameter.get('ou').split(','))
    if ldap_parameter.get('domain') is not None:
        search_base += get_search_base_string('dc',
                                              ldap_parameter.get('domain').split('.'))
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


def row_to_dictionary(row):
    return {
        'id': row.id,
        'login': row.login,
        'name': row.name,
        'phone': row.phone,
        'email': row.email,
        'department': row.department,
        'title': row.title,
        'password': row.password,
        'update_at': row.update_at,
        'disabled': row.disabled,
        'from_ad': row.from_ad
    }


def get_db_user_by_login(login=None):
    output = {}
    if login:
        rows = db.session.query(model.User).filter(model.User.login == login).all()
    else:
        rows = db.session.query(model.User).all()
    for row in rows:
        output[row.login] = row_to_dictionary(row)
    return output


# Check is need update user from III ad user
def check_update_info_by_ad(ad_user, db_user, login_password=None):
    data = {
        "name": None,
        "phone": None,
        "email": None,
        "title": None,
        "department": None,
        "password": None,
        "update_at": db_user.get('update_at'),
        "from_ad": True
    }
    need_change = False
    # User Not specified
    if ad_user.get('iii') is not True or ad_user.get('userPrincipalName') != db_user.get('email'):
        return need_change, data

    # Modify User Name
    if ad_user.get('iii_name') != db_user.get('name'):
        data['name'] = ad_user.get('iii_name')
        need_change = True
    # Modify Telephone Number
    if ad_user.get("telephoneNumber") != db_user.get('phone'):
        data['phone'] = ad_user.get('telephoneNumber')
        need_change = True
    #  Modify Department
    if ad_user.get("department") != db_user.get('department'):
        data['department'] = ad_user['department']
        need_change = True

    # Modify Job Title
    if ad_user.get("title") != db_user.get('title'):
        data['title'] = ad_user.get('title')
        need_change = True

    # Check Need Update Password
    if login_password is not None:
        data['old_password'] = 'FakePassword'
        data['password'] = login_password
        need_change = True

    # Modify Update Time by time object
    db_update = {}
    if db_user.get('update_at') is not None:
        db_update = pytz.timezone('UTC').localize(dateutil.parser.parse(str(db_user.get('update_at'))))
    ad_update = dateutil.parser.parse(ad_user.get('whenChanged'))
    if ad_update != db_update:
        data['update_at'] = str(ad_update)
        need_change = True

    # Check LDAP User Account  Disabled Status
    is_deactivate_user = True
    if ad_user.get('userAccountControl') in USER_ACCOUNT_CONTROL_ACTIVE:
        is_deactivate_user = False
    if db_user.get("disabled", None) is None or db_user.get("disabled") != is_deactivate_user:
        need_change = True
        if is_deactivate_user:
            data['status'] = "disable"
        else:
            data['status'] = "enable"
    return need_change, data


def check_update_info(db_user, db_info, ad_data):
    need_change = False
    if db_info['is_pass'] is not True:
        need_change = True
    if db_user.name != ad_data.get('iii_name'):
        need_change = True
        db_user.name = ad_data.get('iii_name')
    if db_user.phone != ad_data.get('telephoneNumber'):
        need_change = True
        db_user.phone = ad_data.get('telephoneNumber')
    if db_user.department != ad_data.get('department'):
        need_change = True
        db_user.department = ad_data.get('department')
    if db_user.title != ad_data.get('title'):
        need_change = True
        db_user.title = ad_data.get('title')
    if db_user.update_at != ad_data.get('whenChanged'):
        need_change = True
        db_user.update_at = ad_data.get('whenChanged')
    if db_user.from_ad is not True:
        need_change = True
        db_user.from_ad = True
    if need_change is True:
        db.session.commit()
    return need_change


def create_user(ad_user, login_password):
    res = None
    login = ad_user.get('sAMAccountName')
    if ad_user.get('iii') is True and \
            ad_user.get("userAccountControl") in USER_ACCOUNT_CONTROL_ACTIVE and \
            ad_user.get('userPrincipalName') is not None and \
            login is not None:
        args = {
            'name': ad_user.get('iii_name'),
            'email': ad_user.get('userPrincipalName'),
            'login': login,
            'password': login_password,
            'role_id': default_role_id,
            "status": "enable",
            'phone': ad_user.get('telephoneNumber'),
            'title': ad_user.get('title'),
            'department': ad_user.get('department'),
            'update_at': ad_user.get('whenChanged'),
            'from_ad': True,
            'force': True
        }
        res = user_function.create_user(args)
    return res


def check_user_by_ad(ad_users, db_users,  create_by=None, ldap_parameter=None):
    res = {'new': [], 'update': [], 'delete': [], 'nothing': [], 'none': []}
    users = []
    for ad_user in ad_users:
        login = ad_user.get('sAMAccountName')
        if login in users:
            continue
        elif login in db_users:
            is_update, update_data = check_update_info_by_ad(ad_user, db_users.get(login))
            if is_update:
                user_function.update_user(db_users.get(login).get('id'), update_data, True)
                res['update'].append(login)
            else:
                res['nothing'].append(login)
            db_users.pop(login)
        #  Create user
        elif ad_user.get(create_by) is True:
            new_user = create_user(
                ad_user, ldap_parameter.get('default_password'))
            if new_user is not None:
                res['new'].append(new_user)
        else:
            res['none'].append(login)
        users.append(login)

    # Auto Delete User from ad and not in AD
    res['delete'] = remove_user_in_db_not_in_ad(db_users)
    return res


def remove_user_in_db_not_in_ad(db_users):
    res = []
    hosts, ldap_parameter = check_ad_server_status()
    if ldap_parameter is None or len(hosts) == 0:
        return res
    ldap_parameter.pop('ou')
    ad = AD(ldap_parameter)
    for key, item in db_users.items():
        if not item.get('from_ad'):
            continue
        res_ad = ad.get_user(key)
        if len(res_ad) == 0:
            user_function.delete_user(item.get('id'))
            res.append(key)
    return res


def add_ad_user_info_by_iii(ad_user_info):
    iii_info = {'iii': False}
    need_attributes = [
        'displayName',
        'telephoneNumber',
        'physicalDeliveryOfficeName',
        'givenName',
        'sn',
        'title',
        'telephoneNumber',
        'mail',
        'userAccountControl',
        'sAMAccountName',
        'userPrincipalName',
        'whenChanged',
        'whenCreated',
        'department'
    ]
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
    ldap_parameter = None
    plugin = plugins.get_plugin_config('ad')
    if plugin is not None and plugin['disabled'] is False:
        ldap_parameter = get_k8s_key_value(plugin['arguments'])
    return ldap_parameter


def check_ad_server_status():
    ldap_parameter = get_ad_server_in_db()
    if ldap_parameter is not None:
        hosts = get_ad_servers(ldap_parameter.get('host', None))
    else:
        hosts = None
    return hosts, ldap_parameter


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
    def __init__(self, ldap_parameter, filter_by_ou=False, account=None, password=None):
        self.ad_info = {
            'is_pass': False,
            'login': account,
            'data': {}
        }
        self.account = None
        self.password = None
        self.server = None
        self.server = ServerPool(None, pool_strategy=FIRST, active=True)

        hosts = get_ad_servers(ldap_parameter.get('host'))
        is_ssl = bool(ldap_parameter.get('ssl', False))
        # SSL Validate Method [ssl.CERT_NONE, ssl.CERT_OPTIONAL, ssl.CERT_REQUIRED]:
        ssl_validate_str = ldap_parameter.get('ssl_validate', 'REQUIRED')
        if ssl_validate_str == 'REQUIRED':
            ssl_validate = ssl.CERT_REQUIRED
        elif ssl_validate_str == 'OPTIONAL':
            ssl_validate = ssl.CERT_OPTIONAL
        else:
            ssl_validate = ssl.CERT_NONE

        # Add TLS Object
        if is_ssl:
            tls = Tls(validate=ssl_validate, version=ssl.PROTOCOL_TLSv1_2,
                      ca_certs_data=util.base64decode(ldap_parameter.get('ca_certs_data')))
        for host in hosts:
            if is_ssl:
                self.server.add(Server(host=host.get('hostname'), port=host.get('port'), use_ssl=True, tls=tls,
                                       connect_timeout=ad_connect_timeout))
            else:
                self.server.add(Server(host=host.get('hostname'), port=host.get(
                    'port'), connect_timeout=ad_connect_timeout))

        if account is None and password is None:
            self.account = ldap_parameter.get('account')
            self.password = ldap_parameter.get('password')
        else:
            self.account = account
            self.password = password

        self.active_base_dn = generate_base_dn(ldap_parameter, filter_by_ou)
        self.email = self.account + '@' + ldap_parameter['domain']
        try:
            self.conn = Connection(self.server, user=self.email,
                                   password=self.password, read_only=True,
                                   receive_timeout=3,
                                   auto_referrals=False
                                   )
            if self.conn.bind() is True:
                self.ad_info['is_pass'] = True
            else:
                logger.info(f'User Login Error by AD  :{self.account}')
        except NoResultFound:
            logger.info(f'User Login Unexpected Error by AD  :{self.account}')
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
            self.conn.search(
                search_base=self.active_base_dn,
                search_filter=user_search_filter,
                attributes=ALL_ATTRIBUTES
            )
            res = self.conn.response_to_json()
            if len(json.loads(res)['entries']) > 0:
                output = json.loads(res)['entries']
        return output

    def conn_unbind(self):
        return self.conn.unbind()


class SingleADUser(Resource):
    @ jwt_required
    def get(self):
        try:
            role.require_admin('Only admins can get ad user information.')
            parser = reqparse.RequestParser()
            parser.add_argument('account', type=str)
            parser.add_argument('ad_type', type=str)
            args = parser.parse_args()
            res = []
            hosts, ldap_parameter = check_ad_server_status()
            if ldap_parameter is None or len(hosts) == 0:
                return res
            ldap_parameter.pop('ou')
            ad = AD(ldap_parameter)
            res = ad.get_user(args.get('account'))
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
            hosts, ldap_parameter = check_ad_server_status()
            if ldap_parameter is None or len(hosts) == 0:
                return res
            if 'ou' in ldap_parameter:
                ldap_parameter.pop('ou')
            ad = AD(ldap_parameter)
            res = ad.get_user(args.get('account'))
            ad.conn_unbind()
            db_user = get_db_user_by_login(args.get('account'))
            if len(res) == 1:
                user = get_user_info_from_ad(res, args.get('ad_type'))
                res = check_user_by_ad(
                    user,
                    db_user,
                    args.get('ad_type'),
                    ldap_parameter)
            return util.success(res)
        except NoResultFound:
            return util.respond(404, invalid_ad_server,
                                error=apiError.invalid_plugin_name(invalid_ad_server))


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
            hosts, ldap_parameter = check_ad_server_status()
            if ldap_parameter is None or len(hosts) == 0:
                return util.respond(404, invalid_ad_server,
                                    error=apiError.invalid_plugin_name(invalid_ad_server))
            if args.get('ou') is not None:
                ldap_parameter['ou'] = args.get('ou')
            ad = AD(ldap_parameter, True)
            res = ad.get_users()
            ad.conn_unbind()
            if isinstance(res, list):
                return util.success(get_user_info_from_ad(res, args.get('ad_type')))
            else:
                return res
        except NoResultFound:
            return util.respond(404, invalid_ad_server,
                                error=apiError.invalid_plugin_name(invalid_ad_server))

    #  automate create or update user info
    def post(self):
        try:
            res = None
            parser = reqparse.RequestParser()
            parser.add_argument('ou', action='append', default=None)
            parser.add_argument('batch', type=inputs.boolean, default=False)
            parser.add_argument('ad_type', type=str)
            args = parser.parse_args()
            hosts, ldap_parameter = check_ad_server_status()
            if ldap_parameter is None or len(hosts) == 0:
                return res
            users = []
            if args.get('ou') is not None and args.get('batch') is False:
                ldap_parameter['ou'] = args.get('ou')
                ad = AD(ldap_parameter, True)
                users = ad.get_users()
            else:
                ous = ldap_parameter.get('ou')
                if isinstance(ous, str):
                    ous = ous.split(',')
                # Foreach Look
                for ou in ous:
                    ldap_parameter['ou'] = [ou]
                    ad = AD(ldap_parameter, True)
                    users.extend(ad.get_users())
                    ad.conn_unbind()
            db_user = get_db_user_by_login()
            if len(users) != 0:
                res = check_user_by_ad(
                    get_user_info_from_ad(users, args.get('ad_type')),
                    db_user,
                    args.get('ad_type'),
                    ldap_parameter
                )

            return util.success(res)
        except NoResultFound:
            return util.respond(404, invalid_ad_server,
                                error=apiError.invalid_plugin_name(invalid_ad_server))


class ADOrganizations(Resource):
    @ jwt_required
    def get(self):
        try:
            res = None
            hosts, ldap_parameter = check_ad_server_status()
            if ldap_parameter is None or len(hosts) == 0:
                return res
            ad = AD(ldap_parameter)
            res = ad.get_ous()
            ad.conn_unbind()
            return util.success(res)
        except NoResultFound:
            return util.respond(404, invalid_ad_server,
                                error=apiError.invalid_plugin_name(invalid_ad_server))


class LDAP(object):
    #  check User login
    def get_user_info(self, account, password):
        try:
            output = None
            hosts, ldap_parameter = check_ad_server_status()
            if ldap_parameter is None or len(hosts) == 0:
                return output
            ad = AD(ldap_parameter, False, account, password)
            user = ad.get_user(account)
            ad.conn_unbind()
            if len(user) > 0:
                user = user[0]
                output = add_ad_user_info_by_iii(user['attributes'])
            else:
                logger.info(f'User Login Error by AD by Account: {account}')
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
        ad_info_data = ad_info.get('data')
        token = None
        # 'Direct Login AD pass, DB create User'
        if db_info['connect'] is False and ad_info_data.get('iii') is True:
            status = 'Direct Login AD pass, DB create User'
            new_user = create_user(ad_info_data, login_password)
            if new_user is None:
                status = 'Direct login AD pass, Create User Fail'
                return status, token
            user_id = new_user['user_id']
            user_login = login_account
            user_role_id = default_role_id
            token = user_function.get_access_token(
                user_id, user_login, user_role_id, True)
        # 'Direct login AD pass,'
        elif ad_info_data.get('iii') is True and \
                ad_info_data.get('userPrincipalName') == db_user.email:
            db_info['User'] = row_to_dictionary(db_user)
            user_id = db_user.id
            user_login = db_user.login
            user_role_id = db_info.get('role_id')
            # login Password not Change
            if db_info.get('is_password_verify'):
                login_password = None
            is_update, update_data = check_update_info_by_ad(ad_info_data, db_info.get('User'), login_password)
            # 'Direct login AD pass, DB Need Update Info'
            if is_update:
                status = 'Direct login AD pass, DB Need Update Info'
                user_function.update_user(db_info.get('User').get('id'), update_data, True)
            token = user_function.get_access_token(
                user_id, user_login, user_role_id, True)
        else:
            status = 'Not allow ad Account'
        return status, token


ldap_api = LDAP()
