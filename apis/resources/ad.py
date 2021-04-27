import json
import numbers
from datetime import datetime, date
from ldap3 import Server, ServerPool, Connection, SUBTREE, LEVEL, ALL, ALL_ATTRIBUTES, FIRST
import util as util
import config
import model
from model import db
from flask_jwt_extended import jwt_required, get_jwt_identity
from Cryptodome.Hash import SHA256
from flask_restful import Resource, reqparse
from sqlalchemy.orm.exc import NoResultFound
from resources.plugin import api_plugin
from resources.apiError import DevOpsError
import resources.apiError as apiError
from resources.logger import logger
from resources import user


AD_SYSTEM_ACCOUNT = 'sysadmin'
system_password = 'IIIdevops123!'

ad_connect_timeout = 5
ad_receive_timeout = 30

invalid_ad_server = 'Get AD User Error'
default_role_id = 3
default_password = 'IIIdevops_12345'


def get_dc_string(domains):
    output = ''
    for domain in domains:
        output += 'dc='+domain+','
    return output[:-1]


def create_user_from_ad(users):
    res = []
    user = db.session.query(model.User).filter(
            model.User.login == login_account).all()

    for user in users:
        status = 'Direct Login AD pass, DB create User'
        res.append({'user': user , 'status': status})
        # args = {
        #     'name': ad_info['data']['iii_name'],
        #     'email': ad_info['data']['userPrincipalName'],
        #     'login': login_account,
        #     'password': login_password,
        #     'role_id': default_role_id,
        #     'status': "enable",
        #     'phone': ad_info['data']['telephoneNumber'],
        #     'title': ad_info['data']['title'],
        #     'department': ad_info['data']['department'],
        #     'from_ad': True
        # }
        # res.append(user.create_user(args, ad_info['data']['whenChanged'])_

    return res
# def check_ad_server():
#     plugin = api_plugin.get_plugin('ad_server')

#     plugin = model.PluginSoftware.query.\
#         filter(model.PluginSoftware.name == 'ad_server').\
#         first()
#     ad_server = {
#         'ip_port': config.get('AD_IP_PORT'),
#         'domain': config.get('AD_DOMAIN'),
#         'account': config.get('AD_ACCOUNT'),
#         'password': config.get('AD_PASSWORD')
#     }
#     if plugin is not None:
#         parameters = json.loads(plugin.parameter)
#         ad_server['ip_port'] = parameters['ip_port']
#         ad_server['domain'] = parameters['domain']
#         ad_server['account'] = parameters['account']
#         ad_server['password'] = parameters['password']
#     return ad_server


def add_ad_user_info_by_iii(ad_user_info):
    iii_info = {'is_iii': False}
    need_attributes = ['displayName', 'telephoneNumber', 'physicalDeliveryOfficeName',
                       'givenName', 'sn', 'title', 'telephoneNumber', 'mail', 'userAccountControl', 'sAMAccountName', 'userPrincipalName',
                       'whenChanged', 'whenCreated', 'department']
    organization = ['institute', 'director', 'section']
    if 'physicalDeliveryOfficeName' in ad_user_info and 'sn' in ad_user_info and 'givenName' in ad_user_info:
        list_departments = ad_user_info['physicalDeliveryOfficeName'].split(
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


def get_user_info_from_ad(users):
    user_info = []
    for user in users:
        user = add_ad_user_info_by_iii(user['attributes'])
        user_info.append(user)
    return user_info


def create_ad_users(ad_users):
    new_users = []
    old_users = []
    account_disable = []
    temp = []
    if 'data' in ad_users and len(ad_users['data']) > 0:
        ad_users_info = ad_users['data']
        for user_info in ad_users_info:
            login = user_info['sAMAccountName']
            email = user_info['userPrincipalName']
            db_user = db.session.query(model.User).filter(
                (model.User.email == email) | (model.User.login == login)
            ).first()
            #  Create New User
            if db_user is None and 'iii_name' in user_info and int(user_info['userAccountControl']) == 512:
                args = {
                    'name': user_info['iii_name'],
                    'email': email,
                    'login': login,
                    'password': default_password,
                    'role_id': default_role_id,
                    'status': "enable",
                    'phone': user_info['email'],

                }
                new_users.append(user.create_user(args, True))
            elif db_user is None and 'iii_name' in user_info:
                account_disable.append(user_info)
            elif 'iii_name' in user_info:
                old_users.append(user_info)
            else:
                temp.append(user_info)
    return {
        'new_user': new_users,
        'suspend_user': account_disable,
        'old_user': old_users,
        'temp': temp
    }


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
        self.conn = Connection(server, user=email,
                               password=password, read_only=True)
        if self.conn.bind() is True:
            self.ad_info['is_pass'] = True
        self.active_base_dn = get_dc_string(ad_parameter['domain'].split('.'))

    def get_users(self):
        user_search_filter = '(&(|(objectclass=user)(objectclass=person))(!(isCriticalSystemObject=True)))'
        self.conn.search(search_base=self.active_base_dn,
                         search_filter=user_search_filter, attributes=ALL_ATTRIBUTES)
        res = self.conn.response_to_json()
        res = json.loads(res)['entries']
        return res

    def get_ous(self):
        ou_search_filter = '(&(objectclass=OrganizationalPerson)(!(isCriticalSystemObject=True)))'
        self.conn.search(search_base=self.active_base_dn,
                         search_filter=ou_search_filter, attributes=ALL_ATTRIBUTES)
        res = self.conn.response_to_json()
        res = json.loads(res)
        return res

    def get_user(self, account):
        output = None
        # 只获取【用户】对象
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
    def get_user_info(self, account, password,ad_info):
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


ad_user = User()


class Users(Resource):
    @jwt_required
    def get(self):
        try:
            print('Get Users by OU')
            ad = AD()
            return util.success(ad.get_users())
        except NoResultFound:
            return util.respond(404, invalid_ad_server,
                                error=apiError.invalid_plugin_id(invalid_ad_server))

    @jwt_required
    def post(self):
        try:
            ad = AD()
            ad_users = ad.get_users()
            users = get_user_info_from_ad(ad_users)
            res = create_user_from_ad(users)
            return util.success(res)
        except NoResultFound:
            return util.respond(404, invalid_ad_server,
                                error=apiError.invalid_plugin_id(invalid_ad_server))


class Organizations(Resource):
    @jwt_required
    def get(self):
        try:
            print("Get Organizations")
            ad = AD()
            return util.success(ad.get_ous())
        except NoResultFound:
            return util.respond(404, invalid_ad_server,
                                error=apiError.invalid_plugin_id(invalid_ad_server))
