import json
import numbers
from datetime import datetime, date
from ldap3 import Server, Connection, ObjectDef, Reader, SUBTREE, LEVEL, ALL, ALL_ATTRIBUTES, ALL_OPERATIONAL_ATTRIBUTES
import util as util
import config
import model
from model import db
from flask_jwt_extended import jwt_required, get_jwt_identity
from Cryptodome.Hash import SHA256
from flask_restful import Resource, reqparse
from sqlalchemy.orm.exc import NoResultFound
from resources.apiError import DevOpsError
import resources.apiError as apiError
from resources.logger import logger
from resources import user

login_account = 'sysadmin'
login_password = 'IIIdevops123!'
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


def check_ad_server():
    ad_server = {
        'ip_port': config.get('AD_IP_PORT'),
        'domain': config.get('AD_DOMAIN')
    }
    plugin = model.PluginSoftware.query.\
        filter(model.PluginSoftware.name == 'ad_server').\
        first()
    if plugin is not None:
        parameters = json.loads(plugin.parameter)
        ad_server['ip_port'] = parameters['ip_port']
        ad_server['domain'] = parameters['domain']
    return ad_server


def get_ad_users_info(server_info, account, password):
    ad_info = {'is_pass': False,
               'login': account, 'data': {}}
    if server_info['ip_port'] is not None and server_info['domain'] is not None:
        ad_info['exists'] = True
    else:
        ad_info['exists'] = False
        return ad_info
    try:
        ip, port = server_info['ip_port'].split(':')
        email = account+'@'+server_info['domain']
        server = Server(host=ip, port=int(port), get_info=ALL,
                        connect_timeout=ad_connect_timeout)
        conn = Connection(server, user=email,
                          password=password, read_only=True)
        if conn.bind() is False:
            logger.info("User Login Failed by AD: {0}".format(account))
        search_filter = '(!(isCriticalSystemObject=True))'
        search_domain = get_dc_string(server_info['domain'].split('.'))
        # person = ObjectDef(['user','person','organizationalPerson', 'top'], conn)
        person = ObjectDef(['user'], conn)
        person +='sAMAccountName'
        r = Reader(conn, person, search_domain, search_filter)
        r.search_subtree()
        exclusive_attributes = ['replPropertyMetaData', 'allowedAttributes',
                                'msDS-ReplAttributeMetaData', 'allowedAttributesEffective']
        organization = ['institue', 'director', 'section']
        ad_info['is_pass'] = True
        ad_info['data'] = []
        for entry in r.entries:
            info = {}
            for attribute in entry.entry_attributes:
                if hasattr(entry, attribute) and getattr(entry, attribute).value is not None and attribute not in exclusive_attributes:
                    value = getattr(entry, attribute).value
                    if type(value) is date:
                        info[attribute] = value
                    else:
                        info[attribute] = str(value)
            if 'department' in info and 'sn' in info and 'givenName' in info:
                list_departments = info['department'].split('/')
                info['account_name'] = list_departments[(
                    len(list_departments)-1)]+'_'+info['sn']+info['givenName']
                layer = 0
                for name in list_departments:
                    info[organization[layer]] = name
                    layer += 1
            ad_info['data'].append(info)
        return ad_info
    except Exception as e:
        raise DevOpsError(500, 'Error when AD Login ',
                          error=apiError.uncaught_exception(e))


def get_ad_users():
    server = check_ad_server()
    ad_info = get_ad_users_info(server, login_account, login_password)
    return ad_info


def create_ad_users():
    ad_info = get_ad_users()
    new_users = []
    old_users = []
    account_disable = []
    temp = []
    if 'data' in ad_info and len(ad_info['data']) > 0:
        users_info = ad_info['data']        
        for user_info in users_info:
            print(user_info['userPrincipalName'])
            login = user_info['sAMAccountName']
            email = user_info['userPrincipalName']
            db_user = db.session.query(model.User).filter(
                (model.User.email == email) | (model.User.login == login)
            ).first()
            #  Create New User
            if db_user is None and 'account_name' in user_info and int(user_info['userAccountControl']) == 512:
                args = {
                    'name': user_info['account_name'],
                    'email': email,
                    'login': login,
                    'password': default_password,
                    'role_id': default_role_id,
                    'status': "enable",
                    'phone': ''
                }
                new_users.append(user.create_user(args))
            elif db_user is None and 'account_name' in user_info:
                account_disable.append(user_info)
            elif 'account_name' in user_info:
                old_users.append(user_info)                
            else:
                temp.append(user_info)
    return {
        'new_user': new_users,
        'suspend_user': account_disable,
        'old_user': old_users,
        'temp': temp
    }


class Users(Resource):
    @jwt_required
    def get(self):
        try:
            print("Get Users")
            return util.success(get_ad_users())
        except NoResultFound:
            return util.respond(404, invalid_ad_server,
                                error=apiError.invalid_plugin_id(invalid_ad_server))

    @jwt_required
    def post(self):
        try:
            print("Create Users")
            return util.success(create_ad_users())
        except NoResultFound:
            return util.respond(404, invalid_ad_server,
                                error=apiError.invalid_plugin_id(invalid_ad_server))


class organizational(Resource):
    @jwt_required
    def get(self):
        try:
            print("Get Users")
            return util.success(get_ad_users())
        except NoResultFound:
            return util.respond(404, invalid_ad_server,
                                error=apiError.invalid_plugin_id(invalid_ad_server))

