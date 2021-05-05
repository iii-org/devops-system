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
allow_user_account_control = [512, 544]
III_INSTITUTE_NEED_ACCOUT = [
    '系統所',
    '智慧系統研究所',
    '數位所',
    '數位轉型研究所',
    '資安所',
    '資安科技研究所',    
    '服創所',
    '數位服務創新研究所',
    '資訊處', 
    '資訊服務處',
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
        if ad_user["userAccountControl"] in allow_user_account_control :
            args['status'] = "enable"
        if ad_user['whenChanged'] is not None:
            args['update_at'] = str(ad_user['whenChanged'])
        user.update_user(db_user['id'], args, True)
    return db_user['id']


def create_user(ad_user, login_password = default_password):
    res = None
    if ad_user['is_iii'] is True and \
        ad_user["userAccountControl"] in allow_user_account_control and \
        ad_user['userPrincipalName'] is not None and \
        ad_user['sAMAccountName'] is not None  :
        args = {
            'name': ad_user['iii_name'],
            'email': ad_user['userPrincipalName'],
            'login': ad_user['sAMAccountName'],
            'password': login_password,
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


def create_user_from_ad(ad_users, list_departments = None):
    if list_departments is None:
        list_departments = III_INSTITUTE_NEED_ACCOUT
    res = {'new': [], 'old': [], 'none': []}
    db_users = get_db_user_by_login()
    for ad_user in ad_users:               
        #  Update Exist User 
        if ad_user['sAMAccountName'] in db_users:
            res['old'].append(update_user(
                ad_user, db_users[ad_user['sAMAccountName']]))        
        #  Create user
        elif ad_user['is_iii'] is True and ad_user['institute'] in list_departments:            
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
    list_users = []
    for user in users:
        if info  == 'iii':
            user_info = add_ad_user_info_by_iii(user['attributes'])
            list_users.append(user_info)
        elif info == 'raw':
            list_users.append(user_info)
    return list_users



def check_update_info(db_user,db_info, ad_data):
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

def check_ad_server_status():
    ad_parameter = None
    plugin = api_plugin.get_plugin('ad_server')   
    if plugin is not None and plugin['disabled'] is False:
        ad_parameter = plugin['parameter']
    return ad_parameter
    

class AD(object):
    def __init__(self, ad_parameter, account=None, password=None):
        self.ad_info = {
            'is_pass': False,
            'login': account,
            'data': {}
        }    
        self.account= None
        self.password= None
        self.server = ServerPool(None, pool_strategy=FIRST, active=True)
        for host in ad_parameter['host']:
            ip, port = host['ip_port'].split(':')
            self.server.add(Server(host=ip, port=int(port), get_info=ALL,
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
        self.active_base_dn = get_dc_string(ad_parameter['domain'].split('.'))

    def get_users(self):
        res = []
        if self.ad_info['is_pass'] is True:
            user_search_filter = '(&(|(objectclass=user)(objectclass=person))(!(isCriticalSystemObject=True)))'
            self.conn.search(search_base=self.active_base_dn,
                             search_filter=user_search_filter, attributes=ALL_ATTRIBUTES)
            res = self.conn.response_to_json()
            res = json.loads(res)['entries']
        return res

    def get_ous(self):
        res = []
        ou_search_filter = '(&(objectclass=OrganizationalUnit)(!(isCriticalSystemObject=True)))'
        self.conn.search(search_base=self.active_base_dn,
                         search_filter=ou_search_filter, attributes=ALL_ATTRIBUTES)
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
        # user_search_filter_by_ou = '(&(|(objectclass=user)(objectclass=person))(!(isCriticalSystemObject=True))(sAMAccountName='+account+'))'
        self.conn.search(search_base=self.active_base_dn,
                         search_filter=self.ou_search_filter, attributes=ALL_ATTRIBUTES)
        res = self.conn.response_to_json()
        res = json.loads(res)['entries']
        return res

    def conn_unbind(self):
        return self.conn.unbind()


class User(Resource):
    @jwt_required
    def get(self):
        try:
            role.require_admin('Only admins can get ad users.')
            parser = reqparse.RequestParser()
            parser.add_argument('account', type=str)
            parser.add_argument('info', type=str)
            args = parser.parse_args()
            res = []
            ad_parameter = check_ad_server_status()
            if ad_parameter is None:
                return res    
            ad = AD(ad_parameter)           
            res = ad.get_user(args['account'])
            ad.conn_unbind()
            if len(res) == 1:
                if args['info'] == 'iii' : 
                    res = get_user_info_from_ad(res, 'iii')                        
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
            parser.add_argument('info', type=str)
            args = parser.parse_args()            
            res = []
            ad_parameter = check_ad_server_status()
            if ad_parameter is None:
                return res    
            ad = AD(ad_parameter)
            res = ad.get_user(args['account'])
            ad.conn_unbind()
            if len(res) == 1:
                users = get_user_info_from_ad(res, 'iii')            
                res = create_user_from_ad(users)
            return util.success(res)
        except NoResultFound:
            return util.respond(404, invalid_ad_server,
                                error=apiError.invalid_plugin_id(invalid_ad_server))



class Users(Resource):
    @jwt_required
    def get(self):
        try:
            res = None
            role.require_admin('Only admins can get ad users.')
            parser = reqparse.RequestParser()
            parser.add_argument('info', type=str)
            args = parser.parse_args()            
            ad_parameter = check_ad_server_status()
            if ad_parameter is None:
                return res    
            ad = AD(ad_parameter)
            res = ad.get_users()
            ad.conn_unbind()
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
            parser = reqparse.RequestParser()
            parser.add_argument('departments', action='append')            
            args = parser.parse_args()   
            res = None
            ad_parameter = check_ad_server_status()
            if ad_parameter is None:
                return res    
            ad = AD(ad_parameter)
            ad_users = ad.get_users()       
            users = get_user_info_from_ad(ad_users, 'iii')
            res = create_user_from_ad(users, args['departments'])
            ad.conn_unbind()
            return util.success(res)
        except NoResultFound:
            return util.respond(404, invalid_ad_server,
                                error=apiError.invalid_plugin_id(invalid_ad_server))


class Organizations(Resource):
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
    @jwt_required
    def post(self):
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


class APIUser(object):
    #  check User login
    def get_user_info(self, account, password):
        try:
            output = None
            ad_parameter = check_ad_server_status()
            if ad_parameter is None:
                return output    
            ad = AD(ad_parameter, account, password)
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
            ad = AD(ad_parameter, account, password)
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
            plugin = api_plugin.get_plugin('ad_server')
            if plugin is not None:
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
        if db_info['connect'] is False and ad_info_data['is_iii'] is True:
            status = 'Direct Login AD pass, DB create User'
            new_user = create_user(ad_info_data, login_password)
            if new_user is None:
                status = 'Direct login AD pass, Create User Fail'
                return status, token
            user_id = new_user['user_id']
            user_login = login_account
            user_role_id = default_role_id
            token = user.get_access_token(user_id, user_login, user_role_id, True)
        # 'Direct login AD pass,'
        elif ad_info_data['is_iii'] is True and ad_info_data['userPrincipalName'] == db_user.email:
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
            check_update_info(db_user,db_info, ad_info_data)
            token = user.get_access_token(user_id, user_login, user_role_id, True)
        else :
            status = 'Not allow ad Account'
            
        return status, token

ad_user = APIUser()
