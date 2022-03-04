from flask_apispec import marshal_with, doc, use_kwargs
from flask_apispec.views import MethodResource
from flask_jwt_extended import jwt_required
from flask_restful import Resource, reqparse
import util
from threading import Thread
from urls.user import router_model
from resources.user import login, change_user_status, create_user, NexusUser, delete_user, update_user, user_list, user_sa_config
from resources import harbor, role
from . import router_model
import json

# --------------------- Resources ---------------------
@doc(tags=['Login'],description='Login API')
@use_kwargs(router_model.LoginSchema, location=('json'))
@marshal_with(router_model.LoginResponse)  # marshalling
class LoginV2(MethodResource):
    # noinspection PyMethodMayBeStatic
    def post(self,**kwargs):
        return login(kwargs)

class Login(Resource):
    # noinspection PyMethodMayBeStatic
    def post(self):
        parser = reqparse.RequestParser()
        parser.add_argument('username', type=str, required=True)
        parser.add_argument('password', type=str, required=True)
        args = parser.parse_args()
        return login(args)        

class UserStatus(Resource):
    @jwt_required
    def put(self, user_id):
        role.require_admin('Only admins can modify user.')
        parser = reqparse.RequestParser()
        parser.add_argument('status', type=str, required=True)
        args = parser.parse_args()
        return change_user_status(user_id, args)



@doc(tags=['SingleUser'],description='SingleUser API')
class PostSingleUserV2(MethodResource):
    @use_kwargs(router_model.PostSingleUserSchema, location=('json'))
    @marshal_with(router_model.CreateSingleUserResponse)  # marshalling
    @jwt_required
    def post(self,**kwargs):
        role.require_admin('Only admins can create user.')
        return util.success(create_user(kwargs))



@doc(tags=['SingleUser'],description='SingleUser API')   
class GetSingleUserV2(MethodResource):
    # @use_kwargs(router_model.PostSingleUserSchema, location="query")
    # @marshal_with(router_model.SingleUserResponse)  # marshalling
    @jwt_required
    def get(self, user_id):
        print("---------------Get-------------")
        role.require_user_himself(user_id, even_pm=False,
                                  err_message="Only admin and PM can access another user's data.")
        return util.success(NexusUser().set_user_id(user_id).to_json())

    @marshal_with(router_model.SingleUserResponse)  # marshalling
    @jwt_required
    def delete(self, user_id):
        print("---------------Delete-------------")
        role.require_admin("Only admin can delete user.")
        return util.success(delete_user(user_id))

    @use_kwargs(router_model.PutSingleUserSchema, location="json")
    @marshal_with(router_model.SingleUserResponse)  # marshalling
    @jwt_required
    def put(self, user_id,**kwargs):
        print("---------------PUT-------------")
        role.require_user_himself(user_id)
        return update_user(user_id, kwargs)

class SingleUser(Resource):
    @jwt_required
    def get(self, user_id):
        role.require_user_himself(user_id, even_pm=False,
                                  err_message="Only admin and PM can access another user's data.")
        return util.success(NexusUser().set_user_id(user_id).to_json())

    @jwt_required
    def put(self, user_id):
        role.require_user_himself(user_id)
        parser = reqparse.RequestParser()
        parser.add_argument('name', type=str)
        parser.add_argument('password', type=str)
        parser.add_argument('old_password', type=str)
        parser.add_argument('phone', type=str)
        parser.add_argument('email', type=str)
        parser.add_argument('status', type=str)
        parser.add_argument('department', type=str)
        parser.add_argument('title', type=str)
        parser.add_argument('role_id', type=int)
        args = parser.parse_args()
        return update_user(user_id, args)

    @jwt_required
    def delete(self, user_id):
        role.require_admin("Only admin can delete user.")
        return util.success(delete_user(user_id))

    @jwt_required
    def post(self):
        role.require_admin('Only admins can create user.')
        parser = reqparse.RequestParser()
        parser.add_argument('name', type=str, required=True)
        parser.add_argument('email', type=str, required=True)
        parser.add_argument('phone', type=str)
        parser.add_argument('login', type=str, required=True)
        parser.add_argument('password', type=str, required=True)
        parser.add_argument('role_id', type=int, required=True)
        parser.add_argument('status', type=str)
        parser.add_argument('force', type=bool)
        args = parser.parse_args()
        return util.success(create_user(args))


class UserList(Resource):
    @jwt_required
    def get(self):
        role.require_pm()
        parser = reqparse.RequestParser()
        parser.add_argument('role_ids', type=str)
        parser.add_argument('page', type=int)
        parser.add_argument('per_page', type=int)
        parser.add_argument('search', type=str)
        args = parser.parse_args()
        filters = {}
        if args['role_ids'] is not None:
            filters['role_ids'] = json.loads(f'[{args["role_ids"]}]')
        if args['page'] is not None:
            filters['page'] = args['page']
        if args['per_page'] is not None:
            filters['per_page'] = args['per_page']
        if args['search'] is not None:
            filters['search'] = args['search']
        return util.success(user_list(filters))


@doc(tags=['UserList'],description='SingleUser API') 
class UserListV2(MethodResource):
    @use_kwargs(router_model.UserListSchema, location="query")
    @marshal_with(router_model.GetUserListResponse)  # marshalling   
    @jwt_required
    def get(self,**kwargs):
        role.require_pm()
        filters = {}
        if kwargs.get('role_ids') is not None:
            filters['role_ids'] = json.loads(f'[{kwargs.get("role_ids")}]')
        if kwargs.get('page') is not None:
            filters['page'] = kwargs.get('page')
        if kwargs.get('per_page') is not None:
            filters['per_page'] = kwargs.get('per_page')
        if kwargs.get('search') is not None:
            filters['search'] = kwargs.get('search')
        return util.success(user_list(filters))


class UserSaConfig(Resource):
    @jwt_required
    def get(self, user_id):
        role.require_user_himself(user_id, even_pm=False,
                                  err_message="Only admin and PM can access another user's data.")
        return user_sa_config(user_id)
