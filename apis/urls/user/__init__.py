from . import view


def user_url(api, add_resource):
    # Project son relation
    # User
    api.add_resource(view.Login, '/user/login')
    # input api in swagger (for swagger)
    api.add_resource(view.LoginV2, '/v2/user/login')
    add_resource(view.LoginV2, "public")

    # api.add_resource(user.UserForgetPassword, '/user/forgetPassword')
    api.add_resource(view.UserStatus, '/user/<int:user_id>/status')
    api.add_resource(view.SingleUser, '/user', '/user/<int:user_id>')

    api.add_resource(view.PostSingleUserV2, '/v2/user')
    add_resource(view.PostSingleUserV2, "public")
    api.add_resource(view.GetSingleUserV2, '/v2/user/<int:user_id>')
    add_resource(view.GetSingleUserV2, "public")    

    api.add_resource(view.UserList, '/user/list')
    api.add_resource(view.UserListV2, '/v2/user/list')
    add_resource(view.UserListV2, "public")

    api.add_resource(view.UserSaConfig, '/user/<int:user_id>/config')
    
    