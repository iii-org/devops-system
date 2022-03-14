from . import view


def router_url(api, add_resource):

    # Router
    api.add_resource(view.Router, '/router')
    api.add_resource(view.RouterNameV2, '/v2/router/name')
    add_resource(view.RouterNameV2, "public")
    api.add_resource(view.UserRouteV2, '/v2/router/user_route')
    add_resource(view.UserRouteV2, "public")
