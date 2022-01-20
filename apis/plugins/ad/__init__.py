from . import ad_main

# --------------------- API router ---------------------


def router(api):
    api.add_resource(ad_main.ADUsers, '/plugins/ad/users')
    api.add_resource(ad_main.SingleADUser, '/plugins/ad/user')
    api.add_resource(ad_main.ADOrganizations, '/plugins/ad/organizations')
