from flask_jwt_extended import jwt_required
from flask_restful import Resource


def hb_create_project():
    pass


class HarborProject(Resource):
    @jwt_required
    def post(self):
        pass
