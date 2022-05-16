import util
from flask_restful import Resource, reqparse
from resources.template import template_from_project
from flask_jwt_extended import jwt_required


class CreateTemplateFromProject(Resource):
    @jwt_required
    def post(self, project_id):
        parser = reqparse.RequestParser()
        parser.add_argument('name', type=str)
        parser.add_argument('description', type=str)
        args = parser.parse_args()
        return util.success(template_from_project.create_template_from_project(project_id, args["name"], args["description"]))


class TemplateFromProjectList(Resource):
    @jwt_required
    def get(self):
        template_from_project.template_from_project_list()
