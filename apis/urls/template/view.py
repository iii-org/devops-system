import util
from flask_restful import Resource, reqparse
from resources.template import template_from_project


class CreateTemplateFromProject(Resource):
    def post(self, project_id):
        parser = reqparse.RequestParser()
        parser.add_argument('name', type=str)
        parser.add_argument('description', type=str)
        args = parser.parse_args()
        template_from_project.create_template_from_project(project_id, args["name"], args["description"])
        return util.success()
