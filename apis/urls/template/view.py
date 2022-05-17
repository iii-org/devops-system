import util
from flask_apispec import doc, marshal_with, use_kwargs
from flask_apispec.views import MethodResource
from flask_jwt_extended import jwt_required
from flask_restful import Resource, reqparse
from resources import role
from resources.template import template_from_project
from urls.template import router_model


@doc(tags=['Template from project'], description='Create template from project_id')
class TemplateFromProject(MethodResource):
    @use_kwargs(router_model.CreateTemplateFormProjectScheme, location=('form'))
    @jwt_required
    def post(self, project_id):
        parser = reqparse.RequestParser()
        parser.add_argument('name', type=str)
        parser.add_argument('description', type=str)
        args = parser.parse_args()
        return util.success(template_from_project.create_template_from_project(project_id, args["name"],
                                                                               args["description"]))


@doc(tags=['Template from project'], description='Delete template')
class TemplateEdit(MethodResource):
    @jwt_required
    def delete(self, id):
        if role.is_admin() or template_from_project.verify_user_in_template_project(id):
            template_from_project.delete_template(id)
        return util.success()


@doc(tags=['Template from project'], description='Get template list')
class TemplateFromProjectList(MethodResource):
    @jwt_required
    def get(self):
        return util.success(template_from_project.template_from_project_list())
