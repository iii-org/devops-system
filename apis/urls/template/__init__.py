from . import view


def template_url(api, add_resource):
    api.add_resource(view.CreateTemplateFromProject, '/v2/template_from_project/<sint:project_id>')
    # add_resource(view.CreateTemplateFromProject, "public")
