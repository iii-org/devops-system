from .redmine import Redmine
from .project import Project
import json


class Version(object):
    def get_version_list_by_project(self, logger, app, project_id):
        project_plugin_relation_list = Project.get_project_plugin_relation(
            self, logger)
        for project_plugin_relation in project_plugin_relation_list:
            if project_plugin_relation['project_id'] == project_id:
                redmine_key = Redmine.get_redmine_key(self, logger, app)
                version_list, statu_code = Redmine.redmine_get_version_list(
                    self, logger, app,
                    project_plugin_relation['plan_project_id'])
                if statu_code == 200:
                    return {
                        "message": "success",
                        "data": version_list.json()
                    }, 200
                else:
                    return {"message": "get redmine wiki list error"}, 401
    
    def post_version_by_project(self, logger, app, project_id,message_args):
        project_plugin_relation_list = Project.get_project_plugin_relation(
            self, logger)
        for project_plugin_relation in project_plugin_relation_list:
            if project_plugin_relation['project_id'] == project_id:
                redmine_key = Redmine.get_redmine_key(self, logger, app)
                version, statu_code = Redmine.redmine_post_version(
                    self, logger, app,
                    project_plugin_relation['plan_project_id'], message_args
                )
                if statu_code == 204:
                    return {"message": "update Version success", "data": version.json() }, 200
                elif statu_code == 201:
                    return {"message": "create Version success", "data": version.json()}, 200
                else:
                    return {"message": "Create redmine Version error", "data": {}}, 401

    def get_version_by_version_id(self, logger, app, project_id, version_id):
        project_plugin_relation_list = Project.get_project_plugin_relation(
            self, logger)
        for project_plugin_relation in project_plugin_relation_list:
            if project_plugin_relation['project_id'] == project_id:
                redmine_key = Redmine.get_redmine_key(self, logger, app)
                version, statu_code = Redmine.redmine_get_version(
                    self, logger, app, version_id )
                if statu_code == 200:
                    return {
                        "message": "success",
                        "data": version.json()
                    }, 200
                else:
                    return {"message": "get redmine version  error", "data": {} }, 401

    def put_version_by_version_id(self, logger, app, project_id, version_id, args):
        project_plugin_relation_list = Project.get_project_plugin_relation(
            self, logger)
        for project_plugin_relation in project_plugin_relation_list:
            if project_plugin_relation['project_id'] == project_id:
                redmine_key = Redmine.get_redmine_key(self, logger, app)
                version, statu_code = Redmine.redmine_put_version(
                    self, logger, app, version_id, args)
                if statu_code == 204:
                    return {"message": "update version success", "data": {}}, 200
                elif statu_code == 201:
                    return {"message": "create version success", "data": {}}, 200
                else:
                    return {"message": "put redmine version error"}, 401

    def delete_version_by_version_id(self, logger, app, project_id, version_id):
        project_plugin_relation_list = Project.get_project_plugin_relation(
            self, logger)
        for project_plugin_relation in project_plugin_relation_list:
            if project_plugin_relation['project_id'] == project_id:
                redmine_key = Redmine.get_redmine_key(self, logger, app)
                output, statu_code = Redmine.redmine_delete_version(
                    self, logger, app, version_id)
                logger.debug("Delete Redmine Version : {0}".format(output))
                if statu_code == 204:
                    return {"message": "success", "data":{}}, 200
                else:
                    return {"message": "delete redmine wiki error", "data":{} }, 401
