import json

import requests
from flask_jwt_extended import jwt_required
from flask_restful import Resource, reqparse
from sqlalchemy.orm.exc import NoResultFound

import config
import model
import util as util
from resources import apiError, kubernetesClient, role
from resources.apiError import DevOpsError
from resources.logger import logger

from .gitlab  import get_repository_id, gitlab
from .redmine import redmine

error_issue_not_all_closed = "Not All Issues are closed in Versions"
error_gitlab_not_found = 'No such repository found in database.'
version_info_keys = ['id','name','status']
release_info_keys = ['description','created_at','released_at']


def transfer_array_to_object(targets,key):
    output = {}
    for target in targets:        
        output[target[key]] = {}
        output[target[key]] = target
    return output

def mapping_function_by_key(versions, releases):
    output = {}
    for key in versions:        
        info = {}
        if key in releases:
            for version_key in version_info_keys :
                info[version_key] = versions[key][version_key]
            for release_keys in release_info_keys :
                info[release_keys] = releases[key][release_keys]
            output[key] = info
    return output


def get_mapping_list_info(versions, releases):
    output = {}
    rm_key_versions = {}
    gl_key_releases = {}
    rm_key_versions = transfer_array_to_object(versions,'name')    
    gl_key_releases = transfer_array_to_object(releases,'tag_name')
    output = mapping_function_by_key(rm_key_versions,gl_key_releases)
    return list(output.values())
    

def check_issue_unclosed(targets):
    output = { 'check' : True, 'versions' : []}
    for target in targets :
        if target['unclosed'] is not 0:
            output['check'] = False            
            output['versions'].append({"id": int(target['id'])})            
    return output



class Releases(Resource):
    @jwt_required
    def get(self, project_id):    
        plugin_relation = model.ProjectPluginRelation.query.filter_by(project_id=project_id).first()
        try:
            rm_list_versions = redmine.rm_get_version_list(plugin_relation.plan_project_id),            
        except NoResultFound:
            return util.respond(404, error_gitlab_not_found,
                                error=apiError.redmine_project_not_found(plugin_relation.plan_project_id))
        try:
            gl_list_releases = gitlab.gl_list_releases(plugin_relation.git_repository_id),            
        except NoResultFound:
            return util.respond(404, error_gitlab_not_found,
                                error=apiError.repository_id_not_found(plugin_relation.git_repository_id))
        list_versions = rm_list_versions[0]['versions']
        list_releases= gl_list_releases[0]
        return util.success(get_mapping_list_info(list_versions, list_releases))

    @jwt_required
    def post(self, project_id):            
        output = {}
        plugin_relation = model.ProjectPluginRelation.query.filter_by(project_id=project_id).first()        
        parser = reqparse.RequestParser()
        parser.add_argument('main',type=int)
        parser.add_argument('versions',action='append')
        parser.add_argument('branch',type=str)
        parser.add_argument('description', type=str)
        parser.add_argument('released_at', type=str)
        args = parser.parse_args()
        # Check Issues is Closed 
        
        versions = args['versions']        
        issues_by_versions= redmine.rm_list_issues_by_versions(plugin_relation.plan_project_id, versions)
        version_check  =  check_issue_unclosed (issues_by_versions)
        if version_check['check'] is False:
            return util.respond(404, error_issue_not_all_closed,
                                error = apiError.issue_not_all_closed(version_check['versions']))



        output = {'total_check': version_check}

        return util.success(version_check)
        try:
            output = gitlab.gl_create_release(plugin_relation.git_repository_id,args)
        except NoResultFound:
            return util.respond(404, error_gitlab_not_found,
                                error=apiError.repository_id_not_found(plugin_relation.git_repository_id))
        
        output = gitlab.gl_create_release(plugin_relation.git_repository_id,args)
        return output

class Release(Resource):
    @jwt_required
    def get(self, project_id, release_name):    
        plugin_relation = model.ProjectPluginRelation.query.filter_by(project_id=project_id).first()
        try:            
            gl_release = gitlab.gl_get_release(plugin_relation.git_repository_id,release_name)
            rm_list_versions = redmine.rm_get_version_list(plugin_relation.plan_project_id),            
            rm_key_versions = transfer_array_to_object(rm_list_versions[0]['versions'],'name')    
            if release_name not in rm_key_versions:
                return util.success({})          
            return util.success({'gitlab': gl_release, 'redmine' : rm_key_versions[release_name]})
        except NoResultFound:
            return util.respond(404, error_gitlab_not_found,
                                error=apiError.repository_id_not_found(plugin_relation.git_repository_id))
    @jwt_required
    def put(self, project_id, release_name):            
        output = {}
        plugin_relation = model.ProjectPluginRelation.query.filter_by(project_id=project_id).first()                
        parser = reqparse.RequestParser()
        parser.add_argument('main',type=int)
        parser.add_argument('others',type=str)
        parser.add_argument('description', type=str)
        parser.add_argument('released_at', type=str)
        args = parser.parse_args()
        # output = gitlab.gl_update_release(plugin_relation.git_repository_id,release_name,args)
        return util.success(output)
        try:            
            # gl_releases = gitlab.gl_list_releases(repository_id)
            return util.success(gl_releases)
        except NoResultFound:
            return util.respond(404, error_gitlab_not_found,
                                error=apiError.repository_id_not_found(repository_id))

    @jwt_required
    def delete(self, project_id, release_name):            
        plugin_relation = model.ProjectPluginRelation.query.filter_by(project_id=project_id).first()        
        output = gitlab.gl_delete_release(plugin_relation.git_repository_id,release_name)
        return util.success(output['tag_name'])
        try:            
            # gl_releases = gitlab.gl_list_releases(repository_id)
            return util.success(gl_releases)
        except NoResultFound:
            return util.respond(404, error_gitlab_not_found,
                                error=apiError.repository_id_not_found(repository_id))
    