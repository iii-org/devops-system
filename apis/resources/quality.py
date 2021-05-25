from flask_restful import Resource
import json

from .gitlab import gitlab
import util as util

paths = [{
    "path": "iiidevops/postman",
    "file_name_key": "postman_collection.json"
}, {
    "path": "iiidevops/sideex",
    "file_name_key": "sideex.json"
}]


class PostmanJSON:
    def __init__(self, input_dict):
        self.info = input_dict.get("info")

class PostmanJSONInfo:
    def __init__(self, info_dict):
        self.name = info_dict.get("name")


class SideeXJSON:
    def __init__(self, input_dict):
        self.suites = input_dict.get("suites")


class SideeXJSONSuite:
    def __init__(self, input_dict):
        self.title = input_dict.get("title")


def qu_get_collection_list(repository_id):
    out_dict = {}
    for path in paths:
        out_dict[path["file_name_key"]] = []
        trees = gitlab.ql_get_collection(repository_id, path['path'])
        for tree in trees:
            if path["file_name_key"] in tree["name"]:
                path_file = f'{path["path"]}/{tree["name"]}'
                coll_json = json.loads(gitlab.gl_get_file(repository_id, path_file))
                if path["file_name_key"] == "postman_collection.json":
                    collection_obj = PostmanJSON(coll_json)
                    postman_info_ob = PostmanJSONInfo(collection_obj.info)
                    out_dict[path["file_name_key"]].append({"file_name": tree["name"], "name": postman_info_ob.name})
                elif path["file_name_key"] == "sideex.json":
                    suits_list = []
                    sideex_obj = SideeXJSON(coll_json)
                    for suite_dict in sideex_obj.suites:
                        suite = SideeXJSONSuite(suite_dict)
                        suits_list.append(suite.title)
                    out_dict[path["file_name_key"]].append({"file_name": tree["name"], "names": suits_list})
    return out_dict

def qu_get_collection(repository_id, software_name, collection_name):
    for path in paths:
        if software_name == path["file_name_key"]:
            path_file = f'{path["path"]}/{collection_name}'
            collection_json = json.loads(gitlab.gl_get_file(repository_id, path_file))
            pass

class CollectionList(Resource):
    def get(self, repository_id):
        out = qu_get_collection_list(repository_id)
        return util.success(out)

class Collection(Resource):
    def get(self, repository_id, software_name, collection_name):
        out = qu_get_collection(repository_id, software_name, collection_name)
        return util.success(out)