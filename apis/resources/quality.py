from flask_restful import Resource

from .gitlab import gitlab
import util as util

paths = [{
    "path": "iiidevops/postman",
    "file_name_key": "postman_collection.json"
}, {
    "path": "iiidevops/sideex",
    "file_name_key": "sideex.json"
}]


def qu_get_collection_list(repository_id):
    out_dict = {}
    for path in paths:
        out_dict[path["file_name_key"]] = []
        trees = gitlab.ql_get_collection(repository_id, path['path'])
        for tree in trees:
            if path["file_name_key"] in tree["name"]:
                out_dict[path["file_name_key"]].append(tree["name"])
    return out_dict


class Collection(Resource):
    def get(self, repository_id):
        out = qu_get_collection_list(repository_id)
        return util.success(out)