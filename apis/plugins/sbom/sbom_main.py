from flask_apispec import marshal_with, doc, use_kwargs
from flask_apispec.views import MethodResource
from flask_jwt_extended import jwt_required
import util
from model import Sbom, db, Project
import tarfile
from . import router_model
from resources.project import get_pj_id_by_name
import json
from datetime import datetime
from resources.gitlab import commit_id_to_url
import pandas as pd
import os


def nexus_sbom(sbom_row):
    sbom = json.loads(str(sbom_row))
    sbom["commit_url"] = commit_id_to_url(sbom["project_id"], sbom["commit"])
    return sbom


def decompress_tarfile(file_path, decompress_path):
    tar = tarfile.open(file_path, 'r:tar')
    tar.extractall(path=decompress_path)


def get_sboms(project_id):
    sboms = Sbom.query.filter_by(project_id=project_id)
    return [nexus_sbom(sbom) for sbom in sboms]


def create_sbom(kwargs):
    kwargs["project_id"] = get_pj_id_by_name(kwargs.pop("project_name"))["id"]
    kwargs["created_at"] = datetime.utcnow()
    row = Sbom(**kwargs)
    db.session.add(row)
    db.session.commit()
    return {"id": row.id}


def update_sboms(sbom_id, kwargs):
    Sbom.query.filter_by(id=sbom_id).update(kwargs)
    db.session.commit()


def parse_sbom_file(sbom_id):
    # Decompress tar
    sbom = Sbom.query.filter_by(id=sbom_id).first()
    commit, project_id, sequence = sbom.commit, sbom.project_id, sbom.sequence
    project_name = Project.query.get(project_id).name
    folder_name = f'{commit}-{sequence}'
    if os.path.isdir(f"devops-data/project-data/{project_name}/pipeline/{folder_name}/"):
        file_path = f"devops-data/project-data/{project_name}/pipeline/{folder_name}/"
        decompress_tarfile(f"{file_path}/sbom.tar", file_path)
        update_dict = {"finished": True, "scan_status": "Success",
                       "finished_at": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")}
        update_dict.update(package_num(file_path))
        update_dict.update(scan_overview(file_path))
        update_sboms(sbom_id, update_dict)
    else:
        update_dict = {"finished": True, "scan_status": "Fail", "logs": "didn't find the file",
                       "finished_at": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")}
        update_sboms(sbom_id, update_dict)


# Get package_num
def package_num(file_path=None):
    with open(f'{file_path}/sbom.syft.json') as json_data:
        data = json.load(json_data)
    df = pd.DataFrame(data['artifacts'])
    return {"package_nums": df.shape[0]}


# Get scan_overview
def scan_overview(file_path=None):
    with open(f'{file_path}/grype.syft.json') as json_data:
        data = json.load(json_data)
    race_sr = pd.Series(
        [data['matches'][index]['vulnerability']['severity'] for index, value in enumerate(data['matches'])])
    result_dict = race_sr.value_counts().to_dict()
    result_dict['total'] = race_sr.shape[0]
    return {"scan_overview": result_dict}



# --------------------- Resources ---------------------

@doc(tags=['Sbom'], description="Get all project's scan")
@marshal_with(router_model.SbomGetRes)
class SbomGetV2(MethodResource):
    @jwt_required()
    def get(self, project_id):
        return util.success(get_sboms(project_id))


#### Runner
@doc(tags=['Sbom'], description="Create a Sbom scan.")
@use_kwargs(router_model.SbomPostSchema, location="json")
@marshal_with(router_model.SbomPostRes)
class SbomPostV2(MethodResource):
    @jwt_required()
    def post(self, **kwargs):
        return create_sbom(kwargs)


@doc(tags=['Sbom'], description="Update a Sbom scan")
@use_kwargs(router_model.SbomPatchSchema, location="json")
@marshal_with(util.CommonResponse)
class SbomPatchV2(MethodResource):
    @jwt_required()
    def patch(self, sbom_id, **kwargs):
        return util.success(update_sboms(sbom_id, kwargs))    


@doc(tags=['Sbom'], description="Parsing Sbom ")
# @marshal_with(util.CommonResponse)
class SbomParseV2(MethodResource):
    @jwt_required()
    def patch(self, sbom_id):
        return util.success(parse_sbom_file(sbom_id))



