from resources import logger
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
import shutil


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
    kwargs.update({
        "project_id": get_pj_id_by_name(kwargs.pop("project_name"))["id"],
        "created_at": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
        "scan_status": "Running"
    })
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
    if os.path.isfile(f"devops-data/project-data/{project_name}/pipeline/{folder_name}/sbom.tar"):
        file_path = f"devops-data/project-data/{project_name}/pipeline/{folder_name}"
        decompress_tarfile(f"{file_path}/sbom.tar", f"{file_path}/")
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


def remove_parsing_data():
    for super_path in [pj[0] for pj in os.walk("./devops-data/project-data") if pj[0].endswith("pipeline")]:
        for dirpath, dirnames, _ in os.walk(super_path):
            dirname_num = len(dirnames)
            if dirname_num > 5:
                dirnames = sorted(
                    {int(dirname.split("-")[1]): dirname for dirname in dirnames}.items(),
                    key=lambda k: k[0],
                    reverse=True
                )
                while dirname_num > 5:
                    folder_name = dirnames.pop()[1]
                    path = os.path.join(dirpath, folder_name)
                    shutil.rmtree(path)
                    logger.logger.info(f"Remove {path} (sbom files)")
                    dirname_num -= 1
            

def risk_detail(file_path=None):
    with open(f'{file_path}/grype.syft.json') as json_data:
        data = json.load(json_data)
    df_vulnerability_info = pd.DataFrame(
        [data['matches'][index]['vulnerability'] for index, value in enumerate(data['matches'])])[['id', 'severity', 'description']]
    df_artifact_info = pd.DataFrame(
        [data['matches'][index]['artifact'] for index, value in enumerate(data['matches'])])[['name', 'version']]
    df_fix_versions = pd.DataFrame(
        [data['matches'][index]['vulnerability']['fix']['versions'] for index, value in enumerate(data['matches'])])
    if df_fix_versions.isnull().shape[0] == df_fix_versions.shape[0]:
        df_result = df_vulnerability_info.join(df_artifact_info)
        df_result['versions'] = ""
    else:
        df_result = df_vulnerability_info.join(df_artifact_info).join(df_fix_versions)
    return df_result.T.to_dict()
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


@doc(tags=['Sbom'], description="Parsing Sbom")
@marshal_with(util.CommonResponse)
class SbomParseV2(MethodResource):
    @jwt_required()
    def patch(self, sbom_id):
        return util.success(parse_sbom_file(sbom_id))


# Cronjob
@doc(tags=['Sbom'], description="Remove more more than 5 commits")
@marshal_with(util.CommonResponse)
class SbomRemoveExtra(MethodResource):
    @jwt_required()
    def patch(self):
        return util.success(remove_parsing_data())


@doc(tags=['Sbom'], description="Get risk detail")
# @marshal_with(util.CommonResponse)
class SbomRiskDetail(MethodResource):
    @jwt_required()
    def get(self, sbom_id):
        sbom = Sbom.query.filter_by(id=sbom_id).first()
        commit, project_id, sequence = sbom.commit, sbom.project_id, sbom.sequence
        project_name = Project.query.get(project_id).name
        folder_name = f'{commit}-{sequence}'
        if os.path.isfile(f"devops-data/project-data/{project_name}/pipeline/{folder_name}/grype.syft.json"):
            file_path = f"devops-data/project-data/{project_name}/pipeline/{folder_name}"
            return risk_detail(file_path)