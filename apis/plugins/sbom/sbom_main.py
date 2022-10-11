import resources.apiError as apiError
from resources import logger
from flask_apispec import marshal_with, doc, use_kwargs
from flask_apispec.views import MethodResource
from flask_jwt_extended import jwt_required
import util
from model import Sbom, db, Project
import tarfile
import subprocess
from . import router_model
from resources.project import get_pj_id_by_name
import json
from datetime import datetime, date
from resources.gitlab import commit_id_to_url
import pandas as pd
import os
import shutil
from flask import send_file, make_response
from os import listdir
from resources import gitlab
from resources.kubernetesClient import ApiK8sClient
from resources import logger
from sqlalchemy import desc



'''
execute default job and cron_job
perl ~/deploy-anchore/install_anchore.pl
'''


def is_json(string):
    try:
        json.loads(string)
    except ValueError:
        return False
    return True


def row_to_dict(row):
    ret = {}
    if row is None:
        return row
    for key in type(row).__table__.columns.keys():
        value = getattr(row, key)
        if type(value) is datetime or type(value) is date:
            ret[key] = str(value)
        elif isinstance(value, str) and is_json(value):
            ret[key] = json.loads(value)
        else:
            ret[key] = value
    return ret


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
    update_dict = {"finished": True, "scan_status": "Fail",
        "finished_at": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")}

    sbom = Sbom.query.filter_by(id=sbom_id).first()
    commit, project_id, sequence = sbom.commit, sbom.project_id, sbom.sequence
    project_name = Project.query.get(project_id).name
    pipeline_folder_name = f"{commit}-{sequence}"
    file_path = f"devops-data/project-data/{project_name}/pipeline/{pipeline_folder_name}"
    if os.path.isfile(f"./{file_path}/md5.txt"):
        md5 = util.read_txt(f"{file_path}/md5.txt")[0].replace('\n', '').strip()
        os.chmod('./apis/plugins/sbom/sbom.sh', 0o777)
        subprocess.Popen(['./apis/plugins/sbom/sbom.sh', project_name, pipeline_folder_name])
        logger.logger.info("-----------------------parse_sbom_file error-----------------------")
        logger.logger.info(f"Before:{md5 == get_tar_md5(file_path)}")
        if os.path.isfile(f"./{file_path}/sbom.tar") and md5 == get_tar_md5(file_path):
            decompress_tarfile(f"{file_path}/sbom.tar", f"{file_path}/")
            update_dict = {"finished": True, "scan_status": "Success",
                        "finished_at": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")}
            update_dict.update(package_num(file_path))
            update_dict.update(scan_overview(file_path, sbom_id))
        else:
            logger.logger.info(os.path.isfile(f"./{file_path}/sbom.tar"))
            logger.logger.info(f"After:{md5 == get_tar_md5(file_path)}")
            update_dict["logs"] = "Error: There are missing packages during transmission."
    else:
        update_dict["logs"] = "Error: Couldn't find the sbom.tar."

    update_sboms(sbom_id, update_dict)


# Get file md5
def get_tar_md5(file_path):
    session = subprocess.Popen(
        ['md5sum', f'./{file_path}/sbom.tar'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = session.communicate()
    return stdout.decode('ascii').split(" ")[0].replace('\n', '').strip()

# Get package_num
def package_num(file_path=None):
    try:
        with open(f'{file_path}/sbom.syft.json') as json_data:
            data = json.load(json_data)
            df = pd.DataFrame(data['artifacts'])
            package_nums = df.shape[0]
    except Exception:
        package_nums = None
    return {"package_nums": package_nums}


# Get scan_overview
def scan_overview(file_path, sbom_id):
    try:
        result_dict = {}
        with open(f'{file_path}/grype.json') as json_data:
            data = json.load(json_data)
        if data:
            race_sr = pd.Series(
                [data['matches'][index]['vulnerability']['severity'] for index, value in enumerate(data['matches'])])
            result_dict = race_sr.value_counts().to_dict()
            result_dict['total'] = race_sr.shape[0]
        return {"scan_overview": result_dict}
    except Exception as e:
        sbom = Sbom.query.filter_by(id=sbom_id).first()
        sbom.query.filter_by(id=sbom_id).update({
            "scan_status": "Fail",
            "logs": f"get_scan_overviewerror,reasom{e}",
            "finished": True
        })
        db.session.commit()
        return e



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
    with open(f'{file_path}/grype.json') as json_data:
        data = json.load(json_data)
    df_vulnerability_info = pd.DataFrame(
        [data['matches'][index]['vulnerability'] for index, value in enumerate(data['matches'])])
    for i in ['id', 'severity', 'description']:
        if i not in list(df_vulnerability_info.columns):
            df_vulnerability_info[i] = None
    df_vulnerability_info = df_vulnerability_info[['id', 'severity', 'description', 'dataSource']]
    df_artifact_info = pd.DataFrame(
        [data['matches'][index]['artifact'] for index, value in enumerate(data['matches'])])
    for i in ['name']:
        if i not in list(df_artifact_info.columns):
            df_artifact_info[i] = None
    df_artifact_info = df_artifact_info[['name']]
    df_fix_versions = pd.DataFrame(
        [data['matches'][index]['vulnerability']['fix']['versions'] for index, value in enumerate(data['matches'])])
    if df_fix_versions.isnull().shape[0] == df_fix_versions.shape[0]:
        df_result = df_vulnerability_info.join(df_artifact_info)
        df_result['versions'] = None
    else:
        df_result = df_vulnerability_info.join(df_artifact_info).join(df_fix_versions)
    # merge sbom json file
    with open(f'{file_path}/sbom.syft.json') as json_data:
        data = json.load(json_data)
    df = pd.DataFrame(data['artifacts'])
    df_merge = pd.merge(df[['name', 'licenses', 'type', 'version']], df_result, how="left", on='name')
    df_merge = df_merge[['name', 'id', 'severity', 'licenses', 'type', 'version', 'versions', 'dataSource', 'description']]
    sorted_list = ['Critical', 'High', 'Medium', 'Low', 'Negligible', 'Unknown']
    df_sorted = pd.DataFrame()
    for i in sorted_list:
        df_sorted = df_sorted.append(df_merge[(df_merge.severity == i) & (df_merge.versions.notnull())])
        df_sorted = df_sorted.append(df_merge[(df_merge.severity == i) & (df_merge.versions.isnull())])
    df_sorted = df_sorted.append(df_merge[df_merge.severity.isnull()])
    return df_sorted


def get_sbom_scan_file_list(sbom_id):
    file_list = []
    sbom = Sbom.query.filter_by(id=sbom_id).first()
    if sbom is not None:
        project_name = Project.query.get(sbom.project_id).name
        file_path = f"devops-data/project-data/{project_name}/pipeline/{sbom.commit}-{sbom.sequence}"
        if os.path.isdir(file_path):
            file_list = os.listdir(file_path)
            if "sbom.tar" in file_list:
                file_list.remove("sbom.tar")
    return [file for file in file_list if file.startswith("sbom.")]


def check_folder_exist(file_name, path):
    if file_name not in listdir(path):
        raise apiError.DevOpsError(
            404, 'The file is not found in provided path.',
            apiError.file_not_found(file_name, path))


def download_report_file(file_path, file_name):
    check_folder_exist(file_name, file_path)
    return send_file(f"../{file_path}/{file_name}")


# --------------------- Resources ---------------------

@doc(tags=['Sbom'], description="Get all project's scan")
@marshal_with(router_model.SbomGetRes)
class SbomGetV2(MethodResource):
    @jwt_required()
    def get(self, project_id):
        return util.success(get_sboms(project_id))


@doc(tags=['Sbom'], description="Get risk detail")
@use_kwargs(router_model.SbomListResponse, location="query")
@marshal_with(router_model.SbomGetRiskDetailRes)
class SbomRiskDetailV2(MethodResource):
    @jwt_required()
    def get(self, sbom_id, **kwargs):
        sbom = Sbom.query.filter_by(id=sbom_id).first()
        commit, project_id, sequence = sbom.commit, sbom.project_id, sbom.sequence
        project_name = Project.query.get(project_id).name
        folder_name = f'{commit}-{sequence}'
        output_dict = {}
        if os.path.isfile(f"./devops-data/project-data/{project_name}/pipeline/{folder_name}/grype.json"):
            file_path = f"devops-data/project-data/{project_name}/pipeline/{folder_name}"
            out_list, page_dict = util.df_pagination(risk_detail(file_path), kwargs.get("per_page"), kwargs.get("page"))
            output_dict.update({"detail_list": out_list, "page": page_dict})
            return util.success(json.loads(json.dumps(
                output_dict)))
        else:
            return util.success({})


class SbomGetScanFileListV2(MethodResource):
    @doc(tags=['Sbom'], description="Get available file list.")
    @marshal_with(router_model.SbomGetFileList)
    @jwt_required()
    def get(self, sbom_id):
        return util.success(get_sbom_scan_file_list(sbom_id))
    

@doc(tags=['Sbom'], description="Get Sbon List")
@marshal_with(router_model.SbomGetSbonListRes)
@use_kwargs(router_model.SbomListResponse, location="query")
class SbomListV2(MethodResource):
    @jwt_required()
    def get(self, project_id, **kwargs):
        page_dict = {}
        query = Sbom.query.filter_by(project_id=project_id).order_by(Sbom.created_at.desc())
        if 'per_page' in kwargs:
            per_page = kwargs['per_page']
        if 'page' in kwargs:
            paginate_query = query.paginate(
                page=kwargs['page'],
                per_page=per_page,
                error_out=False
            )
            page_dict = {
                'current': paginate_query.page,
                'prev': paginate_query.prev_num,
                'next': paginate_query.next_num,
                'pages': paginate_query.pages,
                'per_page': paginate_query.per_page,
                'total': paginate_query.total
            }
            rows = paginate_query.items
        else:
            rows = query.all()
        sbom_list = []
        for row in rows:
            row = row_to_dict(row)
            row["commit_url"] = gitlab.commit_id_to_url(project_id, row["commit"])
            sbom_list.append(row)
        out_dict = {"Sbom_list": sbom_list, "page": page_dict}
        if page_dict:
            out_dict['page'] = page_dict
        return util.success(out_dict)


@doc(tags=['Sbom'], description="Get risk overview")
@marshal_with(router_model.SbomGetRiskOverviewRes)
class SbomGetRiskOverviewV2(MethodResource):
    @jwt_required()
    def get(self, sbom_id):
        sbom = Sbom.query.filter_by(id=sbom_id).first()
        commit, project_id, sequence = sbom.commit, sbom.project_id, sbom.sequence
        project_name = Project.query.get(project_id).name
        folder_name = f'{commit}-{sequence}'
        if os.path.isfile(f"./devops-data/project-data/{project_name}/pipeline/{folder_name}/grype.json"):
            file_path = f"devops-data/project-data/{project_name}/pipeline/{folder_name}"
            return util.success(scan_overview(file_path, sbom_id)["scan_overview"])
        else:
            return util.success({})


@doc(tags=['Sbom'], description="download report")
@use_kwargs(router_model.SbomDownloadReportRes, location="query")
@marshal_with(util.CommonResponse)
class SbomDownloadReportV2(MethodResource):
    @jwt_required()
    def get(self, sbom_id, **kwargs):
        sbom = Sbom.query.filter_by(id=sbom_id).first()
        commit, project_id, sequence = sbom.commit, sbom.project_id, sbom.sequence
        project_name = Project.query.get(project_id).name
        folder_name = f'{commit}-{sequence}'
        file_path = f"devops-data/project-data/{project_name}/pipeline/{folder_name}"
        response = make_response(download_report_file(file_path, kwargs["file_name"]))
        response.headers["Content-Type"] = "application/octet-stream"
        response.headers["Content-Disposition"] = f"attachment; filename={kwargs['file_name']}"
        return response


def check_status(sbom_id):
    sbom = Sbom.query.filter_by(id=sbom_id).first()
    branch, project_id, sequence = sbom.branch, sbom.project_id, sbom.sequence
    project_name = Project.query.get(project_id).name
    job_name = f"{project_name}-{branch}-sbom-{sequence}"
    alive = ApiK8sClient().read_namespaced_job(name=job_name, namespace=project_name)
    if not alive:
        Sbom.query.filter_by(id=sbom_id).update({
            "scan_status": "Fail",
            "logs": "Job is deleted",
            "finished": True
        })
        db.session.commit()
        return False
    else:
        return True


@doc(tags=['Sbom'], description="update status")
@marshal_with(util.CommonResponse)
class SbomCheckStatusV2(MethodResource):
    @jwt_required()
    def patch(self, sbom_id):
        check_status(sbom_id)
        return util.success()

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


def get_scan_report(project_id, commit_id):
    row = Sbom.query.filter(Sbom.project_id == project_id).filter(Sbom.commit == commit_id).order_by(desc(Sbom.id)).first()
    if row is not None:
        sbom_id = row.id
        ret = row_to_dict(row)
        if not row.finished:
            if check_status(sbom_id):
                return ret
            else:
                return {"error": "job is deleted"}
        else:
            return ret