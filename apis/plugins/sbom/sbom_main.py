from flask_apispec import marshal_with, doc, use_kwargs
from flask_apispec.views import MethodResource
from flask_jwt_extended import jwt_required
import util
from model import Sbom, db
from . import router_model
from resources.project import get_pj_id_by_name
import json
from datetime import datetime
from resources.gitlab import commit_id_to_url


def nexus_sbom(sbom_row):
    sbom = json.loads(str(sbom_row))
    sbom["commit_url"] = commit_id_to_url(sbom["project_id"], sbom["commit"])
    return sbom


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
    sbom = Sbom.query.filter_by(id=sbom_id).first()
    commit, project_id = sbom.commit, sbom.project_id
    





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
    @jwt_required
    def patch(self, sbom_id):
        return util.success(parse_sbom_file(sbom_id))



