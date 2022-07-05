from flask_apispec import marshal_with, doc, use_kwargs
from flask_apispec.views import MethodResource
from datetime import datetime
from flask_jwt_extended import jwt_required
from . import router_model
import util
from resources import excalidraw
from plugins import handle_plugin


class ExcalidrawsV2(MethodResource):
    @doc(tags=['Excalidraw'], description="Create a excalidraw.")
    @use_kwargs(router_model.ExcalidrawCreateSchema, location="form")
    @marshal_with(router_model.ExcalidrawPostRes)
    @handle_plugin("excalidraw")
    @jwt_required()
    def post(self, **kwargs):
        kwargs["issue_ids"] = None if kwargs.get("issue_ids") == "" else kwargs.get("issue_ids")
        return util.success(excalidraw.create_excalidraw(kwargs))


    @doc(tags=['Excalidraw'], description="Get excalidraws.")
    @use_kwargs(router_model.ExcalidrawGetSchema, location="query")
    @marshal_with(router_model.ExcalidrawGetRes)
    @handle_plugin("excalidraw")
    @jwt_required()
    def get(self, **kwargs):
        return util.success(excalidraw.get_excalidraws(kwargs))


class ExcalidrawV2(MethodResource):
    @doc(tags=['Excalidraw'], description="Delete an excalidraw.")
    @marshal_with(util.CommonResponse)
    @handle_plugin("excalidraw")
    @jwt_required()
    def delete(self, excalidraw_id):
        return util.success(excalidraw.delete_excalidraw(excalidraw_id))


    @doc(tags=['Excalidraw'], description="Update an excalidraw.")
    @use_kwargs(router_model.ExcalidrawPatchSchema, location="form")
    @marshal_with(router_model.ExcalidrawPatchRes)
    @handle_plugin("excalidraw")
    @jwt_required()
    def patch(self, excalidraw_id, **kwargs):
        return util.success(excalidraw.update_excalidraw(excalidraw_id, **kwargs))


class SyncExcalidrawDBV2(MethodResource):
    @doc(tags=['Sync'], description="Remove unused data in excalidraw's DB.")
    @handle_plugin("excalidraw")
    @jwt_required()
    def post(self):
        return util.success(excalidraw.sync_excalidraw_db())


class CheckExcalidrawAliveV2(MethodResource):
    @doc(tags=['Excalidraw'], description="Check excalidraw server is alive.")
    @marshal_with(router_model.CheckExcalidrawAliveRes)
    @handle_plugin("excalidraw")
    @jwt_required()
    def get(self):
        return util.success(excalidraw.check_excalidraw_alive())
