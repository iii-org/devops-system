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


class ExcalidrawsFilesV2(MethodResource):
    @doc(tags=['Excalidraw'], description="Put excalidraw Files info")
    @marshal_with(util.CommonResponse)
    @use_kwargs(router_model.ExcalidrawFilePostSchema, location="json")
    def post(self, **kwargs):
        excalidraw.save_file_info(kwargs)
        return util.success()


class ExcalidrawsHistoryV2(MethodResource):
    @doc(tags=['Excalidraw'], description="Get excalidraw record by excalidraw_id.")
    @marshal_with(router_model.ExcalidrawHistoryGetRes)
    @jwt_required()
    def get(self, excalidraw_id):
        return util.success(excalidraw.get_excalidraw_history(excalidraw_id))


    @doc(tags=['Excalidraw'], description="Automatic sync excalidraw. (Get in)")
    @marshal_with(util.CommonResponse)
    @jwt_required()
    def post(self, excalidraw_id):
        excalidraw.update_excalidraw_history(excalidraw_id)
        return util.success()


    @doc(tags=['Excalidraw'], description="Compare excalidraw and store in db. (Get out)")
    @marshal_with(util.CommonResponse)
    @jwt_required()
    def patch(self, excalidraw_id):
        excalidraw.check_excalidraw_history(excalidraw_id)
        return util.success()


class ExcalidrawsVersionRestoreV2(MethodResource):
    @doc(tags=['Excalidraw'], description="restore excalidraw value by user assigned.")
    @marshal_with(util.CommonResponse)
    @jwt_required()
    def put(self, excalidraw_history_id):
        return util.success(excalidraw.excalidraw_version_restore(excalidraw_history_id))


class GetExcalidrawIDV2(MethodResource):
    @doc(tags=['Excalidraw'], description="get excalidraw id.")
    @marshal_with(router_model.ExcalidrawGetIDRes)
    def get(self, room_key):
        from model import Excalidraw
        row = Excalidraw.query.filter_by(room=room_key).first()
        return util.success({"excalidraw_id": row.id})
