from . import excalidraw_main 

ui_route = ["Excalidraw"]

# --------------------- API router ---------------------

def router(api, add_resource):
    api.add_resource(excalidraw_main.ExcalidrawsV2, '/v2/excalidraw')
    add_resource(excalidraw_main.ExcalidrawsV2, "public")
    api.add_resource(excalidraw_main.ExcalidrawV2, '/v2/excalidraw/<int:excalidraw_id>')
    add_resource(excalidraw_main.ExcalidrawV2, "public")
    api.add_resource(excalidraw_main.SyncExcalidrawDBV2, '/v2/excalidraw/sync_db')
    add_resource(excalidraw_main.SyncExcalidrawDBV2, "public")
    api.add_resource(excalidraw_main.CheckExcalidrawAliveV2, '/v2/excalidraw/alive')
    add_resource(excalidraw_main.CheckExcalidrawAliveV2, "public")
    api.add_resource(excalidraw_main.ExcalidrawsHistoryV2, '/v2/excalidraw/<int:excalidraw_id>/historys')
    add_resource(excalidraw_main.ExcalidrawsHistoryV2, "public")
    api.add_resource(excalidraw_main.ExcalidrawsVersionRestoreV2, '/v2/excalidraw/<int:excalidraw_hisrory_id>/restore')
    add_resource(excalidraw_main.ExcalidrawsHistoryV2, "public")