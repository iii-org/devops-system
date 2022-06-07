from . import view 

def excalidraw_url(api, add_resource):
    api.add_resource(view.ExcalidrawsV2, '/v2/excalidraw')
    add_resource(view.ExcalidrawsV2, "public")
    api.add_resource(view.ExcalidrawV2, '/v2/excalidraw/<int:excalidraw_id>')
    add_resource(view.ExcalidrawV2, "public")