from . import view


def sync_system_parameter_url(api, add_resource):
    api.add_resource(view.UploadFiles, '/v2/system_parameter/upload_file_type')
    add_resource(view.UploadFiles, 'public')
    api.add_resource(view.GetUploadFileDistinctName, '/v2/system_parameter/upload_file_type/names')
    add_resource(view.GetUploadFileDistinctName, 'public')
    api.add_resource(view.UploadFile, '/v2/system_parameter/upload_file_type/<int:upload_file_type_id>')
    add_resource(view.UploadFile, 'public')