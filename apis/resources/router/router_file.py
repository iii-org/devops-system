import os
import hashlib
import util
from model import db, UIRouteFile
from datetime import datetime

UI_ROUTE_FOLDER_NAME = "apis/ui_routes"


def check_file_data_is_same():
    for ui_route_file_name in next(os.walk(UI_ROUTE_FOLDER_NAME))[2]:
        print(ui_route_file_name[-5:])
        if ui_route_file_name[-5:] == ".json":
            with open(f"{UI_ROUTE_FOLDER_NAME}/{ui_route_file_name}", 'rb') as file_to_check:
                md5_returned = hashlib.md5(file_to_check.read()).hexdigest()
                row = UIRouteFile.query.filter_by(file_name=ui_route_file_name).first()
                if row is None:
                    '''
                    file_row = UIRouteFile(file_name=ui_route_file_name,
                                           file_md5=md5_returned,
                                           updated_at=datetime.utcnow(),
                                           created_at=datetime.utcnow()
                                           )
                    db.session.add(file_row)
                    db.session()
                    # Insert route into db
                    '''
                    print("Insert UIRouteFile table")
                elif row.file_md5 != md5_returned:
                    '''
                    row.file_md5 = md5_returned
                    row.updated_at = datetime.utcnow()
                    db.session.commit()
                    # Insert route into db
                    '''
                    print("Update UIRouteFile table")
