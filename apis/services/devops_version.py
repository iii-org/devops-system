import uuid

import model


def set_deployment_uuid():
    my_uuid = uuid.uuid1()
    row = model.NexusVersion.query.first()
    row.deployment_uuid = my_uuid
    model.db.session.commit()


