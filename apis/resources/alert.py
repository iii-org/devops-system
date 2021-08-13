from flask_jwt_extended import jwt_required
from flask_restful import Resource, reqparse

import model
import resources.project as project
import util as util
from model import db
import resources.apiError as apiError 
from resources.apiError import DevOpsError
from sqlalchemy.orm.exc import NoResultFound


def get_alert_by_project(project_id):
    if util.is_dummy_project(project_id):
        return []
    try:
        plan_id = project.get_plan_project_id(project_id)
    except NoResultFound:
        return util.respond(404, "Error while getting alerts.",
                            error=apiError.project_not_found(project_id))
    rows = model.Alert.query.filter_by(project_id=project_id).all()
    return {"alert_list": [
        {
            "id": row.id,
            "condition": row.condition,
            "days": row.days,
            "disabled": row.disabled,
        } for row in rows
    ]}

def create_alert(project_id, args):
    rows = model.Alert.query.filter_by(project_id=project_id).all()
    condition = args["condition"]
    # Each project's condition can not be duplicated.
    if condition in [row.condition for row in rows]:
        raise DevOpsError(400, "Conditon can not be duplicated in each project.",
                          error=apiError.argument_error("condition"))

    new = model.Alert(
        project_id=project_id, 
        condition=args['condition'],
        days=args['days'],
        disabled=False
    )
    db.session.add(new)
    db.session.commit()
    return {'alert_id': new.id}

def update_alert(alert_id, args):
    alert = model.Alert.query.get(alert_id)
    days = args.get("days")
    alert.days = days if days is not None else alert.days
    disabled = args.get("disabled")
    alert.disabled = disabled if disabled is not None else alert.disabled
    db.session.commit()


# --------------------- Resources ---------------------
class ProjectAlert(Resource):
    def get(self, project_id):
        return util.success(get_alert_by_project(project_id))

    @jwt_required
    def post(self, project_id):
        parser = reqparse.RequestParser()
        parser.add_argument('condition', type=str, required=True)
        parser.add_argument('days', type=int, required=True)
        args = parser.parse_args()
        return util.success(create_alert(project_id, args))


class ProjectAlertUpdate(Resource):
    @jwt_required
    def patch(self, alert_id):
        parser = reqparse.RequestParser()
        parser.add_argument('days', type=int)
        parser.add_argument('disabled', type=bool)
        args = parser.parse_args()
        return util.success(update_alert(alert_id, args))
