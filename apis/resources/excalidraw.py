from flask_jwt_extended import get_jwt_identity
from rstr import xeger
from model import Excalidraw, ExcalidrawJson, ExcalidrawIssueRelation, db, User
from datetime import datetime
from accessories import redmine_lib
import resources.project as project
from resources import apiError
from resources.apiError import DevOpsError
from resources.role import require_in_project
import config


def get_excalidraw_url(excalidraw):
    excalidraw_url = config.get("EXCALIDRAW_URL")
    return f"{excalidraw_url}/#room={excalidraw.room},{excalidraw.key}"


def nexus_excalidraw(excalidraw_join_issue_relations):
    ret = {}
    for excalidraw_join_issue_relation in excalidraw_join_issue_relations:
        excalidraw, user = excalidraw_join_issue_relation.Excalidraw, excalidraw_join_issue_relation.User
        
        if excalidraw_join_issue_relation.ExcalidrawIssueRelation is not None:
            issue_id = [excalidraw_join_issue_relation.ExcalidrawIssueRelation.issue_id]
            if ret.get(excalidraw.id) is not None:
                ret[excalidraw.id]["issue_ids"] += issue_id
                continue
        else:
            issue_id = None
        
        ret[excalidraw.id] = {
            "id": excalidraw.id,
            "name": excalidraw.name,
            "project_id": excalidraw.project_id,
            "created_at": str(excalidraw.created_at),
            "updated_at": str(excalidraw.updated_at),
            "url": get_excalidraw_url(excalidraw),
            "operator": {"id": user.id, "name": user.name, "login": user.login},
            "issue_ids": issue_id
        }
    return list(ret.values())


def create_excalidraw(args):
    operator_id = get_jwt_identity()['user_id']
    project_id, issue_ids, name = args["project_id"], args.get("issue_ids"), args["name"]
    has_issue_ids = issue_ids is not None
    require_in_project(project_id=project_id)

    # In case it has duplicate room in db
    room, key = xeger(r'[0-9a-f]{20}'), xeger(r'[a-zA-Z0-9_-]{22}')
    while Excalidraw.query.filter_by(room=room).first() is not None:
        room = xeger(r'[0-9a-f]{20}')

    # check issue is in project.
    if has_issue_ids:
        plan_project_id = project.get_plan_project_id(project_id)
        redmine_issues = redmine_lib.redmine.issue.filter(project_id=plan_project_id)
        exist_issue_ids = [redmine_issue.id for redmine_issue in redmine_issues]
        request_issue_ids = issue_ids.split(",")
        
        for issue_id in request_issue_ids:
            if int(issue_id) not in exist_issue_ids:
                raise DevOpsError(400, f'Argument issue_ids include invalid issue_id.',
                                    error=apiError.argument_error("issue_ids")) 

    row = Excalidraw(
        project_id=project_id,
        name=name,
        room=room,
        key=key,
        operator_id=operator_id,
        created_at=datetime.utcnow(),
        updated_at=datetime.utcnow(),
    )
    db.session.add(row) 
    db.session.commit()
    
    if has_issue_ids:
        excalidraw_id = row.id
        excalidraw_issue_relations = [
            ExcalidrawIssueRelation(
                issue_id=int(issue_id),
                excalidraw_id=excalidraw_id
            ) for issue_id in issue_ids.split(",")
        ]
        db.session.add_all(excalidraw_issue_relations)
        db.session.commit()


def get_excalidraws(args):
    project_id, name = args.get("project_id"), args.get("name")
    excalidraw_rows = db.session.query(Excalidraw, ExcalidrawIssueRelation, User).outerjoin(
        ExcalidrawIssueRelation, Excalidraw.id==ExcalidrawIssueRelation.excalidraw_id)
    excalidraw_rows = excalidraw_rows.join(User, Excalidraw.operator_id==User.id)
    
    if project_id is not None:
        excalidraw_rows = excalidraw_rows.filter(Excalidraw.project_id==project_id)
    if name is not None:
        excalidraw_rows = excalidraw_rows.filter(Excalidraw.name.ilike(f'%{name}%'))
    
    return nexus_excalidraw(excalidraw_rows)


def get_excalidraw_by_issue_id(issue_id):
    row = db.session.query(ExcalidrawIssueRelation, Excalidraw). \
    outerjoin(Excalidraw, ExcalidrawIssueRelation.excalidraw_id==Excalidraw.id). \
    filter(ExcalidrawIssueRelation.issue_id==issue_id).first()
    if row is not None:
        excalidraw = row.Excalidraw
        row = {
            "id": excalidraw.id,
            "exlidraw_url": get_excalidraw_url(excalidraw),
            "name": excalidraw.name
        }
    return row


def delete_excalidraw(excalidraw_id):
    excalidraw = Excalidraw.query.filter_by(id=excalidraw_id)
    if excalidraw.first() is not None:
        project_id = excalidraw.first().project_id
        require_in_project(project_id=project_id)
        excalidraw.delete()
        db.session.commit()


def update_excalidraw(excalidraw_id, name=None, issue_ids=None):
    excalidraw = Excalidraw.query.filter_by(id=excalidraw_id).first()
    if excalidraw is None:
        return 
    
    excalidraw_id, project_id = excalidraw.id, excalidraw.project_id
    require_in_project(project_id=project_id)
    if name is not None:
        excalidraw.name = name
    else:
        name = excalidraw.name

    if issue_ids is not None:
        plan_project_id = project.get_plan_project_id(project_id)
        redmine_issues = redmine_lib.redmine.issue.filter(project_id=plan_project_id)
        exist_issue_ids = [redmine_issue.id for redmine_issue in redmine_issues]
        issue_ids = list(map(lambda x: int(x) ,issue_ids.split(",")))
        
        for issue_id in issue_ids:
            if int(issue_id) not in exist_issue_ids:
                raise DevOpsError(400, f'Argument issue_ids include invalid issue_id.',
                                    error=apiError.argument_error("issue_ids")) 
            
        create_issue_ids = issue_ids.copy()
        excalidraw_issues = ExcalidrawIssueRelation.query.filter_by(excalidraw_id=excalidraw_id).all()
        for excalidraw_issue in excalidraw_issues:
            excalidraw_issue_id = excalidraw_issue.issue_id
            if excalidraw_issue_id not in issue_ids:
                db.session.delete(excalidraw_issue) 
            else:
                create_issue_ids.remove(excalidraw_issue_id)
        
        db.session.add_all([
            ExcalidrawIssueRelation(
                issue_id=int(create_issue_id),
                excalidraw_id=excalidraw_id
            ) for create_issue_id in create_issue_ids
        ])
    else:
        excalidraw_issues = ExcalidrawIssueRelation.query.filter_by(excalidraw_id=excalidraw_id).all()
        issue_ids = [excalidraw_issue.issue_id
            for excalidraw_issue in ExcalidrawIssueRelation.query.filter_by(excalidraw_id=excalidraw_id).all()]

    excalidraw.updated_at = datetime.utcnow()
    db.session.commit()

    return {
        "id": excalidraw_id,
        "name": name,
        "issue_ids": issue_ids,
        "url": get_excalidraw_url(excalidraw)
    }