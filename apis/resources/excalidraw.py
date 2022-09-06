from flask_jwt_extended import get_jwt_identity
from rstr import xeger
from model import Excalidraw, ExcalidrawJson, ExcalidrawIssueRelation, Project, ProjectUserRole, db, User
from datetime import datetime
from accessories import redmine_lib
import resources.project as project
from resources import apiError
from resources.apiError import DevOpsError
from resources.role import require_in_project
from plugins import get_plugin_config
import psycopg2
from . import role, user
from util import check_url_alive


def excalidraw_get_config(key):
    for arg in get_plugin_config("excalidraw")["arguments"]:
        if arg['key'] == key:
            return arg['value']
    return None


def get_excalidraw_url(excalidraw):
    excalidraw_url = excalidraw_get_config("excalidraw-url")
    return f"{excalidraw_url}/#room={excalidraw.room},{excalidraw.key}"


def nexus_excalidraw(excalidraw_join_issue_relations):
    ret = {}
    for excalidraw_join_issue_relation in excalidraw_join_issue_relations:
        excalidraw = excalidraw_join_issue_relation.Excalidraw
        user       = excalidraw_join_issue_relation.User
        project    = excalidraw_join_issue_relation.Project

        if excalidraw_join_issue_relation.ExcalidrawIssueRelation is not None:
            issue_id = [excalidraw_join_issue_relation.ExcalidrawIssueRelation.issue_id]
            if ret.get(excalidraw.id) is not None:
                ret[excalidraw.id]["issue_ids"] += issue_id
                continue
        else:
            issue_id = []
        
        ret[excalidraw.id] = {
            "id": excalidraw.id,
            "issue_ids": issue_id,
            "name": excalidraw.name,
            "url": get_excalidraw_url(excalidraw),
            "created_at": str(excalidraw.created_at),
            "updated_at": str(excalidraw.updated_at),
            "project":  {"id": project.id, "name": project.name, "display": project.display},
            "operator": {"id": user.id, "name": user.name, "login": user.login}
        }
    return list(ret.values())


def create_excalidraw(args):
    operator_id = get_jwt_identity()['user_id']
    project_id, issue_ids, name = args["project_id"], args.get("issue_ids"), args["name"]
    has_issue_ids = issue_ids is not None
    datetime_now = datetime.utcnow()
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
        created_at=datetime_now,
        updated_at=datetime_now,
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
    
    return {
        "id": row.id,
        "name": name,
        "project_id": project_id,
        "created_at": str(datetime_now),
        "url": f'{excalidraw_get_config("excalidraw-url")}/#room={room},{key}',
        "issue_ids": [int(issue_id) for issue_id in issue_ids.split(",")] if \
            has_issue_ids else []
    }


def get_excalidraws(args):
    project_id, name = args.get("project_id"), args.get("name")
    user_id = get_jwt_identity()['user_id']
    not_admin_user = user.get_role_id(user_id) != role.ADMIN.id
    excalidraw_rows = db.session.query(Excalidraw, ExcalidrawIssueRelation, User, Project).outerjoin(
        ExcalidrawIssueRelation, Excalidraw.id==ExcalidrawIssueRelation.excalidraw_id).join(
        User, Excalidraw.operator_id==User.id).join(Project, Excalidraw.project_id==Project.id)
    user_project_ids = [
        project.project_id for project in ProjectUserRole.query.filter_by(user_id=user_id).all()]
    
    if project_id is not None:
        if project_id not in user_project_ids and not_admin_user:
            raise apiError.NotInProjectError('You need to be in the project for this operation.')
        excalidraw_rows = excalidraw_rows.filter(Excalidraw.project_id==project_id)
    elif not_admin_user:
        excalidraw_rows = excalidraw_rows.filter(Excalidraw.project_id.in_(user_project_ids))
    
    if name is not None:
        excalidraw_rows = excalidraw_rows.filter(Excalidraw.name.ilike(f'%{name}%'))
    
    return nexus_excalidraw(excalidraw_rows)


def get_excalidraw_by_issue_id(issue_id):
    excalidraw_ids = [
        excalidraw_rel.excalidraw_id for excalidraw_rel in ExcalidrawIssueRelation.query.filter_by(issue_id=issue_id)]
    if excalidraw_ids == []:
        return []

    excalidraw_rows = db.session.query(Excalidraw, ExcalidrawIssueRelation, User, Project).join(
        ExcalidrawIssueRelation, Excalidraw.id==ExcalidrawIssueRelation.excalidraw_id).join(
        User, Excalidraw.operator_id==User.id).join(Project, Excalidraw.project_id==Project.id).filter(
        Excalidraw.id.in_(excalidraw_ids))
    
    return nexus_excalidraw(excalidraw_rows)


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
        if issue_ids != "":
            issue_ids = list(map(lambda x: int(x) ,issue_ids.split(",")))
            for issue_id in issue_ids:
                if int(issue_id) not in exist_issue_ids:
                    raise DevOpsError(400, f'Argument issue_ids include invalid issue_id.',
                                        error=apiError.argument_error("issue_ids")) 
        else:
            issue_ids = []
            
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
            for excalidraw_issue in excalidraw_issues]

    excalidraw.updated_at = datetime.utcnow()
    db.session.commit()

    return {
        "id": excalidraw_id,
        "name": name,
        "issue_ids": issue_ids,
        "url": get_excalidraw_url(excalidraw)
    }


def sync_excalidraw_db():
    # prod
    database = excalidraw_get_config("excalidraw-db-database") 
    user = excalidraw_get_config("excalidraw-db-account") 
    password = excalidraw_get_config("excalidraw-db-password") 
    host = excalidraw_get_config("excalidraw-db-host") 
    port = excalidraw_get_config("excalidraw-db-port")
    excalidraw_keys = ",".join([f"'ROOMS:{excalidraw.room}'" for excalidraw in Excalidraw.query.all()])
    
    conn = psycopg2.connect(
        database=database,
        user=user,
        password=password,
        host=host,
        port=port
    )
    try:
        cur = conn.cursor()
        cur.execute(
            f'''
            DELETE FROM public.keyv
            WHERE key NOT IN ({excalidraw_keys});
            '''
        )
        conn.commit()
    except Exception as e:
        print(str(e))
    finally:
        conn.close()


def check_excalidraw_alive(excalidraw_url=None, excalidraw_socket_url=None):
    excalidraw_url = excalidraw_url or excalidraw_get_config("excalidraw-url")
    excalidraw_socket_url = excalidraw_socket_url or excalidraw_get_config("excalidraw-socket-url")
    
    not_alive_services = []
    ret = {"alive": True, "services": {"API": True, "UI": True, "Socket": True}}

    api_url_list = excalidraw_url.split("://")
    api_url_list[-1] = f"api-{api_url_list[-1]}api/v2"
    api_url = "://".join(api_url_list)

    socket_url_list = excalidraw_socket_url.split("/")
    if socket_url_list[-1] == "socket.io":
        socket_url_list = socket_url_list[:-1]
    socket_url = "/".join(socket_url_list) + "/"

    for service, url in {"UI": excalidraw_url, "Socket": socket_url, "API": api_url}.items():
        if not check_url_alive(url, is_200=True):
            ret["alive"] = ret["services"][service] = False
            not_alive_services.append(service)
    if not_alive_services != []:
        ret["message"] = f'{", ".join(not_alive_services)} not alive'
    return ret
