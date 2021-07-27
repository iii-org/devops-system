from redminelib import Redmine
import requests

import config

redmine = Redmine(config.get('REDMINE_INTERNAL_BASE_URL'),
                  key=config.get('REDMINE_API_KEY'), requests={'verify': False})

STATUS_ID_ISSUE_CLOSED = 6

def __refresh_redmine_by_key(plan_operator_id=None):
    protocol = 'https' if config.get('REDMINE_INTERNAL_BASE_URL')[:5] == "https" else 'http'
    host = config.get('REDMINE_INTERNAL_BASE_URL')[len(protocol + '://'):]
    if plan_operator_id is None:
        redmine = Redmine(config.get('REDMINE_INTERNAL_BASE_URL'),
                        key=config.get('REDMINE_API_KEY'), requests={'verify': False})
    else:
        url = f"{protocol}://{config.get('REDMINE_ADMIN_ACCOUNT')}" \
                f":{config.get('REDMINE_ADMIN_PASSWORD')}" \
                f"@{host}/users/{plan_operator_id}.json"
        output = requests.get(url, headers={'Content-Type': 'application/json'}, verify=False)
        redmine_key = output.json()['user']['api_key']
        redmine = Redmine(config.get('REDMINE_INTERNAL_BASE_URL'),
                        key=redmine_key, requests={'verify': False})
    return redmine


def rm_impersonate(user_name):
    return Redmine(config.get('REDMINE_INTERNAL_BASE_URL'), key=config.get('REDMINE_API_KEY'),
                   impersonate=user_name)


def rm_post_relation(issue_id, issue_to_id, plan_operator_id=None):
    relation = __refresh_redmine_by_key(plan_operator_id).issue_relation.new()
    relation.issue_id = issue_id
    relation.issue_to_id = issue_to_id
    relation.relation_type = 'relates'
    relation.save()
    return {"relation_id": relation.id}


def rm_delete_relation(relation_id, plan_operator_id=None):
    __refresh_redmine_by_key(plan_operator_id).issue_relation.delete(relation_id)