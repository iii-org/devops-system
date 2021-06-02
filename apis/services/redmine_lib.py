from redminelib import Redmine

import config

redmine = Redmine(config.get('REDMINE_INTERNAL_BASE_URL'),
                  key=config.get('REDMINE_API_KEY'))


def rm_impersonate(user_name):
    return Redmine(config.get('REDMINE_INTERNAL_BASE_URL'), key=config.get('REDMINE_API_KEY'),
                   impersonate=user_name)


def rm_post_relation(issue_id, issue_to_id):
    relation = redmine.issue_relation.new()
    relation.issue_id = issue_id
    relation.issue_to_id = issue_to_id
    relation.relation_type = 'relates'
    relation.save()
    return {"relation_id": relation.id}


def rm_delete_relation(relation_id):
    redmine.issue_relation.delete(relation_id)