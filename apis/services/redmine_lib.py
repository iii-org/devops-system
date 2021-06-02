from redminelib import Redmine

import config

redmine = Redmine(config.get('REDMINE_INTERNAL_BASE_URL'),
                  key=config.get('REDMINE_API_KEY'))

STATUS_ID_ISSUE_CLOSED = 6


def rm_impersonate(user_name):
    return Redmine(config.get('REDMINE_INTERNAL_BASE_URL'), key=config.get('REDMINE_API_KEY'),
                   impersonate=user_name)
