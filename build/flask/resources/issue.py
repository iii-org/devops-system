

class Issue(object):
    
    def __init__(self):
        pass

    def get_issue(self, logger, app):
        logger.info("app.config: {0}".format(app.config['REDMINE_URL']))
        logger.info("app.config: {0}".format(app.config['REDMINE_ADMIN_ACCOUNT']))
        logger.info("app.config: {0}".format(app.config['REDMINE_ADMIN_PASSWORD']))
    
