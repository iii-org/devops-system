# Redmine config
REDMINE_IP_PORT = '10.50.1.56:32748'
REDMINE_ADMIN_ACCOUNT = 'admin'
REDMINE_ADMIN_PASSWORD = 'openstack'

# Gitlab config
GITLAB_API_VERSION = 'v4'
GITLAB_IP_PORT = '10.50.1.53'
GITLAB_ADMIN_ACCOUNT = 'root'
GITLAB_ADMIN_PASSWORD = 'openstack'
GITLAB_PRIVATE_TOKEN = '_gTC84sWy8QgrXwzmz3D'

# Rancher config
RANCHER_API_VERSION = 'v3'
RANCHER_IP_PORT = '10.50.1.57'
RANCHER_ADMIN_ACCOUNT = 'admin'
RANCHER_ADMIN_PASSWORD = 'openstack'

#DB
#SQLALCHEMY_DATABASE_URI = 'postgresql://postgres:iiidevops@devopsdb-service:5432/devopsdb'
SQLALCHEMY_DATABASE_URI = 'postgresql://postgres:iiidevops@10.50.1.56:31403/devopsdb'
SQLALCHEMY_TRACK_MODIFICATIONS = False

# jwt
JWT_SECRET_KEY = 'iii-devops'