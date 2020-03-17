import jenkins

Job_name='iii-DevOps-testing-on-Kubernetes'

server = jenkins.Jenkins('http://10.50.1.68:8080', username='admin', password='1qaz2wsx')
user = server.get_whoami()
version = server.get_version()
print('Hello %s from Jenkins %s' % (user['fullName'], version))
print (server.jobs_count())

#server.create_job('Job1', jenkins.EMPTY_CONFIG_XML)
# jobs = server.get_jobs()

if server.job_exists(Job_name) != True:
    server.build_job(Job_name)



#plugins = server.get_plugins_info()
#print (plugins)