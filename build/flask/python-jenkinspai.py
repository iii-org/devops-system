import jenkinsapi

Job_name='iii-DevOps-testing-on-Kubernetes'

Jenkins_server = jenkinsapi.jenkins.Jenkins('http://10.50.1.68:8080', username='admin', password='1qaz2wsx')

if Jenkins_server.has_job(Job_name) is not True:
    Jenkins_server.build_job(Job_name)

#Jenkins_server.keys()
#Jenkins_server[]

DevOps_Job = Jenkins_server.get_job(Job_name)
print(DevOps_Job.get_full_name())
