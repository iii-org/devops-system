

from resources import monitoring 


def monitoring_url(api, add_resource):
    api.add_resource(monitoring.ServersAlive, '/monitoring/alive')
    api.add_resource(monitoring.ServersAliveV2, '/v2/monitoring/alive')
    add_resource(monitoring.ServersAliveV2, "public")
    api.add_resource(monitoring.RedmineAlive, '/monitoring/redmine/alive')
    api.add_resource(monitoring.RedmineAliveV2, '/v2/monitoring/redmine/alive')
    add_resource(monitoring.RedmineAliveV2, "public")
    api.add_resource(monitoring.GitlabAlive, '/monitoring/gitlab/alive')
    api.add_resource(monitoring.GitlabAliveV2, '/v2/monitoring/gitlab/alive')
    add_resource(monitoring.GitlabAliveV2, "public")
    api.add_resource(monitoring.HarborAlive, '/monitoring/harbor/alive')
    api.add_resource(monitoring.HarborAliveV2, '/v2/monitoring/harbor/alive')
    add_resource(monitoring.HarborAliveV2, "public")
    api.add_resource(monitoring.HarborStorage, '/monitoring/harbor/usage')
    api.add_resource(monitoring.HarborStorageV2, '/v2/monitoring/harbor/usage')
    add_resource(monitoring.HarborStorageV2, "public")
    api.add_resource(monitoring.HarborProxy, '/monitoring/harbor/pull_limit')
    api.add_resource(monitoring.HarborProxyV2, '/v2/monitoring/harbor/pull_limit')
    add_resource(monitoring.HarborProxyV2, "public")
    api.add_resource(monitoring.SonarQubeAlive, '/monitoring/sonarqube/alive')
    api.add_resource(monitoring.SonarQubeAliveV2, '/v2/monitoring/sonarqube/alive')
    add_resource(monitoring.SonarQubeAliveV2, "public")
    api.add_resource(monitoring.RancherAlive, '/monitoring/rancher/alive')
    api.add_resource(monitoring.RancherAliveV2, '/v2/monitoring/rancher/alive')
    add_resource(monitoring.RancherAliveV2, "public")
    api.add_resource(monitoring.RancherDefaultName, '/monitoring/rancher/default_name')
    api.add_resource(monitoring.RancherDefaultNameV2, '/v2/monitoring/rancher/default_name')
    add_resource(monitoring.RancherDefaultNameV2, "public")
    api.add_resource(monitoring.K8sAlive, '/monitoring/k8s/alive')
    api.add_resource(monitoring.K8sAliveV2, '/v2/monitoring/k8s/alive')
    add_resource(monitoring.K8sAliveV2, "public")
    api.add_resource(monitoring.CollectPodRestartTime, '/monitoring/k8s/collect_pod_restart_times_by_hour')
    api.add_resource(monitoring.CollectPodRestartTimeV2, '/v2/monitoring/k8s/collect_pod_restart_times_by_hour')
    add_resource(monitoring.CollectPodRestartTimeV2, "public")
    api.add_resource(monitoring.PodAlert, '/monitoring/k8s/pod_alert')
    api.add_resource(monitoring.PodAlertV2, '/v2/monitoring/k8s/pod_alert')
    add_resource(monitoring.PodAlertV2, "private")
    api.add_resource(monitoring.RemoveExtraExecutions, '/monitoring/k8s/remove_extra_executions')
    api.add_resource(monitoring.RemoveExtraExecutionsV2, '/v2/monitoring/k8s/remove_extra_executions')
    add_resource(monitoring.RemoveExtraExecutionsV2, "public")
    api.add_resource(monitoring.GithubTokenVerify, '/monitoring/github/validate_token')
    api.add_resource(monitoring.GithubTokenVerifyV2, '/v2/monitoring/github/validate_token')
    add_resource(monitoring.GithubTokenVerifyV2, "public")