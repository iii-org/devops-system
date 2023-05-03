from . import view


def monitoring_url(api, add_resource):
    api.add_resource(view.ServicesListV2, "/v2/monitoring/services_list")
    add_resource(view.ServicesListV2, "public")
    api.add_resource(view.ServersAliveHelper, "/v2/monitoring/check_alive")
    add_resource(view.ServersAliveHelper, "public")
    api.add_resource(view.ServersAlive, "/monitoring/alive")
    api.add_resource(view.ServersAliveV2, "/v2/monitoring/alive")
    add_resource(view.ServersAliveV2, "public")
    api.add_resource(view.RedmineAlive, "/monitoring/redmine/alive")
    api.add_resource(view.RedmineAliveV2, "/v2/monitoring/redmine/alive")
    add_resource(view.RedmineAliveV2, "public")
    api.add_resource(view.GitlabAlive, "/monitoring/gitlab/alive")
    api.add_resource(view.GitlabAliveV2, "/v2/monitoring/gitlab/alive")
    add_resource(view.GitlabAliveV2, "public")
    api.add_resource(view.HarborAlive, "/monitoring/harbor/alive")
    api.add_resource(view.HarborAliveV2, "/v2/monitoring/harbor/alive")
    add_resource(view.HarborAliveV2, "public")
    api.add_resource(view.HarborStorage, "/monitoring/harbor/usage")
    api.add_resource(view.HarborStorageV2, "/v2/monitoring/harbor/usage")
    add_resource(view.HarborStorageV2, "public")
    api.add_resource(view.HarborProxy, "/monitoring/harbor/pull_limit")
    api.add_resource(view.HarborProxyV2, "/v2/monitoring/harbor/pull_limit")
    add_resource(view.HarborProxyV2, "public")
    api.add_resource(view.SonarQubeAlive, "/monitoring/sonarqube/alive")
    api.add_resource(view.SonarQubeAliveV2, "/v2/monitoring/sonarqube/alive")
    add_resource(view.SonarQubeAliveV2, "public")
    api.add_resource(view.K8sAlive, "/monitoring/kubernetes/alive")
    api.add_resource(view.K8sAliveV2, "/v2/monitoring/kubernetes/alive")
    add_resource(view.K8sAliveV2, "public")
    api.add_resource(view.ExcalidrawAliveV2, "/v2/monitoring/excalidraw/alive")
    add_resource(view.ExcalidrawAliveV2, "public")
    api.add_resource(view.CollectPodRestartTime, "/monitoring/k8s/collect_pod_restart_times_by_hour")
    api.add_resource(
        view.CollectPodRestartTimeV2,
        "/v2/monitoring/k8s/collect_pod_restart_times_by_hour",
    )
    add_resource(view.CollectPodRestartTimeV2, "public")
    api.add_resource(view.GithubTokenVerify, "/monitoring/github/validate_token")
    api.add_resource(view.GithubTokenVerifyV2, "/v2/monitoring/github/validate_token")
    add_resource(view.GithubTokenVerifyV2, "public")
