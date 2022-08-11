from .ui_route_upgrade import create_ui_route_object

artifacts_dict_dict = {
    "path": "podsLists",
    "hidden": True,
    "component": "layout/components/parentBlank",
    "name": "PodsLists",
    "redirect": {
            "name": "PodsList"
    },
    "meta": {
        "title": "PodsLists",
        "roles": [
            "Engineer",
            "Project Manager",
            "Administrator"
        ]
    }
}
pod_list_dict = {
    "path": "",
    "name": "PodsList",
    "hidden": True,
    "component": "views/SystemResource/PluginResource/components/PodsList",
    "meta": {
            "roles": [
                "Engineer",
                "Project Manager",
                "Administrator"
            ]
    }
}
pod_exec_dict = {
    "path": "podExecuteShell",
    "name": "PodExecuteShell",
    "hidden": True,
    "component": "views/SystemResource/PluginResource/components/PodsList/components/PodExecuteShell",
    "meta": {
            "title": "PodExecuteShell",
            "roles": [
                "Engineer",
                "Project Manager",
                "Administrator"
            ]
    }
}
service_list_dict = {
    "path": "serviceList",
    "name": "ServiceList",
    "hidden": True,
    "component": "views/SystemResource/PluginResource/components/ServiceList",
    "meta": {
            "title": "ServiceList",
            "roles": [
                "Engineer",
                "Project Manager",
                "Administrator"
            ]
    }
}
secret_list_dict = {
    "path": "secretList",
    "name": "SecretList",
    "hidden": True,
    "component": "views/SystemResource/PluginResource/components/SecretList",
    "meta": {
            "title": "SecretList",
            "roles": [
                "Engineer",
                "Project Manager",
                "Administrator"
            ]
    }
}
configmaps_list_dict = {
    "path": "configmapsList",
    "name": "ConfigMapsList",
    "hidden": True,
    "component": "views/SystemResource/PluginResource/components/ConfigMapsList",
    "meta": {
            "title": "ConfigMapsList",
            "roles": [
                "Engineer",
                "Project Manager",
                "Administrator"
            ]
    }
}
deploy_list_dict = {
    "path": "deploymentList",
    "name": "DeploymentList",
    "hidden": True,
    "component": "views/SystemResource/PluginResource/components/DeploymentList",
    "meta": {
            "title": "DeploymentList",
            "roles": [
                "Engineer",
                "Project Manager",
                "Administrator"
            ]
    }
}
ingress_list_dict = {
    "path": "ingressesList",
    "name": "IngressesList",
    "hidden": True,
    "component": "views/SystemResource/PluginResource/components/IngressesList",
    "meta": {
            "title": "IngressesList",
            "roles": [
                "Engineer",
                "Project Manager",
                "Administrator"
            ]
    }
}


system_resource_dict = {
    "path": "/systemResource",
    "component": "layout",
    "name": "SystemResource",
    "redirect": {
            "name": "PluginResource"
    },
    "meta": {
        "title": "SystemResource",
        "icon": "el-icon-pie-chart",
        "roles": [
                "Engineer",
                "Project Manager",
                "Administrator"
        ]
    }
}
plugin_resources_dict = {
    "path": ":projectName?/pluginResource",
    "component": "layout/components/parentBlank",
    "name": "PluginResources",
    "redirect": {
            "name": "PluginResource"
    },
    "meta": {
        "title": "PluginResource",
        "roles": [
            "Engineer",
            "Project Manager",
            "Administrator"
        ]
    }
}
plugin_resource_dict = {
    "path": "",
    "name": "PluginResource",
    "hidden": True,
    "component": "views/SystemResource/PluginResource",
    "meta": {
        "roles": [
            "Engineer",
            "Project Manager",
            "Administrator"
        ]
    }
}
harbors_dict = {
    "path": "harbor",
    "hidden": True,
    "component": "layout/components/parentBlank",
    "name": "Harbors",
    "redirect": {
        "name": "Harbor"
    },
    "meta": {
        "title": "Harbor",
        "roles": [
            "Engineer",
            "Project Manager",
            "Administrator"
        ]
    }
}
harbor_dict = {
    "path": "",
    "name": "Harbor",
    "hidden": True,
    "component": "views/SystemResource/Harbor/ResourceHarbor",
    "meta": {
        "roles": [
            "Engineer",
            "Project Manager",
            "Administrator"
        ]
    }
}
artifacts_dict = {
    "path": ":rName/artifacts",
    "name": "Artifacts",
    "hidden": True,
    "component": "views/SystemResource/Harbor/components/ProjectArtifacts",
    "meta": {
        "title": "Artifacts",
        "roles": [
            "Engineer",
            "Project Manager",
            "Administrator"
        ]
    }
}
service_monitoring_dict = {
    "path": "serviceMonitoring",
    "name": "ServiceMonitoring",
    "component": "views/SystemResource/ServiceMonitoring",
    "meta": {
        "title": "ServiceMonitoring",
        "roles": [
            "Engineer",
            "Project Manager",
            "Administrator"
        ]
    }
}


def add_harbor_ui_route_children():
    create_ui_route_object("PodsLists", "Project Manager", artifacts_dict_dict, "Harbors", "Artifacts")
    create_ui_route_object("PodsList", "Project Manager", pod_list_dict, "PodsLists", "")
    create_ui_route_object("PodExecuteShell", "Project Manager", pod_exec_dict, "PodsLists", "PodsList")
    create_ui_route_object("ServiceList", "Project Manager", service_list_dict, "Harbors", "PodsLists")
    create_ui_route_object("SecretList", "Project Manager", secret_list_dict, "Harbors", "ServiceList")
    create_ui_route_object("ConfigMapsList", "Project Manager", configmaps_list_dict, "Harbors", "SecretList")
    create_ui_route_object("DeploymentList", "Project Manager", deploy_list_dict, "Harbors", "ConfigMapsList")
    create_ui_route_object("IngressesList", "Project Manager", ingress_list_dict, "Harbors", "DeploymentList")

    create_ui_route_object("PodsLists", "Administrator", artifacts_dict_dict, "Harbors", "Artifacts")
    create_ui_route_object("PodsList", "Administrator", pod_list_dict, "PodsLists", "")
    create_ui_route_object("PodExecuteShell", "Administrator", pod_exec_dict, "PodsLists", "PodsList")
    create_ui_route_object("ServiceList", "Administrator", service_list_dict, "Harbors", "PodsLists")
    create_ui_route_object("SecretList", "Administrator", secret_list_dict, "Harbors", "ServiceList")
    create_ui_route_object("ConfigMapsList", "Administrator", configmaps_list_dict, "Harbors", "SecretList")
    create_ui_route_object("DeploymentList", "Administrator", deploy_list_dict, "Harbors", "ConfigMapsList")
    create_ui_route_object("IngressesList", "Administrator", ingress_list_dict, "Harbors", "DeploymentList")

    create_ui_route_object("SystemResource", "Engineer", system_resource_dict, "", "Scan")
    create_ui_route_object("PluginResources", "Engineer", plugin_resources_dict, "SystemResource", "")
    create_ui_route_object("PluginResource", "Engineer", plugin_resource_dict, "PluginResources", "")
    create_ui_route_object("Harbors", "Engineer", harbors_dict, "PluginResources", "PluginResource")
    create_ui_route_object("Harbor", "Engineer", harbor_dict, "Harbors", "")
    create_ui_route_object("Artifacts", "Engineer", artifacts_dict, "Harbors", "Harbor")
    create_ui_route_object("PodsLists", "Engineer", artifacts_dict_dict, "Harbors", "Artifacts")
    create_ui_route_object("PodsList", "Engineer", pod_list_dict, "PodsLists", "")
    create_ui_route_object("PodExecuteShell", "Engineer", pod_exec_dict, "PodsLists", "PodsList")
    create_ui_route_object("ServiceList", "Engineer", service_list_dict, "Harbors", "PodsLists")
    create_ui_route_object("SecretList", "Engineer", secret_list_dict, "Harbors", "ServiceList")
    create_ui_route_object("ConfigMapsList", "Engineer", configmaps_list_dict, "Harbors", "SecretList")
    create_ui_route_object("DeploymentList", "Engineer", deploy_list_dict, "Harbors", "ConfigMapsList")
    create_ui_route_object("IngressesList", "Engineer", ingress_list_dict, "Harbors", "DeploymentList")
    create_ui_route_object("ServiceMonitoring", "Engineer", service_monitoring_dict,
                           "SystemResource", "PluginResources")
