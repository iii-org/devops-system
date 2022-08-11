import json
from .ui_route_upgrade import create_ui_route_object


def add_harbor_ui_route_children():

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

    create_ui_route_object("PodsLists", "Project Manager", artifacts_dict_dict, "Harbors", "Artifacts")
    #create_ui_route_object("PodsList", "Project Manager", pod_list_dict, "PodsLists", "")
    #create_ui_route_object("PodExecuteShell", "Project Manager", pod_exec_dict, "PodsLists", "PodsList")
    #create_ui_route_object("ServiceList", "Project Manager", service_list_dict, "Harbors", "PodsLists")
    #create_ui_route_object("SecretList", "Project Manager", secret_list_dict, "Harbors", "ServiceList")
    #create_ui_route_object("ConfigMapsList", "Project Manager", configmaps_list_dict, "Harbors", "SecretList")
    #create_ui_route_object("DeploymentList", "Project Manager", deploy_list_dict, "Harbors", "ConfigMapsList")
    #create_ui_route_object("IngressesList", "Project Manager", ingress_list_dict, "Harbors", "DeploymentList")
