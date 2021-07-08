import json
import requests
import util as util
from flask_jwt_extended import jwt_required, get_jwt_identity
from flask_restful import Resource, reqparse
from resources import apiError
from resources.apiError import DevOpsError
from resources.logger import logger
get_router_error = "Without Router Definition "

default_json = [
    {
        "path": "/project",
        "component": "Layout",
        "name": "project",
        "redirect": "/project/overview",
        "meta": {
            "title": "singleProject",
            "icon": "el-icon-data-analysis"
        },
        "children": [
            {
                "path": "overview",
                "name": "Overview",
                "component": "Project/Overview",
                "meta": {
                    "title": "projectOverview"
                }
            },
            {
                "path": "issue-boards",
                "name": "issue-boards",
                "component": "Project/IssueBoards",
                "meta": {
                    "title": "kanban"
                }
            },
            {
                "path": "issues",
                "component": "parentBlank",
                "children": [
                    {
                        "path": "",
                        "name": "issue-list",
                        "component": "Project/IssueList",
                        "meta": {
                            "title": "issueList"
                        }
                    },
                    {
                        "path": ":issueId",
                        "name": "issue-detail",
                        "hidden": True,
                        "component": "Project/IssueDetail",
                        "meta": {
                            "title": "Issue Detail"
                        }
                    }
                ]
            },
            {
                "path": "test-case",
                "component": "parentBlank",
                "meta": {
                    "title": "createTest"
                },
                "children": [
                    {
                        "path": "",
                        "name": "test-case",
                        "component": "Project/TestCase/TestCase",
                        "hidden": True,
                        "meta": {}
                    },
                    {
                        "path": "test-item/:testCaseId",
                        "name": "test-item",
                        "component": "Project/TestCase/TestItem",
                        "hidden": True,
                        "meta": {
                            "title": "testItem"
                        }
                    }
                ]
            },
            {
                "path": "wiki",
                "name": "wiki-list",
                "component": "Project/Wiki",
                "meta": {
                    "title": "wikiList"
                }
            },
            {
                "path": "file",
                "name": "file-list",
                "component": "Project/Files",
                "meta": {
                    "title": "fileList"
                }
            },
            {
                "path": "roadmap",
                "name": "Project Roadmap",
                "component": "Project/Roadmap",
                "meta": {
                    "title": "Project Roadmap"
                }
            },
            {
                "path": "/release-version",
                "name": "releaseVersion",
                "component": "Project/ReleaseVersion",
                "meta": {
                    "title": "releaseVersion"
                }
            },
            {
                "path": "settings",
                "component": "parentBlank",
                "meta": {
                    "title": "Project Settings"
                },
                "children": [
                    {
                        "path": "",
                        "name": "Project Settings",
                        "hidden": True,
                        "component": "Project/Settings/index",
                        "meta": {}
                    },
                    {
                        "path": "advance-branch-settings",
                        "name": "advance-branch-settings",
                        "hidden": True,
                        "component": "Project/Settings/components/AdvanceBranchSettings",
                        "meta": {
                            "title": "advanceBranchSettings"
                        }
                    }
                ]
            }
        ]
    },
    {
        "path": "/progress",
        "component": "Layout",
        "name": "progress",
        "redirect": "/progress/git-graph",
        "meta": {
            "title": "devProgress",
            "icon": "el-icon-odometer"
        },
        "children": [
            {
                "path": "dev-branch",
                "name": "dev-branch",
                "component": "/Progress/DevBranch",
                "meta": {
                    "title": "devBranch"
                }
            },
            {
                "path": "git-graph",
                "name": "git-graph",
                "component": "Progress/GitGraph",
                "meta": {
                    "title": "gitGraph"
                }
            },
            {
                "path": "pipelines",
                "name": "Pipelines",
                "component": "Progress/Pipelines",
                "meta": {
                    "title": "pipelines"
                }
            },
            {
                "path": "dev-environment",
                "name": "dev-environment",
                "component": "Progress/DevEnvironment",
                "meta": {
                    "title": "devEnvironment"
                }
            },
            {
                "path": "kubernetes-resources",
                "component": "parentBlank",
                "meta": {
                    "title": "kubernetesResources"
                },
                "children": [
                    {
                        "path": "",
                        "name": "Kubernetes-resources",
                        "component": "Progress/KubernetesResources",
                        "hidden": True,
                        "meta": {}
                    },
                    {
                        "path": "deployment-list",
                        "name": "Deployment List",
                        "hidden": True,
                        "component": "Progress/KubernetesResources/components/DeploymentList",
                        "meta": {
                            "title": "Deployment List"
                        }
                    },
                    {
                        "path": "pods-list",
                        "name": "Pods List",
                        "hidden": True,
                        "component": "Progress/KubernetesResources/components/PodsList",
                        "meta": {
                            "title": "Pods List"
                        }
                    },
                    {
                        "path": "service-list",
                        "name": "Service List",
                        "hidden": True,
                        "component": "Progress/KubernetesResources/components/ServiceList",
                        "meta": {
                            "title": "Service List"
                        }
                    },
                    {
                        "path": "secret-list",
                        "name": "Secret List",
                        "hidden": True,
                        "component": "Progress/KubernetesResources/components/SecretList",
                        "meta": {
                            "title": "Secret List"
                        }
                    },
                    {
                        "path": "configmaps-list",
                        "name": "ConfigMaps List",
                        "hidden": True,
                        "component": "Progress/KubernetesResources/components/ConfigMapsList",
                        "meta": {
                            "title": "ConfigMaps List"
                        }
                    },
                    {
                        "path": "ingresses-list",
                        "name": "Ingresses List",
                        "hidden": True,
                        "component": "Progress/KubernetesResources/components/IngressesList",
                        "meta": {
                            "title": "Ingresses List"
                        }
                    }
                ]
            }
        ]
    },
    {
        "path": "/scan",
        "component": "Layout",
        "name": "scan",
        "meta": {
            "title": "autoTesting",
            "icon": "el-icon-circle-check"
        },
        "redirect": "/scan/postman",
        "children": [
            {
                "path": "postman",
                "component": "parentBlank",
                "meta": {
                    "title": "postman"
                },
                "children": [
                    {
                        "path": "",
                        "name": "postman",
                        "hidden": True,
                        "component": "Scan/Postman",
                        "meta": {}
                    },
                    {
                        "path": "devops/:id",
                        "name": "devops-test-case",
                        "hidden": True,
                        "component": "Scan/TestCaseDevOps",
                        "meta": {
                            "title": "fromDevops"
                        }
                    },
                    {
                        "path": "postman/:id",
                        "name": "postman-test-case",
                        "hidden": True,
                        "component": "Scan/TestCasePostman",
                        "meta": {
                            "title": "fromCollection"
                        }
                    }
                ]
            },
            {
                "path": "checkmarx",
                "name": "checkmarx",
                "component": "Scan/Checkmarx",
                "meta": {
                    "title": "checkMarx"
                }
            },
            {
                "path": "web-inspect",
                "component": "parentBlank",
                "meta": {
                    "title": "webInspect"
                },
                "children": [
                    {
                        "path": "",
                        "name": "webinspect",
                        "hidden": True,
                        "component": "Scan/WebInspect",
                        "meta": {}
                    },
                    {
                        "path": "report/:scan_id",
                        "name": "webInspectReport",
                        "component": "Scan/WIEReportViewer",
                        "hidden": True,
                        "meta": {
                            "title": "webInspectReport"
                        }
                    }
                ]
            },
            {
                "path": "zap",
                "name": "zap",
                "component": "Scan/Zap",
                "meta": {
                    "title": "zap"
                }
            },
            {
                "path": "sideex",
                "name": "sideex",
                "component": "Scan/Sideex",
                "meta": {
                    "title": "sideex"
                }
            },
            {
                "path": "sonarqube",
                "name": "sonarqube",
                "component": "Scan/SonarQube",
                "meta": {
                    "title": "sonarQube"
                }
            }
        ]
    },
    {
        "path": "/system-resource",
        "component": "Layout",
        "name": "System Resource",
        "redirect": "/system-resource/plugin-resource",
        "meta": {
            "title": "System Resource",
            "icon": "el-icon-pie-chart"
        },
        "children": [
            {
                "path": "plugin-resource",
                "component": "parentBlank",
                "meta": {
                    "title": "Plugin Resource"
                },
                "children": [
                    {
                        "path": "",
                        "name": "Plugin Resource",
                        "hidden": True,
                        "component": "SystemResource/PluginResource",
                        "meta": {}
                    },
                    {
                        "path": "harbor",
                        "hidden": True,
                        "component": "parentBlank",
                        "meta": {
                            "title": "Harbor"
                        },
                        "children": [
                            {
                                "path": "",
                                "name": "Harbor",
                                "hidden": True,
                                "component": "SystemResource/Harbor/ResourceHarbor",
                                "meta": {}
                            },
                            {
                                "path": "artifacts",
                                "name": "Artifacts",
                                "hidden": True,
                                "component": "SystemResource/Harbor/components/ProjectArtifacts",
                                "meta": {
                                    "title": "Artifacts"
                                }
                            }
                        ]
                    }
                ]
            }
        ]
    },
    {
        "path": "/activities",
        "component": "Layout",
        "name": "Activities",
        "redirect": "/activities/project-activities",
        "meta": {
            "title": "Activities",
            "icon": "el-icon-s-order"
        },
        "children": [
            {
                "path": "project-activities",
                "name": "ProjectActivities",
                "component": "Activities/ProjectActivities",
                "meta": {
                    "title": "Project Activities"
                }
            }
        ]
    },
    {
        "path": "/system-settings",
        "component": "Layout",
        "name": "Admin",
        "redirect": "/system-settings/account-manage",
        "meta": {
            "title": "Admin",
            "icon": "el-icon-setting"
        },
        "children": [
            {
                "path": "account-manage",
                "name": "",
                "component": "SystemSettings/AccountManage",
                "meta": {
                    "title": "Account Manage"
                }
            },
            {
                "path": "participate-project/:user_id",
                "name": "ParticipateProject",
                "hidden": True,
                "component": "SystemSettings/AccountManage/components/ParticipateProject",
                "meta": {
                    "title": "Participate Project"
                }
            },
            {
                "path": "system-activities",
                "name": "SystemActivities",
                "component": "SystemSettings/SystemActivities",
                "meta": {
                    "title": "System Activities"
                }
            },
            {
                "path": "system-arguments",
                "name": "System Arguments",
                "component": "SystemSettings/SystemArguments",
                "meta": {
                    "title": "System Arguments"
                }
            },
            {
                "path": "sub-admin-projects",
                "name": "Sub Admin Projects",
                "component": "SystemSettings/SubAdminProjects",
                "meta": {
                    "title": "Project Settings (QA)"
                }
            },
            {
                "path": "system-plugin-manage",
                "name": "System Plugin Manage",
                "component": "SystemSettings/SystemPluginManage",
                "meta": {
                    "title": "System Plugin Manage"
                }
            }
        ]
    },
    {
        "path": "/profile",
        "component": "Layout",
        "redirect": "/profile",
        "hidden": True,
        "children": [
            {
                "path": "",
                "component": "Profile",
                "name": "Profile",
                "meta": {
                    "title": "Profile",
                    "icon": "user",
                    "noCache": True
                }
            }
        ]
    },
    {
        "path": "/SystemVersion",
        "component": "Layout",
        "redirect": "/SystemVersion",
        "hidden": True,
        "meta": {},
        "children": [
            {
                "path": "",
                "component": "SystemVersion",
                "name": "SystemVersion",
                "meta": {
                    "title": "System Version",
                    "icon": "user",
                    "noCache": True
                }
            }
        ]
    }
]



class Router(Resource):
    @jwt_required
    def get(self):
        try:
            return util.success(default_json)
        except DevOpsError:
            return util.respond(404, get_router_error
                                )
