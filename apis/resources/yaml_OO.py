class RancherPipelineYaml:
    def __init__(self):
        self.stages = RancherPipelineStage
        self.when = RancherPipelineWhen




class RancherPipelineStep:
    def __init__(self):
        self.runScriptConfig = RancherPipelineRunScriptConfig
        self.publishImageConfig = RancherPipelinePublishImageConfig
        self.applyYamlConfig = RancherPipelineApplyYamlConfig
        self.applyAppConfig = RancherPipelineApplyAppConfig
        self.env = ""
        self.envFrom = RancherPipelineEnvFrom
        self.when = RancherPipelineWhen

class RancherPipelineBranch:
    def __init__(self, include=None, exclude=None, event=None):
        self.include = include
        self.exclude = exclude
        self.event = event

class RancherPipelineWhen:
    def __init__(self, branch=None):
        if branch is not None:
            self.branch = RancherPipelineBranch(branch.get("include"), branch.get("exclude"), branch.get("event"))


class RancherPipelineStage(RancherPipelineWhen):
    def __init__(self, name, branch):
        super().__init__(branch)
        self.name = name




class RancherPipelineEnvFrom:
    def __init__(self):
        self.sourceName = ""
        self.sourceKey = ""
        self.targetKey = ""

class RancherPipelineRunScriptConfig:
    def __init__(self):
        self.image = ""
        self.shellScript = ""


class RancherPipelineApplyAppConfig:
    def __init__(self):
        self.catalogTemplate = ""
        self.version = ""
        self.name = ""
        self.targetNamespace = ""
        self.answers = {}


class RancherPipelinePublishImageConfig:
    def __init__(self):
        self.dockerfilePath = ""
        self.buildContext = ""
        self.tag = ""
        self.pushRemote = ""
        self.registry = ""

class RancherPipelineApplyYamlConfig:
    def __init__(self):
        self.path = ""