class RancherPipelineYaml:
    def __init__(self):
        self.stages = RancherPipelineStage
        self.when = RancherPipelineWhen

class RancherPipelineStage:
    def __init__(self):
        self.name = ""
        self.when = RancherPipelineWhen
        self.steps = RancherPipelineStep

class RancherPipelineStep:
    def __init__(self):
        self.runScriptConfig = RancherPipelineRunScriptConfig
        self.publishImageConfig = RancherPipelinePublishImageConfig
        self.applyYamlConfig = RancherPipelineApplyYamlConfig
        self.applyAppConfig = RancherPipelineApplyAppConfig
        self.env = ""
        self.envFrom = RancherPipelineEnvFrom
        self.when = RancherPipelineWhen

class RancherPipelineWhen:
    def __init__(self):
        self.branch = RancherPipelineBranch

class RancherPipelineBranch:
    def __init__(self):
        self.include = []
        self.exclude = []
        self.event = ""


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