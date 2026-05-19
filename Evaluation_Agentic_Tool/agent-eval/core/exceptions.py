class AgentEvalError(Exception):
    pass


class AdapterError(AgentEvalError):
    pass


class AdapterNotFoundError(AdapterError):
    pass


class AttackGenerationError(AgentEvalError):
    pass


class PolicyLoadError(AgentEvalError):
    pass


class EvaluationError(AgentEvalError):
    pass


class JudgeError(AgentEvalError):
    pass
