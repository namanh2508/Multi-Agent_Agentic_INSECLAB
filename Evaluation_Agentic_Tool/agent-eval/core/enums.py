from enum import Enum


class ASICategory(str, Enum):
    ASI01_GOAL_HIJACK = "ASI01"
    ASI02_TOOL_MISUSE = "ASI02"
    ASI06_MEMORY_POISON = "ASI06"

    @property
    def display_name(self) -> str:
        names = {
            "ASI01": "Goal Hijack",
            "ASI02": "Tool Misuse",
            "ASI06": "Memory Poison",
        }
        return names.get(self.value, self.value)

    @property
    def description(self) -> str:
        descs = {
            "ASI01": "Attacker manipulates the agent's goal or objective through prompt injection, "
                     "context poisoning, or goal replacement.",
            "ASI02": "Attacker causes the agent to misuse tools by manipulating tool definitions, "
                     "outputs, or invocation patterns.",
            "ASI06": "Attacker poisons the agent's memory or context by injecting malicious content "
                     "into long-term memory stores.",
        }
        return descs.get(self.value, "")


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def score(self) -> int:
        scores = {
            "critical": 10,
            "high": 7,
            "medium": 4,
            "low": 2,
            "info": 0,
        }
        return scores.get(self.value, 0)


class AttackSurface(str, Enum):
    USER_PROMPT = "user_prompt"
    RETRIEVED_WEB_CONTENT = "retrieved_web_content"
    TOOL_OUTPUT = "tool_output"
    TOOL_DEFINITION = "tool_definition"
    MEMORY_READ = "memory_read"
    MEMORY_WRITE = "memory_write"
    SYSTEM_PROMPT = "system_prompt"
    CONTEXT_EXTENSION = "context_extension"


class AttackState(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    SUCCESS = "success"
    FAILED = "failed"
    SKIPPED = "skipped"


class Confidence(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
